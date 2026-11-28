<?php

declare(strict_types=1);

namespace App\Messenger;

use __PHP_Incomplete_Class;
use function array_any;
use function array_filter;
use function array_intersect_key;
use function array_map;
use function array_values;
use function base64_decode;
use function base64_encode;
use DateTimeImmutable;
use Beffroi\Core\Bridge\JwtLibrary\SealedMessageBody;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Core\Port\MessageBodyOpenerInterface;
use Beffroi\Core\Port\MessageBodySealerInterface;
use function in_array;
use function is_array;
use function is_object;
use function is_string;
use function is_subclass_of;
use function serialize;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;
use Symfony\Component\Clock\DatePoint;
use Symfony\Component\ErrorHandler\Exception\FlattenException;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\Exception\UnrecoverableMessageHandlingException;
use Symfony\Component\Messenger\Stamp\BusNameStamp;
use Symfony\Component\Messenger\Stamp\HandledStamp;
use Symfony\Component\Messenger\Stamp\NonSendableStampInterface;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Stamp\SentToFailureTransportStamp;
use Symfony\Component\Messenger\Stamp\StampInterface;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Symfony\Component\Scheduler\Generator\MessageContext;
use Symfony\Component\Scheduler\Trigger\SerializedTrigger;
use Throwable;
use function unserialize;

/**
 * A header decides nothing: the tenant is sealed with the body, and a stamp that reads back as another class
 * than its header names is refused.
 */
final readonly class SealedBodySerializer implements SerializerInterface
{
    public const string STAMP_HEADER_PREFIX = 'X-Message-Stamp-';

    public const string TYPE_HEADER = 'type';

    /**
     * The stamps written in clear, each read before a body opens or when it never does, none carrying anything of the
     * message: the tenant the body opens under, the count of its retries, the bus a worker hands it to, the transport
     * a failure came from, and the other stamps, sealed. Every other stamp, of Messenger or of this provider, named
     * here or not, is sealed with the others.
     *
     * @var list<class-string<StampInterface>>
     */
    public const array STAMPS_IN_CLEAR = [
        TenantStamp::class,
        RedeliveryStamp::class,
        BusNameStamp::class,
        SentToFailureTransportStamp::class,
        SealedStamps::class,
    ];

    /**
     * What a stamp of the component holds besides scalars: the exception of an ErrorDetailsStamp, the moment of a
     * RedeliveryStamp, and that moment as the clock of the component writes it when the stamp is given none, the
     * context of a ScheduledStamp, whose trigger crosses as its description only. Whoever writes to the transport
     * writes the headers, and whoever reads the public half of a message key can seal stamps: no seal proves an origin.
     *
     * @var list<class-string>
     */
    private const array HELD_BY_A_STAMP = [
        FlattenException::class,
        DateTimeImmutable::class,
        DatePoint::class,
        MessageContext::class,
        SerializedTrigger::class,
    ];

    public function __construct(
        private AmbientTenantInterface $tenants,
        private MessageBodySealerInterface $sealer,
        private MessageBodyOpenerInterface $opener,
    ) {
    }

    public function encode(Envelope $envelope): array
    {
        $message = $envelope->getMessage();
        // A body that failed to decode goes on as it arrived: it is already sealed, and its headers describe it.
        $failed = self::bodyThatFailedToDecode($message);
        $envelope = $envelope->withoutStampsOfType(NonSendableStampInterface::class);
        // Results are for synchronous callers; a retry needs only the names of the handlers that ran.
        $handled = $envelope->all(HandledStamp::class);
        if ($handled !== []) {
            $envelope = $envelope
                ->withoutAll(HandledStamp::class)
                ->with(...array_map(
                    static fn (HandledStamp $stamp): HandledStamp => new HandledStamp(null, $stamp->getHandlerName()),
                    $handled,
                ));
        }
        if ($failed !== null) {
            $headers = [
                self::TYPE_HEADER => $failed['headers'][self::TYPE_HEADER] ?? $message::class,
                ...$this->encodeStamps($envelope, $failed['headers']),
            ];

            return [
                'body' => $failed['body'],
                'headers' => $headers
                    + array_filter(
                        $failed['headers'],
                        static fn (string $name): bool => ! str_starts_with($name, self::STAMP_HEADER_PREFIX),
                        ARRAY_FILTER_USE_KEY,
                    ),
            ];
        }
        $tenant = $this->tenants->provide();
        $envelope = $envelope->withoutAll(TenantStamp::class)->with(new TenantStamp($tenant->slug));

        return [
            'body' => $this->sealer->seal($tenant, serialize($message)),
            'headers' => [
                self::TYPE_HEADER => $message::class,
                ...$this->encodeStamps($envelope, []),
            ],
        ];
    }

    /**
     * The compact JWEs of the sealed stamps a set of headers carries, read as the decoding reads them.
     *
     * @param array<array-key, mixed> $headers
     *
     * @return list<string>
     */
    public static function sealedStampsIn(array $headers): array
    {
        $header = self::STAMP_HEADER_PREFIX . SealedStamps::class;
        $sealed = [];
        foreach (self::decodeStamps(array_intersect_key(self::headers(['headers' => $headers]), [$header => true])) as $stamp) {
            if ($stamp instanceof SealedStamps) {
                $sealed[] = $stamp->jwe;
            }
        }

        return $sealed;
    }

    /**
     * A body that does not open is a failure of the message, sent to the failure transport. A KMS that does not
     * answer, or a process without a tenant, is a failure of the process and propagates: nobody would replay a
     * message sent to the failure transport for an outage.
     */
    public function decode(array $encodedEnvelope): Envelope
    {
        $stamps = $this->openStamps(self::decodeStamps(self::headers($encodedEnvelope), $stampFailure), $stampFailure, $sealFailure);
        $body = $encodedEnvelope['body'];
        if ($body === '') {
            return MessageDecodingFailedException::wrap($encodedEnvelope, 'An encoded envelope of this provider carries a sealed body.')->with(...$stamps);
        }
        if ($stampFailure !== null) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, $stampFailure->getMessage(), 0, $stampFailure)->with(...$stamps);
        }
        $scope = self::scope($stamps);
        if ($scope === null) {
            return MessageDecodingFailedException::wrap(
                $encodedEnvelope,
                'An encoded envelope of this provider names the tenant it was written for.',
            )->with(...$stamps);
        }
        $tenant = $this->tenants->provide();
        if ($scope !== $tenant->slug) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, sprintf(
                'The message was written for the tenant "%s" and this process serves "%s".',
                $scope,
                $tenant->slug,
            ))->with(...$stamps);
        }
        try {
            $opened = $this->opener->open($tenant, $body);
        } catch (InvalidJweException $exception) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, $exception->getMessage(), 0, $exception)->with(...$stamps);
        }
        try {
            $message = self::read($opened);
        } catch (Throwable $failure) {
            // unserialize() runs the code of the classes it builds, which a body an older version of a class wrote can stop.
            return MessageDecodingFailedException::wrap(
                $encodedEnvelope,
                sprintf('The body of the message does not read back: %s', $failure->getMessage()),
                0,
                $failure,
            )->with(...$stamps);
        }
        if ($message === null) {
            return MessageDecodingFailedException::wrap(
                $encodedEnvelope,
                'The body of the message does not read back as the message it carried.',
            )->with(...$stamps);
        }
        $type = self::headers($encodedEnvelope)[self::TYPE_HEADER] ?? null;
        if ($type !== $message::class) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, sprintf(
                'The body of the message opens as "%s" and its headers name "%s".',
                $message::class,
                is_string($type) ? $type : 'nothing',
            ))->with(...$stamps);
        }
        if ($sealFailure !== null) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, 'The stamps sealed with the message do not open.', 0, $sealFailure)->with(...$stamps);
        }

        return new Envelope($message, $stamps);
    }

    /**
     * @return array{body: string, headers: array<string, string>}|null
     */
    private static function bodyThatFailedToDecode(object $message): ?array
    {
        if (! $message instanceof MessageDecodingFailedException) {
            return null;
        }
        $encoded = $message->encodedEnvelope;
        $body = $encoded['body'] ?? null;
        if (! is_string($body) || $body === '') {
            return null;
        }
        $headers = [];
        foreach (is_array($encoded['headers'] ?? null) ? $encoded['headers'] : [] as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $headers[$name] = $value;
            }
        }

        return [
            'body' => $body,
            'headers' => $headers,
        ];
    }

    /**
     * A stamp header of a body that failed to decode, which no stamp of the envelope replaces, goes on sealed whatever
     * class it names: nothing read what it holds.
     *
     * @param array<string, string> $failedHeaders
     *
     * @return array<string, string>
     *
     * @throws KeyNotFoundException when the tenant has no active message key, rather than writing a stamp in the clear
     */
    private function encodeStamps(Envelope $envelope, array $failedHeaders): array
    {
        $clear = [];
        $sealed = [];
        foreach ($envelope->all() as $class => $stamps) {
            if ($class === SealedStamps::class) {
                continue;
            }
            $header = self::STAMP_HEADER_PREFIX . $class;
            $value = base64_encode(serialize(array_values($stamps)));
            if (in_array($class, self::STAMPS_IN_CLEAR, true)) {
                $clear[$header] = $value;
            } else {
                $sealed[$header] = $value;
            }
        }
        foreach ($failedHeaders as $name => $value) {
            if (str_starts_with($name, self::STAMP_HEADER_PREFIX) && $name !== self::STAMP_HEADER_PREFIX . SealedStamps::class && ! isset($clear[$name])) {
                $sealed[$name] ??= $value;
            }
        }
        $sealedStamps = $envelope->all(SealedStamps::class);
        if ($sealed !== []) {
            $sealedStamps[] = new SealedStamps($this->sealer->seal($this->tenants->provide(), serialize($sealed)));
        }
        if ($sealedStamps !== []) {
            $clear[self::STAMP_HEADER_PREFIX . SealedStamps::class] = base64_encode(serialize(array_values($sealedStamps)));
        }

        return $clear;
    }

    /**
     * The stamps sealed for the tenant of this process are opened, whatever tenant a header in clear names, and read as
     * the headers in clear are; the ones whose seal names another tenant go on as they came. Sealed stamps that do not
     * open are a failure of the message, reported once its body opened: without them, a handler that already ran would
     * run again.
     *
     * @param list<StampInterface> $stamps
     *
     * @return list<StampInterface>
     *
     * @throws KmsUnavailableException
     */
    private function openStamps(array $stamps, ?Throwable &$stampFailure, ?InvalidJweException &$sealFailure): array
    {
        $opened = [];
        $tenant = null;
        foreach ($stamps as $stamp) {
            if (! $stamp instanceof SealedStamps) {
                $opened[] = $stamp;

                continue;
            }
            $tenant ??= $this->tenants->provide();
            $sealedFor = SealedMessageBody::tenantOf($stamp->jwe);
            if ($sealedFor !== null && $sealedFor !== $tenant->slug) {
                $opened[] = $stamp;

                continue;
            }
            try {
                $headers = @unserialize($this->opener->open($tenant, $stamp->jwe), [
                    'allowed_classes' => false,
                ]);
            } catch (InvalidJweException $exception) {
                $sealFailure ??= $exception;
                $opened[] = $stamp;

                continue;
            }
            if (! is_array($headers)) {
                $stampFailure ??= new MessageDecodingFailedException('The stamps sealed with the message do not read back.');
                $opened[] = $stamp;

                continue;
            }
            $opened = [...$opened, ...self::decodeStamps(self::headers(['headers' => $headers]), $stampFailure)];
        }

        return $opened;
    }

    /**
     * A stamp that does not read back leaves the others kept, so that the retries of the message are still counted.
     * When the stamp that counts them is the one that does not read back, the failure is not retried: without its
     * count, the message would be retried forever.
     *
     * @param array<string, string> $headers
     *
     * @return list<StampInterface>
     */
    private static function decodeStamps(array $headers, ?Throwable &$failure = null): array
    {
        $stamps = [];
        foreach ($headers as $name => $value) {
            if (! str_starts_with($name, self::STAMP_HEADER_PREFIX)) {
                continue;
            }
            $class = substr($name, strlen(self::STAMP_HEADER_PREFIX));
            $decoded = base64_decode($value, true);
            $thrown = null;
            try {
                $read = $decoded === false || ! is_subclass_of($class, StampInterface::class)
                    ? false
                    : @unserialize($decoded, [
                        'allowed_classes' => [$class, ...self::HELD_BY_A_STAMP],
                    ]);
            } catch (Throwable $thrown) {
                $read = false;
            }
            if (! is_array($read)) {
                $failure ??= new MessageDecodingFailedException(sprintf('The header of the stamp "%s" does not read back.', $class), 0, $thrown);

                continue;
            }
            foreach ($read as $stamp) {
                if (! $stamp instanceof StampInterface || $stamp::class !== $class) {
                    $failure ??= new MessageDecodingFailedException(sprintf('The header of the stamp "%s" carries something else.', $class));

                    continue;
                }
                $stamps[] = $stamp;
            }
        }
        if (
            $failure !== null
            && isset($headers[self::STAMP_HEADER_PREFIX . RedeliveryStamp::class])
            && ! array_any($stamps, static fn (StampInterface $stamp): bool => $stamp instanceof RedeliveryStamp)
        ) {
            $failure = new UnrecoverableMessageHandlingException(
                sprintf('%s The retries of the message cannot be counted.', $failure->getMessage()),
                0,
                $failure,
            );
        }

        return $stamps;
    }

    /**
     * @param array{body?: string, headers?: mixed, extra?: array<string, mixed>} $encodedEnvelope
     *
     * @return array<string, string>
     */
    private static function headers(array $encodedEnvelope): array
    {
        $headers = [];
        foreach (is_array($encodedEnvelope['headers'] ?? null) ? $encodedEnvelope['headers'] : [] as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $headers[$name] = $value;
            }
        }

        return $headers;
    }

    /**
     * @param list<StampInterface> $stamps
     */
    private static function scope(array $stamps): ?string
    {
        $scope = null;
        foreach ($stamps as $stamp) {
            if ($stamp instanceof TenantStamp) {
                $scope = $stamp->slug;
            }
        }

        return $scope;
    }

    private static function read(string $opened): ?object
    {
        $message = @unserialize($opened, [
            'allowed_classes' => true,
        ]);

        return is_object($message) && ! $message instanceof __PHP_Incomplete_Class ? $message : null;
    }
}
