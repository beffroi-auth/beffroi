<?php

declare(strict_types=1);

namespace App\Messenger;

use __PHP_Incomplete_Class;
use function array_map;
use function array_values;
use function base64_decode;
use function base64_encode;
use DateTimeImmutable;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Core\Port\MessageBodyOpenerInterface;
use Beffroi\Core\Port\MessageBodySealerInterface;
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
use Symfony\Component\Messenger\Stamp\HandledStamp;
use Symfony\Component\Messenger\Stamp\NonSendableStampInterface;
use Symfony\Component\Messenger\Stamp\StampInterface;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
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
     * What a stamp of the component holds besides scalars: the exception of an ErrorDetailsStamp, the moment of a
     * RedeliveryStamp, and that moment as the clock of the component writes it when the stamp is given none. Whoever
     * writes to the transport writes the headers, and no key seals them.
     *
     * @var list<class-string>
     */
    private const array HELD_BY_A_STAMP = [FlattenException::class, DateTimeImmutable::class, DatePoint::class];

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
                ...self::encodeStamps($envelope),
            ];

            return [
                'body' => $failed['body'],
                'headers' => $headers + $failed['headers'],
            ];
        }
        $tenant = $this->tenants->provide();
        $envelope = $envelope->withoutAll(TenantStamp::class)->with(new TenantStamp($tenant->slug));

        return [
            'body' => $this->sealer->seal($tenant, serialize($message)),
            'headers' => [
                self::TYPE_HEADER => $message::class,
                ...self::encodeStamps($envelope),
            ],
        ];
    }

    /**
     * A body that does not open is a failure of the message, sent to the failure transport. A KMS that does not
     * answer, or a process without a tenant, is a failure of the process and propagates: nobody would replay a
     * message sent to the failure transport for an outage.
     */
    public function decode(array $encodedEnvelope): Envelope
    {
        $stamps = self::decodeStamps($encodedEnvelope, $stampFailure);
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
        $message = self::read($opened);
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
     * @return array<string, string>
     */
    private static function encodeStamps(Envelope $envelope): array
    {
        $headers = [];
        foreach ($envelope->all() as $class => $stamps) {
            $headers[self::STAMP_HEADER_PREFIX . $class] = base64_encode(serialize(array_values($stamps)));
        }

        return $headers;
    }

    /**
     * A stamp that does not read back leaves the others kept, so that the retries of the message are still counted.
     *
     * @param array{body?: string, headers?: array<string, string>, extra?: array<string, mixed>} $encodedEnvelope
     *
     * @return list<StampInterface>
     */
    private static function decodeStamps(array $encodedEnvelope, ?Throwable &$failure = null): array
    {
        $stamps = [];
        foreach (self::headers($encodedEnvelope) as $name => $value) {
            if (! str_starts_with($name, self::STAMP_HEADER_PREFIX)) {
                continue;
            }
            $class = substr($name, strlen(self::STAMP_HEADER_PREFIX));
            $decoded = base64_decode($value, true);
            $read = $decoded === false || ! is_subclass_of($class, StampInterface::class)
                ? false
                : @unserialize($decoded, [
                    'allowed_classes' => [$class, ...self::HELD_BY_A_STAMP],
                ]);
            if (! is_array($read)) {
                $failure ??= new MessageDecodingFailedException(sprintf('The header of the stamp "%s" does not read back.', $class));

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

        return $stamps;
    }

    /**
     * @param array{body?: string, headers?: array<string, string>, extra?: array<string, mixed>} $encodedEnvelope
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
