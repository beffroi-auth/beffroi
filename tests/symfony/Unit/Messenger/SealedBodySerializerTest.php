<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use Beffroi\Core\Tests\Domain\Event\EventsLeaveTheProcessTest;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function base64_decode;
use function base64_encode;
use App\Message\AdvanceKeyLifecycle;
use App\Message\IssueLogoutToken;
use App\Message\SendLogoutToken;
use App\Message\SendAddressConfirmation;
use App\Message\TellUserOfCredentialChange;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use App\Messenger\SealedBodySerializer;
use App\Messenger\TenantStamp;
use App\Tests\Symfony\Fixture\AmbientTenant;
use App\Tests\Symfony\Fixture\AskWhatIsKnown;
use App\Tests\Symfony\Fixture\EnrichTheProvenance;
use App\Tests\Symfony\Fixture\SomethingHappened;
use App\Tests\Symfony\Fixture\WokenWhenRead;
use App\Tests\Symfony\Fixture\WriteBeforeAnswering;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodyOpener;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\MessageBodyOpenerInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match_all;
use function serialize;
use function sprintf;
use function strlen;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\Stamp\ErrorDetailsStamp;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Stamp\SentToFailureTransportStamp;
use Symfony\Component\Messenger\Stamp\StampInterface;
use Symfony\Component\Scheduler\Generator\MessageContext;
use Symfony\Component\Scheduler\Messenger\ScheduledStamp;
use Symfony\Component\Scheduler\Trigger\PeriodicalTrigger;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Decision 0020
 */
final class SealedBodySerializerTest extends TestCase
{
    private const int SEARCHED_FROM = 8;

    private const string USERNAME = 'alice@acme.example';

    private const string SUBJECT = 'alice-of-acme-0001';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private SealedBodySerializer $serializer;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($this->messageKey($this->tenant));
        $this->serializer = $this->serializerOf($this->tenant, new SealedKeyProvider($this->keys, Keys::opened()));
    }

    /**
     * @return iterable<string, array{object}>
     */
    public static function messages(): iterable
    {
        yield 'a command' => [new AdvanceKeyLifecycle()];
        yield 'a command of its own' => [new EnrichTheProvenance(Uuid::v7())];
        yield 'an event of the provider' => [new SomethingHappened('a page was rendered')];
        yield 'a notification' => [new SendLogoutToken(
            Fixtures::tenant(),
            'oidc-demo',
            'https://demo.localhost/backchannel-logout',
            'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature',
            Uuid::v7(),
            Fixtures::user()->subject,
            Fixtures::context(),
        )];
        yield 'a logout token still to issue' => [new IssueLogoutToken(
            Fixtures::tenant(),
            'oidc-demo',
            Uuid::v7(),
            Fixtures::user()->subject,
            Fixtures::context(),
        )];
        yield 'a change told to a person' => [new TellUserOfCredentialChange(
            new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey'),
            'mail',
        )];
        yield 'a confirmation sent to an address' => [new SendAddressConfirmation(
            Fixtures::tenant(),
            Uuid::v7(),
            'phone_number',
            '+33612345678',
            Uuid::v7(),
            '042917',
            'the-value-of-the-link-of-the-confirmation',
            Fixtures::now()->modify('+10 minutes'),
        )];
        yield 'a query' => [new AskWhatIsKnown('the sessions of alice')];
        yield 'a write the protocol waits for' => [new WriteBeforeAnswering('the consent')];
        foreach (EventsLeaveTheProcessTest::events() as $name => $case) {
            yield 'an event of the core: ' . $name => $case;
        }
        foreach (\Beffroi\Oidc\Tests\Domain\Event\EventsLeaveTheProcessTest::events() as $name => $case) {
            yield 'an event of the module: ' . $name => $case;
        }
    }

    #[Test]
    #[DataProvider('messages')]
    public function aMessageIsSealedOnItsWayOutAndIsTheSameMessageOnItsWayBack(object $message): void
    {
        // When
        $decoded = $this->serializer->decode($this->serializer->encode(new Envelope($message)));

        // Then
        static::assertSame(serialize($message), serialize($decoded->getMessage()));
    }

    #[Test]
    #[DataProvider('messages')]
    public function theEncodedBodyCarriesNoneOfTheStringsTheMessageHeld(object $message): void
    {
        // Given
        $searched = self::stringsOf($message);

        // When
        $body = $this->serializer->encode(new Envelope($message))['body'];

        // Then
        static::assertCount(5, explode('.', $body));
        foreach ($searched as $string) {
            static::assertStringNotContainsString($string, $body, sprintf('the body of the message gives "%s" away.', $string));
        }
    }

    #[Test]
    #[DataProvider('provideWhatAMessageOfAPersonCarries')]
    public function theEncodedBodyOfAMessageOfAPersonGivesNoneOfTheirValuesAway(string $value): void
    {
        // Given
        $message = new UserAuthenticated(self::sessionOfAPerson());

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertStringContainsString($value, serialize($message), 'a value the message does not carry is a value this test does not search for.');
        static::assertStringNotContainsString($value, $encoded['body']);
        foreach ($encoded['headers'] ?? [] as $header) {
            static::assertStringNotContainsString($value, $header);
        }
    }

    /**
     * Decision 0011
     *
     * @return iterable<string, array{string}>
     */
    public static function provideWhatAMessageOfAPersonCarries(): iterable
    {
        yield 'the username' => [self::USERNAME];
        yield 'the subject' => [self::SUBJECT];
        yield 'the address of the request' => ['203.0.113.10'];
        yield 'the user agent of the request' => ['Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0'];
    }

    private static function sessionOfAPerson(): AuthenticationSession
    {
        return Fixtures::session(Fixtures::user(username: self::USERNAME, subject: self::SUBJECT));
    }

    #[Test]
    #[DataProvider('messages')]
    public function noHeaderCarriesAnythingOfTheMessageButItsClass(object $message): void
    {
        // Given
        $searched = self::stringsOf($message);

        // When
        $headers = $this->serializer->encode(new Envelope($message))['headers'] ?? [];

        // Then
        static::assertSame(
            [
                SealedBodySerializer::TYPE_HEADER,
                SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class,
            ],
            array_keys($headers),
        );
        static::assertSame($message::class, $headers[SealedBodySerializer::TYPE_HEADER]);
        static::assertSame([$this->tenant->slug], array_map(
            static fn (TenantStamp $stamp): string => $stamp->slug,
            self::stampsOf(TenantStamp::class, $headers[SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class]),
        ));
        foreach ($searched as $string) {
            if ($string === $message::class) {
                continue;
            }
            foreach ($headers as $name => $value) {
                static::assertStringNotContainsString($string, $value, sprintf('the header "%s" gives "%s" away.', $name, $string));
                static::assertStringNotContainsString($string, (string) base64_decode($value, true));
            }
        }
    }

    #[Test]
    public function aStampThatSaysTheWrongScopeMakesTheOpeningFail(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->keys->save($this->messageKey($other));
        $elsewhere = $this->serializerOf($other, new SealedKeyProvider($this->keys, Keys::opened()))->encode(new Envelope(
            new SomethingHappened('something of another tenant'),
        ));
        $elsewhere['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class] = base64_encode(serialize([
            new TenantStamp($this->tenant->slug),
        ]));

        // When
        $decoded = $this->serializer->decode($elsewhere);

        // Then
        static::assertStringContainsString('sealed for another scope', self::failureOf($decoded)->getMessage());
    }

    #[Test]
    public function aMessageOfAnotherTenantIsNotOpenedHere(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class] = base64_encode(serialize([
            new TenantStamp('other'),
        ]));

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertSame(
            'The message was written for the tenant "other" and this process serves "acme".',
            self::failureOf($decoded)->getMessage(),
        );
    }

    #[Test]
    public function anEnvelopeThatNamesNoScopeIsRefused(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        unset($encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class]);

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertSame(
            'An encoded envelope of this provider names the tenant it was written for.',
            self::failureOf($decoded)->getMessage(),
        );
    }

    #[Test]
    public function theBodyDecidesTheClassOfTheMessageAndNotTheHeader(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::TYPE_HEADER] = AdvanceKeyLifecycle::class;

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertStringContainsString('opens as', self::failureOf($decoded)->getMessage());
    }

    #[Test]
    public function aFailedMessageIsNamedDatedAndExplainedWithoutItsBodyBeingOpened(): void
    {
        // Given
        $message = new SomethingHappened('a page was rendered');
        $encoded = $this->serializer->encode(new Envelope($message));
        $refused = $this->serializerOf($this->tenant, new SealedKeyProvider(new InMemoryTenantKeyRepository(), Keys::opened()));
        $failure = $refused->decode($encoded);
        $redeliveredAt = new DateTimeImmutable('2026-10-09T12:00:00+00:00');

        // When
        $written = $refused->encode($failure->with(
            new SentToFailureTransportStamp('async_priority_low'),
            new RedeliveryStamp(1, $redeliveredAt),
            ErrorDetailsStamp::create(new KmsUnavailableException('the vault did not answer')),
        ));

        // Then
        static::assertSame($encoded['body'], $written['body']);
        static::assertSame(SomethingHappened::class, $written['headers'][SealedBodySerializer::TYPE_HEADER] ?? null);
        static::assertSame(['2026-10-09T12:00:00+00:00'], array_map(
            static fn (RedeliveryStamp $stamp): string => $stamp->getRedeliveredAt()->format(DateTimeImmutable::RFC3339),
            self::stampsOf(RedeliveryStamp::class, $written['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . RedeliveryStamp::class] ?? ''),
        ));
        static::assertSame(['the vault did not answer'], array_map(
            static fn (ErrorDetailsStamp $stamp): string => $stamp->getExceptionMessage(),
            self::stampsOf(ErrorDetailsStamp::class, $written['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . ErrorDetailsStamp::class] ?? ''),
        ));
    }

    #[Test]
    public function aFailedMessageReadBackKeepsWhenItWasRetriedAndWhatFailed(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $refused = $this->serializerOf($this->tenant, new SealedKeyProvider(new InMemoryTenantKeyRepository(), Keys::opened()));
        $written = $refused->encode($refused->decode($encoded)->with(
            new RedeliveryStamp(1, new DateTimeImmutable('2026-10-09T12:00:00+00:00')),
            ErrorDetailsStamp::create(new KmsUnavailableException('the vault did not answer')),
        ));

        // When
        $read = $refused->decode($written);

        // Then
        static::assertSame('2026-10-09T12:00:00+00:00', $read->last(RedeliveryStamp::class)?->getRedeliveredAt()->format(DateTimeImmutable::RFC3339));
        static::assertSame('the vault did not answer', $read->last(ErrorDetailsStamp::class)?->getFlattenException()?->getMessage());
    }

    #[Test]
    public function aMessageRetriedReadBackKeepsTheMomentTheClockOfTheComponentGaveItsRetry(): void
    {
        // Given
        $retried = new RedeliveryStamp(1);
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered'), [$retried]));

        // When
        $read = $this->serializer->decode($encoded);

        // Then
        static::assertSame(
            $retried->getRedeliveredAt()->format(DateTimeImmutable::RFC3339_EXTENDED),
            $read->last(RedeliveryStamp::class)?->getRedeliveredAt()->format(DateTimeImmutable::RFC3339_EXTENDED),
        );
    }

    #[Test]
    public function aScheduledMessageReadBackKeepsTheScheduleThatSentIt(): void
    {
        // Given
        $triggeredAt = new DateTimeImmutable('2026-10-09T12:00:00+00:00');
        $trigger = new PeriodicalTrigger(60, $triggeredAt);
        $encoded = $this->serializer->encode(new Envelope(new AdvanceKeyLifecycle(), [
            new ScheduledStamp(new MessageContext('beffroi', 'advance-key-lifecycle', $trigger, $triggeredAt)),
        ]));

        // When
        $read = $this->serializer->decode($encoded);

        // Then
        static::assertInstanceOf(AdvanceKeyLifecycle::class, $read->getMessage());
        $context = $read->last(ScheduledStamp::class)?->messageContext;
        static::assertSame('advance-key-lifecycle', $context?->id);
        static::assertSame('2026-10-09T12:00:00+00:00', $context->triggeredAt->format(DateTimeImmutable::RFC3339));
        static::assertSame((string) $trigger, (string) $context->trigger);
    }

    #[Test]
    public function aHeaderThatNamesAClassThatIsNoStampBuildsNothing(): void
    {
        // Given
        WokenWhenRead::$woken = 0;
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . WokenWhenRead::class] = base64_encode(serialize([new WokenWhenRead()]));

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertSame(0, WokenWhenRead::$woken);
        static::assertStringContainsString('does not read back', self::failureOf($decoded)->getMessage());
    }

    #[Test]
    public function aHeaderOfAStampThatHoldsAnotherObjectBuildsNothing(): void
    {
        // Given
        WokenWhenRead::$woken = 0;
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . RedeliveryStamp::class] = base64_encode(serialize([new WokenWhenRead()]));

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertSame(0, WokenWhenRead::$woken);
        static::assertStringContainsString('carries something else', self::failureOf($decoded)->getMessage());
    }

    #[Test]
    public function aKmsThatDoesNotAnswerIsNotAMessageThrownAway(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $opener = self::createStub(MessageBodyOpenerInterface::class);
        $opener->method('open')->willThrowException(new KmsUnavailableException('the vault did not answer'));
        $worker = new SealedBodySerializer(
            new AmbientTenant($this->tenant),
            new JwtLibraryMessageBodySealer(new SealedKeyProvider($this->keys, Keys::opened()), Algorithms::messageSealing()),
            $opener,
        );

        // Then
        $this->expectException(KmsUnavailableException::class);

        // When
        $worker->decode($encoded);
    }

    #[Test]
    public function sealingABodyAsksTheKmsNothing(): void
    {
        // Given
        $kms = self::createMock(KeySealerInterface::class);
        $kms->expects(static::never())->method('unseal');
        $serializer = $this->serializerOf($this->tenant, new SealedKeyProvider($this->keys, new OpenedKeys($kms)));

        // When
        $encoded = $serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));

        // Then
        static::assertCount(5, explode('.', $encoded['body']));
    }

    private function serializerOf(Tenant $tenant, SealedKeyProvider $keys): SealedBodySerializer
    {
        return new SealedBodySerializer(
            new AmbientTenant($tenant),
            new JwtLibraryMessageBodySealer($keys, Algorithms::messageSealing()),
            new JwtLibraryMessageBodyOpener($keys, Algorithms::messageSealing()),
        );
    }

    private function messageKey(Tenant $tenant): TenantKey
    {
        $pair = Keys::messagePair();
        $key = new TenantKey(
            $pair->kid,
            $tenant,
            Algorithms::messageSeal(),
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());

        return $key;
    }

    private static function failureOf(Envelope $envelope): MessageDecodingFailedException
    {
        $failure = $envelope->getMessage();
        static::assertInstanceOf(MessageDecodingFailedException::class, $failure);

        return $failure;
    }

    /**
     * @return list<string>
     */
    private static function stringsOf(object $message): array
    {
        preg_match_all('/s:(\d+):"((?:[^"\\\\]|\\\\.)*)";/', serialize($message), $matches, PREG_SET_ORDER);
        $searched = [];
        foreach ($matches as $match) {
            if (strlen($match[2]) >= self::SEARCHED_FROM) {
                $searched[] = $match[2];
            }
        }

        return array_values(array_unique($searched));
    }

    /**
     * @template T of StampInterface
     *
     * @param class-string<T> $class
     *
     * @return non-empty-list<T>
     */
    private static function stampsOf(string $class, string $header): array
    {
        $decoded = base64_decode($header, true);
        static::assertIsString($decoded);
        $stamps = unserialize($decoded, [
            'allowed_classes' => true,
        ]);
        static::assertIsArray($stamps);
        static::assertNotSame([], $stamps);
        $read = [];
        foreach ($stamps as $stamp) {
            static::assertInstanceOf($class, $stamp);
            $read[] = $stamp;
        }

        return $read;
    }
}
