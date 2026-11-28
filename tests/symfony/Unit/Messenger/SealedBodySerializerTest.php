<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\BodyOfTheVersionBefore;
use Error;
use function str_starts_with;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Tests\Domain\Event\EventsLeaveTheProcessTest;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function base64_decode;
use function base64_encode;
use App\Message\AdvanceKeyLifecycle;
use App\Message\IssueLogoutToken;
use App\Message\RevokeTheTokensOfTheSession;
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
use RuntimeException;
use function serialize;
use function sprintf;
use stdClass;
use function str_replace;
use function strlen;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\Exception\UnrecoverableExceptionInterface;
use Symfony\Component\Messenger\Stamp\ErrorDetailsStamp;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Stamp\SentToFailureTransportStamp;
use Symfony\Component\Messenger\Stamp\StampInterface;
use Symfony\Component\Scheduler\Generator\MessageContext;
use Symfony\Component\Scheduler\Messenger\ScheduledStamp;
use Symfony\Component\Scheduler\Trigger\PeriodicalTrigger;
use Symfony\Component\Uid\Uuid;
use TypeError;
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
            new ThePerson(),
        )];
        yield 'a logout token still to issue' => [new IssueLogoutToken(
            Fixtures::tenant(),
            'oidc-demo',
            Uuid::v7(),
            Fixtures::user()->subject,
            Fixtures::context(),
            new ADirectory('Entra ID'),
        )];
        yield 'the revocation of the tokens of an ended session' => [new RevokeTheTokensOfTheSession(
            Fixtures::tenant(),
            Uuid::v7(),
            Fixtures::now(),
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

    /**
     * Decision 0066: a logout token queued when the provider was upgraded is told in the name of whoever ended the
     * session, as the version before named them.
     */
    #[Test]
    #[DataProvider('provideLogoutTokensOfTheVersionBefore')]
    public function aLogoutTokenTheVersionBeforeQueuedReadsBackNamingItsAuthor(object $message): void
    {
        // Given
        $encoded = $this->encodedWithBody($message, BodyOfTheVersionBefore::of($message));

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertEquals($message, $decoded->getMessage());
    }

    /**
     * @return iterable<string, array{object}>
     */
    public static function provideLogoutTokensOfTheVersionBefore(): iterable
    {
        $tenant = Fixtures::tenant();
        $session = Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8091');
        $subject = Fixtures::user()->subject;
        $administrator = new AnAdministrator(new Subject('administrator-subject'));
        yield 'one to issue, an administrator having ended the session' => [new IssueLogoutToken(
            $tenant,
            'oidc-demo',
            $session,
            $subject,
            Fixtures::context(),
            $administrator,
        )];
        yield 'one to issue, the person having ended it' => [new IssueLogoutToken(
            $tenant,
            'oidc-demo',
            $session,
            $subject,
            Fixtures::context(),
            new ThePerson(),
        )];
        yield 'one to issue, the console having ended it' => [new IssueLogoutToken(
            $tenant,
            'oidc-demo',
            $session,
            $subject,
            Fixtures::context(ipAddress: null),
            new TheHost(),
        )];
        yield 'one to send, an administrator having ended the session' => [
            new SendLogoutToken(
                $tenant,
                'oidc-demo',
                'https://demo.localhost/backchannel-logout',
                'eyJ.the.token',
                $session,
                $subject,
                Fixtures::context(),
                $administrator,
            ),
        ];
        yield 'one to send, the person having ended it' => [
            new SendLogoutToken(
                $tenant,
                'oidc-demo',
                'https://demo.localhost/backchannel-logout',
                'eyJ.the.token',
                $session,
                $subject,
                Fixtures::context(),
                new ThePerson(),
            ),
        ];
    }

    #[Test]
    public function aBodyItsClassCannotBuildGoesToTheFailuresInPlaceOfStoppingTheWorker(): void
    {
        // Given
        $message = new SomethingHappened('a page was rendered');
        $body = str_replace(':1:{s:4:"what";', ':2:{s:13:"administrator";N;s:4:"what";', serialize($message));
        $encoded = $this->encodedWithBody($message, $body);

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        $failure = self::failureOf($decoded);
        static::assertSame(
            [true, Error::class],
            [
                str_starts_with($failure->getMessage(), 'The body of the message does not read back: '),
                $failure->getPrevious() === null ? null : $failure->getPrevious()::class,
            ],
        );
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
    #[DataProvider('provideHeadersThatThrowWhenRead')]
    public function aHeaderThatThrowsWhenReadIsAStampThatDoesNotReadBack(string $header): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . RedeliveryStamp::class] = base64_encode($header);

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertStringContainsString('does not read back', self::failureOf($decoded)->getMessage());
        static::assertSame($this->tenant->slug, $decoded->last(TenantStamp::class)?->slug);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHeadersThatThrowWhenRead(): iterable
    {
        $redeliveredAt = new DateTimeImmutable('2026-10-09T12:00:00+00:00');
        $header = serialize([new RedeliveryStamp(1, $redeliveredAt)]);

        yield 'an object outside the list in a typed property' => [str_replace(serialize($redeliveredAt), serialize(new stdClass()), $header)];
        yield 'a string in a property typed int' => [self::aRetryCountThatIsAString()];
        yield 'a moment without its date' => [str_replace(serialize($redeliveredAt), 'O:17:"DateTimeImmutable":0:{}', $header)];
    }

    #[Test]
    public function aHeaderThatThrowsWhenReadKeepsWhatItThrew(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . ErrorDetailsStamp::class] = base64_encode(self::anErrorWhoseMessageIsNull());

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertInstanceOf(TypeError::class, self::failureOf($decoded)->getPrevious()?->getPrevious());
    }

    /**
     * @param array<class-string<StampInterface>, string> $headers
     */
    #[Test]
    #[DataProvider('provideHeadersOfTheRetriesThatDoNotReadBack')]
    public function aMessageWhoseRetriesCannotBeCountedIsNotRetried(array $headers): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        foreach ($headers as $class => $header) {
            $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . $class] = $header;
        }

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertInstanceOf(UnrecoverableExceptionInterface::class, self::failureOf($decoded)->getPrevious());
    }

    /**
     * @return iterable<string, array{array<class-string<StampInterface>, string>}>
     */
    public static function provideHeadersOfTheRetriesThatDoNotReadBack(): iterable
    {
        yield 'a header that throws when read' => [[RedeliveryStamp::class => base64_encode(self::aRetryCountThatIsAString())]];
        yield 'a header that is no base64' => [[RedeliveryStamp::class => 'no base64 at all!']];
        yield 'a header that carries no stamp' => [[RedeliveryStamp::class => base64_encode(serialize([1]))]];
        yield 'after the header of another stamp that does not read back' => [[
            ErrorDetailsStamp::class => base64_encode(self::anErrorWhoseMessageIsNull()),
            RedeliveryStamp::class => base64_encode(self::aRetryCountThatIsAString()),
        ]];
    }

    /**
     * @param list<StampInterface> $stamps
     */
    #[Test]
    #[DataProvider('provideRetriesThatStillCount')]
    public function aMessageWhoseRetriesStillCountIsLeftToTheRetryStrategy(array $stamps, int $retries): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered'), $stamps));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . ErrorDetailsStamp::class] = base64_encode(self::anErrorWhoseMessageIsNull());

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertNotInstanceOf(UnrecoverableExceptionInterface::class, self::failureOf($decoded)->getPrevious());
        static::assertSame($retries, RedeliveryStamp::getRetryCountFromEnvelope($decoded));
    }

    /**
     * @return iterable<string, array{list<StampInterface>, int}>
     */
    public static function provideRetriesThatStillCount(): iterable
    {
        yield 'a message retried once' => [[new RedeliveryStamp(1, new DateTimeImmutable('2026-10-09T12:00:00+00:00'))], 1];
        yield 'a first delivery, which no header counts yet' => [[], 0];
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

    /**
     * @return array{body: string, headers: array<string, string>}
     */
    private function encodedWithBody(object $message, string $body): array
    {
        $headers = [];
        foreach ($this->serializer->encode(new Envelope($message))['headers'] ?? [] as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }

        return [
            'body' => new JwtLibraryMessageBodySealer(new SealedKeyProvider($this->keys, Keys::opened()), Algorithms::messageSealing())->seal(
                $this->tenant,
                $body,
            ),
            'headers' => $headers,
        ];
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

    private static function aRetryCountThatIsAString(): string
    {
        return str_replace(
            'retryCount";i:1;',
            'retryCount";s:3:"one";',
            serialize([new RedeliveryStamp(1, new DateTimeImmutable('2026-10-09T12:00:00+00:00'))]),
        );
    }

    private static function anErrorWhoseMessageIsNull(): string
    {
        return str_replace(
            'exceptionMessage";s:24:"the vault did not answer";',
            'exceptionMessage";N;',
            serialize([new ErrorDetailsStamp(RuntimeException::class, 0, 'the vault did not answer')]),
        );
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
