<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use function array_map;
use DateInterval;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Authentication\AuthenticationRefusal;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Authentication\PasswordAuthenticator;
use Beffroi\Core\Application\Authentication\PasswordVerification;
use Beffroi\Core\Application\Authentication\SecondFactorRequirement;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasswordRehashed;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\PendingLogin;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Tests\Fixture\FakeAttemptLimiter;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\Totps;
use const PASSWORD_BCRYPT;
use function password_hash;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Beffroi\Core\Tests\Fixture\FakeMonotonicClock;
use Beffroi\Core\Tests\Fixture\TimedPasswordHasher;

final class PasswordAuthenticatorTest extends TestCase
{
    /**
     * @var array<string, int> nanoseconds a verification takes, by name of algorithm
     */
    private const array COSTS = [Argon2id::NAME => 117_800_000, Bcrypt::NAME => 87_700_000];

    private Tenant $tenant;

    private User $alice;

    private InMemoryUserRepository $users;

    private InMemoryCredentialRepository $credentials;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private FakeAttemptLimiter $attempts;

    private MockClock $clock;

    private PasswordAuthenticator $authenticator;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
        $this->credentials = new InMemoryCredentialRepository();
        $hasher = new FakePasswordHasher();
        $this->credentials->save(new PasswordCredential(Uuid::v7(), $this->alice, $hasher->hash('correct horse'), Fixtures::now()));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->attempts = new FakeAttemptLimiter(5);
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->authenticator = $this->authenticatorOn($hasher);
    }

    private function authenticatorOn(
        PasswordHasherInterface $hasher,
        ?FakeAttemptLimiter $attempts = null,
        FakeMonotonicClock $time = new FakeMonotonicClock(),
    ): PasswordAuthenticator {
        return new PasswordAuthenticator(
            new PasswordVerification(
                $this->users,
                $this->credentials,
                new ActivePassword(new ActiveCredentials($this->credentials)),
                $hasher,
                new DecoyHash($hasher, new SymfonyUuidGenerator(), $time),
                $attempts ?? $this->attempts,
                new AuthenticationRefusal($this->clock, $this->events),
                $this->clock,
                $this->events,
                new FederatedDomains($this->upstreamProviders),
                $this->credentials,
            ),
            new SessionOpener(
                $this->sessions,
                new SymfonyUuidGenerator(),
                $this->clock,
                $this->events,
                new AuthenticationRefusal($this->clock, $this->events),
                new DateInterval('PT8H'),
            ),
            new SecondFactorRequirement(new ActiveCredentials($this->credentials)),
            $this->clock,
        );
    }

    #[Test]
    public function aRightPasswordOpensASessionOfTheUser(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->authenticator->authenticate($this->tenant, ' alice ', 'correct horse', $context);

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
        static::assertSame($this->alice, $session->user);
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertSame('1', $session->authenticationContextClass()->value);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now(), $session->establishedAt);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
        static::assertSame(
            [
                'pwd' => $this->clock->now()->getTimestamp(),
            ],
            $session->proofs->toTimestamps(),
        );
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
    }

    #[Test]
    public function aRightPasswordSavesTheSession(): void
    {
        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function aRightPasswordDatesTheUseOfTheCredential(): void
    {
        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now(), $this->credentials->findByUser($this->alice, PasswordCredential::class)[0]->lastUsedAt);
    }

    #[Test]
    public function aRightPasswordAnnouncesTheAuthenticationOnce(): void
    {
        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(1, $this->events->of(UserAuthenticated::class));
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    #[Test]
    public function aRightPasswordAnnouncesThePasswordItAccepted(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', $context);

        // Then
        static::assertCount(2, $this->events->events);
        $used = $this->events->of(PasswordUsed::class)[0];
        static::assertSame($this->credentials->findByUser($this->alice, PasswordCredential::class)[0], $used->credential);
        static::assertSame($context, $used->context);
        static::assertEquals($this->clock->now(), $used->occurredAt);
    }

    #[Test]
    public function aWrongPasswordFails(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            static::assertSame('Authentication failed.', $exception->getMessage());
        }
    }

    #[Test]
    public function aWrongPasswordIsRecordedWithTheUser(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $this->events->events);
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failure->reason);
        static::assertSame($this->alice, $failure->user);
        static::assertSame('alice', $failure->identifier);
        static::assertSame($this->tenant, $failure->tenant);
        static::assertEquals($this->clock->now(), $failure->occurredAt);
    }

    #[Test]
    public function aWrongPasswordOpensNoSession(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function anUnknownUserFails(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'mallory', 'whatever', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
        }
    }

    #[Test]
    public function anUnknownUserIsRecordedWithWhatWasTyped(): void
    {
        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'mallory', 'whatever', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::UnknownUser, $failure->reason);
        static::assertNull($failure->user);
        static::assertSame('mallory', $failure->identifier);
    }

    #[Test]
    public function aUserWithoutPasswordFails(): void
    {
        // Given
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'bob', 'anything', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::NoSuchCredential, $exception->reason);
        }
    }

    #[Test]
    public function aUserWithoutPasswordIsRecordedAsTheUser(): void
    {
        // Given
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->users->save($bob);

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'bob', 'anything', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::NoSuchCredential, $failure->reason);
        static::assertSame($bob, $failure->user);
    }

    #[Test]
    public function aDisabledUserWithAWrongPasswordFailsLikeAnyWrongPassword(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'wrong', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
        }
    }

    #[Test]
    public function aDisabledUserWithTheRightPasswordFailsAsDisabled(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());

        // When
        try {
            $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::DisabledUser, $exception->reason);
        }
    }

    /**
     * Decision 0029, spec/saml.md S-63
     */
    #[Test]
    #[DataProvider('provideFederatedPersons')]
    public function aPersonOfAFederatedDomainWithTheRightPasswordIsRefused(?string $email, string $username): void
    {
        // Given
        $this->upstreamProviders->declare($this->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        if ($email !== null) {
            $this->alice->changeEmail(new EmailAddress($email), true, Fixtures::now());
        }
        $this->alice->rename($username, Fixtures::now());

        // When
        $exception = $this->failToAuthenticate($username, 'correct horse');

        // Then
        static::assertSame(AuthenticationFailureReason::FederatedDomain, $exception->reason);
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function provideFederatedPersons(): iterable
    {
        yield 'by their mailbox' => ['alice@ACME.example', 'alice'];
        yield 'by their username' => [null, 'alice@acme.example'];
        yield 'by a username whose domain the rule does not read' => [null, 'alice@acme.example.'];
    }

    /**
     * Decision 0029
     */
    #[Test]
    public function aPersonOfAFederatedDomainWithAWrongPasswordFailsLikeAnyWrongPassword(): void
    {
        // Given
        $this->upstreamProviders->declare($this->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        $exception = $this->failToAuthenticate('alice', 'wrong');

        // Then
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
    }

    /**
     * Decision 0029
     */
    #[Test]
    public function aPersonOfAnotherDomainSignsInWithTheirPassword(): void
    {
        // Given
        $this->upstreamProviders->declare($this->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $this->alice->changeEmail(new EmailAddress('alice@eu.acme.example'), true, Fixtures::now());

        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
    }

    #[Test]
    public function aTenantThatAdmitsNoPasswordRefusesBeforeNamingAnybody(): void
    {
        // Given
        $hardened = Fixtures::hardenedTenant();

        // When
        try {
            $this->authenticator->authenticate($hardened, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::BelowTheFloor, $exception->reason);
            static::assertSame([], $this->attempts->attempts);
            static::assertSame([], $this->events->of(PasswordUsed::class));
        }
    }

    #[Test]
    public function aUserOfAnotherTenantIsUnknownHere(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When
        try {
            $this->authenticator->authenticate($other, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
        }
    }

    #[Test]
    public function aFailureIsRecordedInTheTenantItWasAttemptedIn(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When
        try {
            $this->authenticator->authenticate($other, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame($other, $this->events->of(AuthenticationFailed::class)[0]->tenant);
    }

    #[Test]
    public function aLegacyHashIsReplacedAfterASuccessfulLogin(): void
    {
        // Given
        $carol = Fixtures::user($this->tenant, 'carol', 'carol-subject');
        $this->users->save($carol);
        $this->credentials->save(
            new PasswordCredential(
                Uuid::v7(),
                $carol,
                new PasswordHash(new Bcrypt(), password_hash('carol pass', PASSWORD_BCRYPT)),
                Fixtures::now(),
            ),
        );

        // When
        $this->authenticatorOn(new NativePasswordHasher())->authenticate($this->tenant, 'carol', 'carol pass', Fixtures::context());

        // Then
        $credential = $this->credentials->findByUser($carol, PasswordCredential::class)[0];
        static::assertSame(Argon2id::NAME, $credential?->hash->algorithm->name());
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
        static::assertTrue(new NativePasswordHasher()->verify($credential->hash, 'carol pass'));
    }

    #[Test]
    public function aRehashIsAnnounced(): void
    {
        // Given
        $carol = Fixtures::user($this->tenant, 'carol', 'carol-subject');
        $this->users->save($carol);
        $this->credentials->save(
            new PasswordCredential(
                Uuid::v7(),
                $carol,
                new PasswordHash(new Bcrypt(), password_hash('carol pass', PASSWORD_BCRYPT)),
                Fixtures::now(),
            ),
        );

        // When
        $this->authenticatorOn(new NativePasswordHasher())->authenticate($this->tenant, 'carol', 'carol pass', Fixtures::context());

        // Then
        static::assertCount(1, $this->events->of(PasswordRehashed::class));
        static::assertSame($this->credentials->findByUser($carol, PasswordCredential::class)[0], $this->events->of(PasswordRehashed::class)[0]->credential);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function theSixthAttemptIsRefusedWhateverThePassword(): void
    {
        // Given
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $this->failToAuthenticate('alice', 'wrong')->reason);
        }

        // When
        $exception = $this->failToAuthenticate('alice', 'correct horse');

        // Then
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, $exception->reason);
    }

    #[Test]
    public function aRefusedAttemptIsRecordedWithTheUser(): void
    {
        // Given
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->failToAuthenticate('alice', 'wrong');
        }

        // When
        $this->failToAuthenticate('alice', 'correct horse');

        // Then
        $failure = $this->events->of(AuthenticationFailed::class)[5];
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, $failure->reason);
        static::assertSame($this->alice, $failure->user);
        static::assertSame('alice', $failure->identifier);
    }

    #[Test]
    public function aRefusedAttemptOpensNoSession(): void
    {
        // Given
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->failToAuthenticate('alice', 'wrong');
        }

        // When
        $this->failToAuthenticate('alice', 'correct horse');

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    /**
     * Decision 0058
     */
    #[Test]
    public function aWrongPasswordAgainstAHashTheHasherWouldReplaceTakesTheTimeOfTheDecoy(): void
    {
        // Given
        $time = new FakeMonotonicClock();
        $authenticator = $this->authenticatorOn(new TimedPasswordHasher($time, self::COSTS), null, $time);
        $this->carolHolds(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'));
        $this->failToAuthenticateWith($authenticator, 'mallory');
        $start = $time->now();

        // When
        $this->failToAuthenticateWith($authenticator, 'carol');

        // Then
        static::assertSame(self::COSTS[Argon2id::NAME], $time->now() - $start);
    }

    /**
     * Decision 0058
     */
    #[Test]
    public function aWrongPasswordAgainstAHashOfTheDayWaitsNothing(): void
    {
        // Given
        $time = new FakeMonotonicClock();
        $authenticator = $this->authenticatorOn(new TimedPasswordHasher($time, self::COSTS), null, $time);
        $this->carolHolds(TimedPasswordHasher::hashOf(new Argon2id(), 'carol pass'));
        $this->failToAuthenticateWith($authenticator, 'mallory');

        // When
        $this->failToAuthenticateWith($authenticator, 'carol');

        // Then
        static::assertSame([], $time->waited);
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideRefusalsBeforeTheHash')]
    public function aRefusalBeforeTheHashCostsAHashLikeAWrongPassword(string $username, int $allowedAttempts): void
    {
        // Given
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $hasher = new FakePasswordHasher();
        $authenticator = $this->authenticatorOn($hasher, new FakeAttemptLimiter($allowedAttempts));

        // When
        try {
            $authenticator->authenticate($this->tenant, $username, 'correct horse', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $hasher->verifiedAgainst);
        static::assertStringStartsWith('fake:', $hasher->verifiedAgainst[0]);
        static::assertNotSame($hasher->hash('correct horse')->encoded, $hasher->verifiedAgainst[0]);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideRefusalsBeforeTheHash(): iterable
    {
        yield 'an unknown user' => ['mallory', 5];
        yield 'a user without a password' => ['bob', 5];
        yield 'an attempt too many' => ['alice', 0];
    }

    #[Test]
    public function anAttemptIsCountedBeforeThePasswordIsVerified(): void
    {
        // When
        $this->failToAuthenticate('alice', 'wrong');

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $this->attempts->attempts);
    }

    #[Test]
    public function anUnknownUserIsNotCounted(): void
    {
        // When
        $this->failToAuthenticate('mallory', 'whatever');

        // Then
        static::assertSame([], $this->attempts->attempts);
    }

    #[Test]
    public function aUserWithoutPasswordIsCounted(): void
    {
        // Given
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->users->save($bob);

        // When
        $this->failToAuthenticate('bob', 'anything');

        // Then
        static::assertSame([$bob->id->toRfc4122()], $this->attempts->attempts);
    }

    #[Test]
    public function aSuccessfulLoginEmptiesTheCountOfTheUser(): void
    {
        // Given
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->failToAuthenticate('alice', 'wrong');
        }
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->failToAuthenticate('alice', 'wrong');
        }

        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
        static::assertSame($this->alice, $session->user);
        static::assertSame([], $this->attempts->attempts);
    }

    #[Test]
    public function aDisabledUserWithTheRightPasswordKeepsTheCount(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());

        // When
        $this->failToAuthenticate('alice', 'correct horse');

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $this->attempts->attempts);
    }

    /**
     * Architecture §3.2
     */
    #[Test]
    public function aRightPasswordOfAUserWhoHoldsASecondFactorHoldsTheLoginInsteadOfOpeningASession(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, new FakePasswordHasher()));

        // When
        $login = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(PendingLogin::class, $login);
        static::assertSame($this->alice->id, $login->userId);
        static::assertSame(['pwd'], array_map(static fn ($method) => $method->value, $login->methods));
        static::assertEquals($this->clock->now(), $login->provenAt);
        static::assertEquals($this->clock->now()->modify('+5 minutes'), $login->expiresAt);
    }

    #[Test]
    public function aHeldLoginOpensNoSession(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, new FakePasswordHasher()));

        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function aHeldLoginAnnouncesThePasswordAndNoOutcome(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, new FakePasswordHasher()));

        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(1, $this->events->events);
        static::assertCount(1, $this->events->of(PasswordUsed::class));
    }

    #[Test]
    public function aHeldLoginEmptiesTheCountOfTheUser(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, new FakePasswordHasher()));
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->failToAuthenticate('alice', 'wrong');
        }

        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([], $this->attempts->attempts);
    }

    #[Test]
    public function aHeldLoginDatesTheUseOfThePassword(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, new FakePasswordHasher()));

        // When
        $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now(), $this->credentials->findByUser($this->alice, PasswordCredential::class)[0]->lastUsedAt);
    }

    #[Test]
    public function aRevokedSecondFactorHoldsNothing(): void
    {
        // Given
        $totp = Totps::credential($this->alice, new FakePasswordHasher());
        $totp->revoke(Fixtures::now()->modify('+1 hour'));
        $this->credentials->save($totp);

        // When
        $session = $this->authenticator->authenticate($this->tenant, 'alice', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
        static::assertSame(['pwd'], $session->methodReferences());
    }

    /**
     * RFC 8265 §4.2.3, §4.3, RFC 7644 §5
     */
    #[Test]
    #[DataProvider('provideFormsOfOnePassword')]
    public function aPasswordTypedInAnotherFormThanItWasSetInSignsIn(string $set, string $typed): void
    {
        // Given
        $this->carolHolds(new FakePasswordHasher()->hash($set));

        // When
        $session = $this->authenticator->authenticate($this->tenant, 'carol', $typed, Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideFormsOfOnePassword(): iterable
    {
        yield 'an ogham space mark, example 16 of RFC 8265 §4.3' => ['foo bar', "foo\u{1680}bar"];
        yield 'a no-break space' => ['correct horse battery staple', "correct\u{00A0}horse battery staple"];
        yield 'an e and a combining acute accent' => ["jos\u{00E9} is home", "jose\u{0301} is home"];
        yield 'a Greek question mark' => ['ab;cd', "ab\u{037E}cd"];
    }

    /**
     * RFC 8265 §4.2.2 rules 1 and 3, §4.3
     */
    #[Test]
    #[DataProvider('provideOtherPasswords')]
    public function aPasswordThatDiffersByItsEnforcedFormFails(string $set, string $typed): void
    {
        // Given
        $this->carolHolds(new FakePasswordHasher()->hash($set));

        // When
        $exception = $this->failToAuthenticate('carol', $typed);

        // Then
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideOtherPasswords(): iterable
    {
        yield 'examples 12 and 13 of RFC 8265 §4.3, which differ by case' => ['correct horse battery staple', 'Correct Horse Battery Staple'];
        yield 'a fullwidth letter' => ['abc', "\u{FF41}bc"];
        yield 'a ligature' => ['office', "o\u{FB03}ce"];
    }

    /**
     * RFC 8265 §6.2, decision 0065
     */
    #[Test]
    public function aHashOfTheBytesAsTheyWereTypedBeforeTheProfileSignsInWithThoseBytes(): void
    {
        // Given
        $this->carolHeldBefore(new FakePasswordHasher()->hash("correct\u{00A0}horse"));

        // When
        $session = $this->authenticator->authenticate($this->tenant, 'carol', "correct\u{00A0}horse", Fixtures::context($this->clock->now()));

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $session);
    }

    /**
     * RFC 8265 §8.2, decision 0065
     */
    #[Test]
    public function aHashOfBeforeTheProfileIsReplacedByAHashOfTheEnforcedFormAtTheSignIn(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $carol = $this->carolHeldBefore($hasher->hash("correct\u{00A0}horse"));

        // When
        $this->authenticator->authenticate($this->tenant, 'carol', "correct\u{00A0}horse", Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($hasher->hash('correct horse')->encoded, $this->credentials->findByUser($carol, PasswordCredential::class)[0]?->hash->encoded);
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function anAsciiHashOfBeforeTheProfileIsReplacedTooSoThatNoneIsLeftInTheTenant(): void
    {
        // Given
        $this->carolHeldBefore(new FakePasswordHasher()->hash('correct horse'));

        // When
        $this->authenticator->authenticate($this->tenant, 'carol', 'correct horse', Fixtures::context($this->clock->now()));

        // Then
        static::assertFalse($this->credentials->remainIn($this->tenant));
    }

    /**
     * RFC 8265 §6.2
     */
    #[Test]
    public function theReplacementOfAHashOfBeforeTheProfileIsAnnounced(): void
    {
        // Given
        $this->carolHeldBefore(new FakePasswordHasher()->hash("correct\u{00A0}horse"));

        // When
        $this->authenticator->authenticate($this->tenant, 'carol', "correct\u{00A0}horse", Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(1, $this->events->of(PasswordRehashed::class));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aHashOfTheBytesAsTypedOnARowThatSaysOtherwiseIsReplacedOnceThoseBytesVerifyIt(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $this->carolHeldBefore($hasher->hash('carol pass'));
        $david = $this->davidHolds($hasher->hash("david\u{00A0}pass"));

        // When
        $this->authenticator->authenticate($this->tenant, 'david', "david\u{00A0}pass", Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($hasher->hash('david pass')->encoded, $this->credentials->findByUser($david, PasswordCredential::class)[0]?->hash->encoded);
    }

    /**
     * RFC 8265 §4.2.3
     */
    #[Test]
    public function aHashOfTheEnforcedFormIsKeptWhenThePasswordIsTypedInAnotherForm(): void
    {
        // Given
        $this->carolHolds(new FakePasswordHasher()->hash('correct horse'));

        // When
        $this->authenticator->authenticate($this->tenant, 'carol', "correct\u{00A0}horse", Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([], $this->events->of(PasswordRehashed::class));
    }

    /**
     * RFC 8265 §4.2.3, §8.2, decision 0058
     */
    #[Test]
    public function aHashTheHasherWouldReplaceIsReplacedByAHashOfTheEnforcedForm(): void
    {
        // Given
        $time = new FakeMonotonicClock();
        $authenticator = $this->authenticatorOn(new TimedPasswordHasher($time, self::COSTS), null, $time);
        $carol = $this->carolHolds(TimedPasswordHasher::hashOf(new Bcrypt(), 'correct horse'));

        // When
        $authenticator->authenticate($this->tenant, 'carol', "correct\u{00A0}horse", Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(
            TimedPasswordHasher::hashOf(new Argon2id(), 'correct horse')->encoded,
            $this->credentials->findByUser($carol, PasswordCredential::class)[0]?->hash->encoded,
        );
    }

    /**
     * RFC 8265 §4.1, §4.3, decision 0006
     */
    #[Test]
    public function aPasswordTheProfileRefusesFailsEvenAgainstAHashOfItsBytes(): void
    {
        // Given
        $this->carolHeldBefore(new FakePasswordHasher()->hash("my cat is a \u{0009}by"));

        // When
        $exception = $this->failToAuthenticate('carol', "my cat is a \u{0009}by");

        // Then
        static::assertSame(AuthenticationFailureReason::DisallowedCharacter, $exception->reason);
    }

    /**
     * Decision 0006, decision 0058
     */
    #[Test]
    #[DataProvider('provideAccounts')]
    public function aPasswordTheProfileRefusesCostsOneVerificationOfTheDecoyWhateverTheAccount(string $username, int $allowedAttempts): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $held = [
            $this->carolHeldBefore($hasher->hash("my cat is a \u{0009}by")),
            $this->davidHolds($hasher->hash('david pass')),
            $this->alice,
        ];
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $authenticator = $this->authenticatorOn($hasher, new FakeAttemptLimiter($allowedAttempts));

        // When
        try {
            $authenticator->authenticate($this->tenant, $username, "my cat is a \u{0009}by", Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $hasher->verifiedAgainst);
        static::assertNotContains($hasher->verifiedAgainst[0], $this->hashesOf($held));
    }

    /**
     * Decision 0006, decision 0058, RFC 8265 §6.2
     */
    #[Test]
    #[DataProvider('provideAccounts')]
    public function aWrongPasswordTypedInAnotherFormCostsTwoVerificationsWhateverTheAccountWhileAHashOfBeforeRemains(
        string $username,
        int $allowedAttempts,
    ): void {
        // Given
        $hasher = new FakePasswordHasher();
        $this->carolHeldBefore($hasher->hash("carol\u{00A0}pass"));
        $this->davidHolds($hasher->hash('david pass'));
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $authenticator = $this->authenticatorOn($hasher, new FakeAttemptLimiter($allowedAttempts));

        // When
        try {
            $authenticator->authenticate($this->tenant, $username, "not\u{00A0}the password", Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(2, $hasher->verifiedAgainst);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideAccounts(): iterable
    {
        yield 'an unknown user' => ['mallory', 5];
        yield 'a user without a password' => ['bob', 5];
        yield 'an attempt too many' => ['alice', 0];
        yield 'a hash of the bytes as they were typed' => ['carol', 5];
        yield 'a hash of an enforced form' => ['david', 5];
    }

    /**
     * Decision 0065, decision 0058
     */
    #[Test]
    #[DataProvider('provideAccountsOfATenantOfTheProfile')]
    public function aWrongPasswordTypedInAnotherFormCostsOneVerificationWhateverTheAccountOnceNoHashOfBeforeRemains(
        string $username,
        int $allowedAttempts,
    ): void {
        // Given
        $hasher = new FakePasswordHasher();
        $this->davidHolds($hasher->hash('david pass'));
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $authenticator = $this->authenticatorOn($hasher, new FakeAttemptLimiter($allowedAttempts));

        // When
        try {
            $authenticator->authenticate($this->tenant, $username, "not\u{00A0}the password", Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $hasher->verifiedAgainst);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideAccountsOfATenantOfTheProfile(): iterable
    {
        yield 'an unknown user' => ['mallory', 5];
        yield 'a user without a password' => ['bob', 5];
        yield 'an attempt too many' => ['alice', 0];
        yield 'a hash of an enforced form' => ['david', 5];
    }

    /**
     * Decision 0058, RFC 8265 §6.2
     */
    #[Test]
    #[DataProvider('provideAccountsOfEveryHash')]
    public function aWrongPasswordTypedInAnotherFormTakesTwiceTheTimeOfTheDecoyWhateverTheHashWhileAHashOfBeforeRemains(string $username): void
    {
        // Given
        $time = new FakeMonotonicClock();
        $authenticator = $this->authenticatorOn(new TimedPasswordHasher($time, self::COSTS), null, $time);
        $this->carolHeldBefore(TimedPasswordHasher::hashOf(new Bcrypt(), "carol\u{00A0}pass"));
        $this->davidHolds(TimedPasswordHasher::hashOf(new Argon2id(), 'david pass'));
        $this->failToAuthenticateWith($authenticator, 'mallory');
        $start = $time->now();

        // When
        try {
            $authenticator->authenticate($this->tenant, $username, "not\u{00A0}the password", Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame(2 * self::COSTS[Argon2id::NAME], $time->now() - $start);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAccountsOfEveryHash(): iterable
    {
        yield 'an unknown user' => ['mallory'];
        yield 'a bcrypt of the bytes as they were typed, which the hasher would replace' => ['carol'];
        yield 'an argon2id of the enforced form' => ['david'];
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aPasswordVerifiedUnderBothItsFormsIsOneAttempt(): void
    {
        // Given
        $this->carolHeldBefore(new FakePasswordHasher()->hash('carol pass'));

        // When
        $this->failToAuthenticate('alice', "not\u{00A0}the password");

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $this->attempts->attempts);
    }

    private function carolHolds(PasswordHash $hash): User
    {
        return $this->holds('carol', $hash);
    }

    /**
     * A row written before the provider enforced the OpaqueString profile.
     */
    private function carolHeldBefore(PasswordHash $hash): User
    {
        $carol = $this->carolHolds($hash);
        Fixtures::hashedAsTyped($this->credentials->findByUser($carol, PasswordCredential::class)[0] ?? static::fail('Carol holds no password.'));

        return $carol;
    }

    private function davidHolds(PasswordHash $hash): User
    {
        return $this->holds('david', $hash);
    }

    private function holds(string $username, PasswordHash $hash): User
    {
        $user = Fixtures::user($this->tenant, $username, $username . '-subject');
        $this->users->save($user);
        $this->credentials->save(new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now()));

        return $user;
    }

    /**
     * @param list<User> $users
     *
     * @return list<string>
     */
    private function hashesOf(array $users): array
    {
        return array_map(
            fn (User $user): string => (
                $this->credentials->findByUser($user, PasswordCredential::class)[0] ?? static::fail('A user holds no password.')
            )->hash->encoded,
            $users,
        );
    }

    private function failToAuthenticateWith(PasswordAuthenticator $authenticator, string $identifier): void
    {
        try {
            $authenticator->authenticate($this->tenant, $identifier, 'not the password', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException) {
        }
    }

    private function failToAuthenticate(string $identifier, string $password): AuthenticationFailedException
    {
        try {
            $this->authenticator->authenticate($this->tenant, $identifier, $password, Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException $exception) {
            return $exception;
        }

        static::fail('Authentication should have failed.');
    }
}
