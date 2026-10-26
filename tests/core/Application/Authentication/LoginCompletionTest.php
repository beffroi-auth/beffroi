<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use DateInterval;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Authentication\AuthenticationRefusal;
use Beffroi\Core\Application\Authentication\LoginCompletion;
use Beffroi\Core\Application\Authentication\PendingLoginVerification;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Application\Totp\TotpAuthentication;
use Beffroi\Core\Application\Totp\TotpCodeMatcher;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\TotpUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakeAttemptLimiter;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.2: the login the password held is completed by a code, and the session is opened on
 * both methods at once, dated when the login ended.
 */
final class LoginCompletionTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private FakeAttemptLimiter $attempts;

    private MockClock $clock;

    private PendingLogin $login;

    private LoginCompletion $completion;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $users = new InMemoryUserRepository();
        $users->save($this->alice);
        $hasher = new FakePasswordHasher();
        $credentials = new InMemoryCredentialRepository();
        $credentials->save(new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(new Argon2id(), '$argon2id$alice'), Fixtures::now()));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->attempts = new FakeAttemptLimiter(5);
        $this->clock = new MockClock('2026-09-20T12:00:15+00:00');
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        // enrolled an hour ago: the step of its first code is long past
        $credentials->save(Totps::credential(
            $this->alice,
            $hasher,
            Totps::stepAt($this->clock->now()->modify('-1 hour')),
            createdAt: $this->clock->now()->modify('-1 hour'),
        ));
        // the password was typed a minute ago
        $this->login = PendingLogin::provenAt($this->alice->id, [AuthenticationMethod::password()], $this->clock->now()->modify('-1 minute'));
        $this->completion = new LoginCompletion(
            new PendingLoginVerification(
                $users,
                new AuthenticationRefusal($this->clock, $this->events),
                $this->clock,
                new FederatedDomains($this->upstreamProviders),
            ),
            new TotpAuthentication(
                $credentials,
                new ActiveTotp(new ActiveCredentials($credentials)),
                new TotpCodeMatcher(Totps::algorithm()),
                Totps::sealer(),
                $hasher,
                $this->attempts,
                new AuthenticationRefusal($this->clock, $this->events),
                $this->clock,
                $this->events,
            ),
            new SessionOpener(
                $this->sessions,
                new SymfonyUuidGenerator(),
                $this->clock,
                $this->events,
                new AuthenticationRefusal($this->clock, $this->events),
                new DateInterval('PT8H'),
            ),
        );
    }

    #[Test]
    public function aRightCodeOpensASessionOnWhatBothStepsProved(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), $context);

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertSame(['pwd', 'otp', 'mfa'], $session->methodReferences());
        static::assertSame('2', $session->authenticationContextClass()->value);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
    }

    /**
     * The authentication took place when the code passed, in the sense of auth_time: the password of the
     * first step is dated then too, not a minute earlier.
     */
    #[Test]
    public function bothMethodsAreDatedWhenTheLoginEnds(): void
    {
        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        $now = $this->clock->now()->getTimestamp();
        static::assertSame(
            [
                'pwd' => $now,
                'otp' => $now,
            ],
            $session->proofs->toTimestamps(),
        );
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
    }

    /**
     * The first step may have proven more than one method (a PIN and a smart card, say): all of them are
     * carried onto the session, not the first one.
     */
    #[Test]
    public function everythingTheFirstStepProvedIsCarriedOntoTheSession(): void
    {
        // Given
        $login = PendingLogin::provenAt(
            $this->alice->id,
            [new AuthenticationMethod(AuthenticationMethod::PIN), new AuthenticationMethod(AuthenticationMethod::SMART_CARD)],
            $this->clock->now()->modify('-1 minute'),
        );

        // When
        $session = $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(['pin', 'sc', 'otp', 'mfa'], $session->methodReferences());
    }

    #[Test]
    public function aRightCodeSavesTheSession(): void
    {
        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function aRightCodeAnnouncesTheCodeThenTheAuthentication(): void
    {
        // When
        $session = $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));

        // Then
        static::assertCount(2, $this->events->events);
        static::assertInstanceOf(TotpUsed::class, $this->events->events[0]);
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    #[Test]
    public function aWrongCodeFails(): void
    {
        // When
        try {
            $this->completion->complete($this->tenant, $this->login, '000000', Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
        }
    }

    #[Test]
    public function aWrongCodeOpensNoSession(): void
    {
        // When
        try {
            $this->completion->complete($this->tenant, $this->login, '000000', Fixtures::context($this->clock->now()));
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    /**
     * Five minutes to type a code: past that, the first factor is proven again, and the code is not read.
     */
    #[Test]
    public function anExpiredLoginIsRefusedBeforeTheCodeIsRead(): void
    {
        // Given
        $login = PendingLogin::provenAt($this->alice->id, [AuthenticationMethod::password()], $this->clock->now()->modify('-5 minutes'));

        // When
        try {
            $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::ExpiredLogin, $exception->reason);
            static::assertSame([], $this->attempts->attempts);
            static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
        }
    }

    /**
     * Decision 0029, spec/saml.md S-63: a login held for a person whose domain the tenant has federated since, or
     * whose address has moved into one, completes nothing, and the code is not read.
     */
    #[Test]
    public function aLoginOfAPersonOfAFederatedDomainIsRefusedBeforeTheCodeIsRead(): void
    {
        // Given
        $this->upstreamProviders->declare($this->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        try {
            $this->completion->complete($this->tenant, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::FederatedDomain, $exception->reason);
            static::assertSame([], $this->attempts->attempts);
            static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
        }
    }

    #[Test]
    public function anExpiredLoginIsRecordedWithTheUser(): void
    {
        // Given
        $login = PendingLogin::provenAt($this->alice->id, [AuthenticationMethod::password()], $this->clock->now()->modify('-5 minutes'));
        $context = Fixtures::context($this->clock->now());

        // When
        try {
            $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), $context);
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertCount(1, $this->events->events);
        $failure = $this->events->of(AuthenticationFailed::class)[0];
        static::assertSame(AuthenticationFailureReason::ExpiredLogin, $failure->reason);
        static::assertSame('otp', $failure->method?->value);
        static::assertSame('alice', $failure->identifier);
        static::assertSame($this->alice, $failure->user);
        static::assertSame($this->tenant, $failure->tenant);
        static::assertSame($context, $failure->context);
    }

    #[Test]
    public function aLoginOfAUserWhoNoLongerExistsFails(): void
    {
        // Given
        $gone = Uuid::v7();
        $login = PendingLogin::provenAt($gone, [AuthenticationMethod::password()], $this->clock->now()->modify('-1 minute'));

        // When
        try {
            $this->completion->complete($this->tenant, $login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
            $failure = $this->events->of(AuthenticationFailed::class)[0];
            static::assertNull($failure->user);
            static::assertSame($gone->toRfc4122(), $failure->identifier);
        }
    }

    #[Test]
    public function aLoginOfAUserOfAnotherTenantIsUnknownHere(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When
        try {
            $this->completion->complete($other, $this->login, Totps::codeAt($this->clock->now()), Fixtures::context($this->clock->now()));
            static::fail('The login should not have been completed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::UnknownUser, $exception->reason);
            static::assertSame($other, $this->events->of(AuthenticationFailed::class)[0]->tenant);
        }
    }
}
