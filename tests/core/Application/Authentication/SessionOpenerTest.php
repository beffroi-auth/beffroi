<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use DateInterval;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Authentication\AuthenticationRefusal;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use function array_map;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class SessionOpenerTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private SessionOpener $opener;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-20T09:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now()->modify('-1 second'), '198.51.100.7');
        $this->opener = new SessionOpener(
            $this->sessions,
            new SymfonyUuidGenerator(),
            $this->clock,
            $this->events,
            new AuthenticationRefusal($this->clock, $this->events),
            new DateInterval('PT8H'),
        );
    }

    #[Test]
    public function itOpensASessionOfTheUserInTheTenant(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertSame($this->tenant, $session->tenant);
        static::assertSame($this->alice, $session->user);
        static::assertSame($this->context, $session->createdFrom);
        static::assertFalse($session->hasEnded());
    }

    #[Test]
    public function itDatesTheSessionNowNotWhenTheRequestWasReceived(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertEquals($this->clock->now(), $session->establishedAt);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
    }

    /**
     * beffroi/saml S-57, OIDC Core §2: what an upstream identity provider proved is dated by the instant it says the
     * person authenticated, its AuthnInstant, which is the auth_time of the session, and not by the instant the
     * session is opened.
     */
    #[Test]
    public function itDatesTheProofsWhenWhatProvedThemSaysTheyWereGiven(): void
    {
        // Given
        $authnInstant = $this->clock->now()->modify('-3 minutes');

        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context, $authnInstant);

        // Then
        static::assertEquals([$authnInstant, $this->clock->now()], [$session->authenticatedAt(), $session->establishedAt]);
    }

    /**
     * beffroi/saml S-57, saml2-model M-7: an instant ahead of the clock, which the model admits within its skew, is
     * dated by the clock, no proof being later than the session that holds it.
     */
    #[Test]
    public function aProofDatedAheadOfTheClockIsDatedByTheClock(): void
    {
        // When
        $session = $this->opener->open(
            $this->tenant,
            $this->alice,
            [AuthenticationMethod::password()],
            $this->context,
            $this->clock->now()->modify('+2 minutes'),
        );

        // Then
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
    }

    /**
     * beffroi/saml S-57, SAML Core §2.7.2: a session an upstream identity provider allows until an instant before the
     * end of its lifetime ends then; one it allows longer ends with its lifetime.
     */
    #[Test]
    #[DataProvider('provideBounds')]
    public function theSessionEndsNoLaterThanWhatProvedItAllows(string $bound, string $expiresAt): void
    {
        // When
        $session = $this->opener->open(
            $this->tenant,
            $this->alice,
            [AuthenticationMethod::password()],
            $this->context,
            null,
            $this->clock->now()->modify($bound),
        );

        // Then
        static::assertEquals($this->clock->now()->modify($expiresAt), $session->expiresAt);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBounds(): iterable
    {
        yield 'before the end of its lifetime' => ['+2 hours', '+2 hours'];
        yield 'after it' => ['+10 hours', '+8 hours'];
    }

    #[Test]
    public function itProvesEveryMethodGivenAtOnce(): void
    {
        // Given
        $methods = [new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), new AuthenticationMethod(AuthenticationMethod::USER_PRESENCE)];

        // When
        $session = $this->opener->open($this->tenant, $this->alice, $methods, $this->context);

        // Then
        static::assertSame(['hwk', 'user'], $session->methodReferences());
        static::assertEquals($this->clock->now(), $session->proofs->provenAt($methods[0]));
        static::assertEquals($this->clock->now(), $session->proofs->provenAt($methods[1]));
    }

    #[Test]
    public function itExpiresTheSessionAfterTheLifetimeGiven(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
    }

    /**
     * Issue #327: the floor of the tenant holds here, because every login of this provider ends here. A
     * password proves nothing of a tenant that signs its users in by passkey, so the session is not opened,
     * and the refusal is announced like any other (AuthenticationRefusal).
     */
    #[Test]
    public function aLoginUnderTheFloorOfItsTenantOpensNoSession(): void
    {
        // Given
        $hardened = Fixtures::hardenedTenant();

        // When
        try {
            $this->opener->open($hardened, Fixtures::user($hardened), [AuthenticationMethod::password()], $this->context);
            static::fail('The session should not have been opened.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::BelowTheFloor, $exception->reason);
            static::assertSame([], $this->events->of(UserAuthenticated::class));
            static::assertCount(1, $this->events->of(AuthenticationFailed::class));
        }
    }

    /**
     * Issue #327: what the floor reads opens its session as it always did, a synced passkey proving the
     * possession of a key.
     */
    #[Test]
    public function aLoginThatMeetsTheFloorOpensItsSession(): void
    {
        // Given
        $hardened = Fixtures::hardenedTenant();

        // When
        $session = $this->opener->open(
            $hardened,
            Fixtures::user($hardened),
            [new AuthenticationMethod('swk'), new AuthenticationMethod('user')],
            $this->context,
        );

        // Then
        static::assertSame(['swk', 'user'], array_map(static fn (AuthenticationMethod $method): string => $method->value, $session->proofs->methods()));
        static::assertCount(1, $this->events->of(UserAuthenticated::class));
    }

    #[Test]
    public function theDefaultLifetimeIsTwelveHours(): void
    {
        // Given
        $opener = new SessionOpener(
            $this->sessions,
            new SymfonyUuidGenerator(),
            $this->clock,
            $this->events,
            new AuthenticationRefusal($this->clock, $this->events),
        );

        // When
        $session = $opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+12 hours'), $session->expiresAt);
    }

    #[Test]
    public function itSavesTheSession(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function itAnnouncesTheAuthenticationOnce(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertCount(1, $this->events->events);
        static::assertInstanceOf(UserAuthenticated::class, $this->events->events[0]);
        static::assertSame($session, $this->events->events[0]->session);
    }

    #[Test]
    public function twoSessionsOpenedForTheSameUserAreDistinct(): void
    {
        // When
        $first = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);
        $second = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertFalse($first->id->equals($second->id));
        static::assertCount(2, $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function itRefusesAUserOfAnotherTenant(): void
    {
        // Given
        $bob = Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'), 'bob', 'bob-subject');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A session authenticates a user of its own tenant.');

        // When
        $this->opener->open($this->tenant, $bob, [AuthenticationMethod::password()], $this->context);
    }

    #[Test]
    public function nothingIsSavedNorAnnouncedForAUserOfAnotherTenant(): void
    {
        // Given
        $bob = Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'), 'bob', 'bob-subject');

        // When
        try {
            $this->opener->open($this->tenant, $bob, [AuthenticationMethod::password()], $this->context);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($bob, $this->clock->now()));
        static::assertSame([], $this->events->events);
    }
}
