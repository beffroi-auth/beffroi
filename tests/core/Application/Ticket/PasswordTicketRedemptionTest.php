<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Ticket;

use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Tests\Fixture\FakeChannelChangeWindow;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Application\Ticket\PasswordTicketRedemption;
use Beffroi\Core\Application\Ticket\TicketIssuing;
use Beffroi\Core\Application\Ticket\TicketRedeeming;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryPasswordTicketRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Credential\PasswordChangeRefusal;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Domain\Ticket\PasswordTicket;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Beffroi\Core\Exception\PasswordRefusedException;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\FixedClaims;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\SectionsOneAtATime;
use function count;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Beffroi\Core\Tests\Fixture\FakeMonotonicClock;

/**
 * Decision 0026
 */
final class PasswordTicketRedemptionTest extends TestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    private const string BREACHED = 'monkey business as usual';

    private User $alice;

    private FakePasswordHasher $hasher;

    private InMemoryCredentialRepository $credentials;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryPasswordTicketRepository $tickets;

    private RecordingEventDispatcher $events;

    private RecordingCredentialChangeNotifier $notifier;

    private MockClock $clock;

    private SectionsOneAtATime $sections;

    private PasswordTicketRedemption $redemption;

    /**
     * @var IssuedTicket<PasswordTicket>
     */
    private IssuedTicket $issued;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->hasher = new FakePasswordHasher();
        $this->credentials = new InMemoryCredentialRepository();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->tickets = new InMemoryPasswordTicketRepository();
        $this->events = new RecordingEventDispatcher();
        $this->notifier = new RecordingCredentialChangeNotifier();
        $this->clock = new MockClock('2026-11-17T12:00:00+00:00');
        $this->sections = new SectionsOneAtATime();
        $active = new ActivePassword(new ActiveCredentials($this->credentials));
        $this->redemption = new PasswordTicketRedemption(
            $this->tickets,
            new TicketRedeeming(
                $this->hasher,
                new DecoyHash($this->hasher, new SymfonyUuidGenerator(), new FakeMonotonicClock()),
                $this->clock,
                $this->sections,
            ),
            $active,
            $this->hasher,
            new UserProvisioner(
                new InMemoryUserRepository(),
                $this->credentials,
                $active,
                $this->hasher,
                new BreachedPasswordRefusal(BreachedPasswordsOfARecord::holding([self::BREACHED])),
                new EnrolmentRefusal(new FederatedDomains(new InMemoryUpstreamProviders())),
                new SymfonyUuidGenerator(),
                $this->clock,
                new FixedClaims([]),
                new ChannelChangeNotice(new FakeChannelChangeWindow(), new RecordingCredentialChangeNotifier()),
            ),
            new OtherSessionsTermination($this->sessions, new SessionTerminator($this->sessions, $this->clock, $this->events)),
            $this->clock,
            $this->events,
            $this->notifier,
        );
        $this->issued = $this->ticketOf($this->alice);
    }

    #[Test]
    public function theTicketOfTheLinkOpens(): void
    {
        // When
        $ticket = $this->redemption->redeem($this->alice->tenant, $this->issued->ticket->id, $this->issued->value);

        // Then
        static::assertSame($this->issued->ticket, $ticket);
    }

    #[Test]
    public function aWrongValueOpensNothing(): void
    {
        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs('This ticket opens nothing.');

        // When
        $this->redemption->redeem($this->alice->tenant, $this->issued->ticket->id, 'not the value of the link');
    }

    #[Test]
    public function thePasswordPosedReplacesTheOneHeld(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::POSED));
    }

    #[Test]
    public function replacingThePasswordIsTheActOfAChange(): void
    {
        // Given
        $this->passwordInUse();

        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([1, 0], [count($this->events->of(PasswordChanged::class)), count($this->events->of(CredentialEnrolled::class))]);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function thePersonIsToldTheirPasswordWasReplaced(): void
    {
        // Given
        $this->passwordInUse();

        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([[PasswordChanged::NAME, 'password']], $this->notifier->acts());
    }

    #[Test]
    public function aPersonWithoutAPasswordPosesTheirFirst(): void
    {
        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        $held = new ActivePassword(new ActiveCredentials($this->credentials))->of($this->alice) ?? static::fail('No password is held.');
        static::assertTrue($this->hasher->verify($held->hash, self::POSED));
    }

    #[Test]
    public function aFirstPasswordIsTheActOfAnEnrolment(): void
    {
        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([0, 1], [count($this->events->of(PasswordChanged::class)), count($this->events->of(CredentialEnrolled::class))]);
    }

    /**
     * NIST SP 800-63B-4 §4.1.2.1
     */
    #[Test]
    public function thePersonIsToldAFirstPasswordWasAdded(): void
    {
        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([[CredentialEnrolled::NAME, 'password']], $this->notifier->acts());
    }

    #[Test]
    public function theTicketIsSpentOnceThePasswordIsWritten(): void
    {
        // Given
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        $this->expectException(TicketRefusedException::class);

        // When
        $this->redemption->redeem($this->alice->tenant, $this->issued->ticket->id, $this->issued->value);
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function thePasswordIsWrittenAloneAmongTheRedemptionsOfTheTicket(): void
    {
        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(['beffroi.ticket.' . $this->issued->ticket->id->toRfc4122()], $this->sections->entered);
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function aTicketAnotherRedemptionSpentMeanwhileIsRefused(): void
    {
        // Given
        $this->spentByAnotherRedemption();

        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs('This ticket opens nothing.');

        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function aTicketAnotherRedemptionSpentMeanwhileWritesNoPassword(): void
    {
        // Given
        $this->spentByAnotherRedemption();

        // When
        try {
            $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));
        } catch (TicketRefusedException) {
        }

        // Then
        static::assertNull(new ActivePassword(new ActiveCredentials($this->credentials))->of($this->alice));
    }

    #[Test]
    public function everySessionOfThePersonEndsWithTheSecretItOpenedWith(): void
    {
        // Given
        $here = Fixtures::session($this->alice, $this->clock->now());
        $there = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($here);
        $this->sessions->save($there);

        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(
            [SessionEnd::User, SessionEnd::User, 2],
            [$here->endedBy, $there->endedBy, count($this->events->of(AuthenticationSessionEnded::class))],
        );
    }

    #[Test]
    public function thePasswordHeldAlreadyIsRefused(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::IN_USE), Fixtures::context($this->clock->now()));
            static::fail('The password held was posed again.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::SameAsBefore, $exception->refusal);
        }
    }

    #[Test]
    public function aPasswordRefusedLeavesTheTicketToSpendAndTheSessionsOpen(): void
    {
        // Given
        $this->passwordInUse();
        $session = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($session);

        // When
        try {
            $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::IN_USE), Fixtures::context($this->clock->now()));
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertSame([false, false], [$this->issued->ticket->isSpent(), $session->hasEnded()]);
    }

    #[Test]
    public function aPasswordRefusedTellsThePersonNothing(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::IN_USE), Fixtures::context($this->clock->now()));
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertSame([], $this->notifier->told);
    }

    #[Test]
    public function aPasswordAListOfCompromisedPasswordsCountsIsRefused(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);

        // When
        $this->redemption->spend($this->issued->ticket, Fixtures::plainPassword(self::BREACHED), Fixtures::context($this->clock->now()));
    }

    /**
     * Decision 0025: a floor raised once the ticket was issued refuses the password it would pose.
     */
    #[Test]
    public function aTenantThatSignsInWithoutAPasswordRefusesThePasswordOfATicket(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant(), 'carol');
        $ticket = new PasswordTicket(Uuid::v7(), $carol, $this->hasher->hash('the value'), $this->clock->now(), $this->clock->now()->modify('+72 hours'));
        $this->tickets->save($ticket);

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);

        // When
        $this->redemption->spend($ticket, Fixtures::plainPassword(self::POSED), Fixtures::context($this->clock->now()));
    }

    /**
     * @return IssuedTicket<PasswordTicket>
     */
    private function ticketOf(User $user): IssuedTicket
    {
        return new TicketIssuing(new SymfonyUuidGenerator(), new PlatformRandomness(), $this->hasher, $this->clock)->issue(
            $this->tickets,
            $user,
            static fn (
                Uuid $id,
                User $user,
                PasswordHash $secret,
                DateTimeImmutable $issuedAt,
                DateTimeImmutable $expiresAt,
            ): PasswordTicket => new PasswordTicket($id, $user, $secret, $issuedAt, $expiresAt),
        );
    }

    /**
     * What the store holds once another request has redeemed the same ticket: its row spent.
     */
    private function spentByAnotherRedemption(): void
    {
        $this->issued->ticket->spend($this->clock->now());
        $this->tickets->save($this->issued->ticket);
    }

    private function passwordInUse(): PasswordCredential
    {
        $credential = new PasswordCredential(Uuid::v7(), $this->alice, $this->hasher->hash(self::IN_USE), Fixtures::now());
        $this->credentials->save($credential);

        return $credential;
    }
}
