<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Ticket;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Ticket\CredentialTicketRefusal;
use Beffroi\Core\Application\Ticket\TotpTicketIssue;
use Beffroi\Core\Application\Ticket\TicketIssuing;
use Beffroi\Core\Bridge\InMemory\InMemoryTotpTicketRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Event\TotpTicketIssued;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0026
 */
final class TotpTicketIssueTest extends TestCase
{
    private User $alice;

    private FakePasswordHasher $hasher;

    private InMemoryTotpTicketRepository $tickets;

    private InMemoryUpstreamProviders $upstreamProviders;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private TotpTicketIssue $issue;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->hasher = new FakePasswordHasher();
        $this->tickets = new InMemoryTotpTicketRepository();
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-11-17T12:00:00+00:00');
        $this->issue = new TotpTicketIssue(
            $this->tickets,
            new TicketIssuing(new SymfonyUuidGenerator(), new PlatformRandomness(), $this->hasher, $this->clock),
            new CredentialTicketRefusal(new EnrolmentRefusal(new FederatedDomains($this->upstreamProviders))),
            $this->events,
        );
    }

    #[Test]
    public function theValueHandedBackIsTheOneTheRowHoldsTheHashOf(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertTrue($this->hasher->verify($issued->ticket->secret, $issued->value));
        static::assertSame($issued->ticket, $this->tickets->find($issued->ticket->id));
    }

    #[Test]
    public function aTicketOpensForSeventyTwoHours(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now()->modify('+72 hours'), $issued->ticket->expiresAt);
    }

    #[Test]
    public function aSecondTicketTakesTheFirstAway(): void
    {
        // Given
        $first = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // When
        $second = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([null, [$second->ticket]], [$this->tickets->find($first->ticket->id), $this->tickets->unspentOf($this->alice)]);
    }

    #[Test]
    public function theActOfATicketTheHostIssuedNamesIt(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(TotpTicketIssued::class);
        static::assertCount(1, $acts);
        static::assertEquals([$issued->ticket, $this->alice->subject, new TheHost()], [$acts[0]->ticket, $acts[0]->subject(), $acts[0]->author()]);
    }

    /**
     * Decision 0038.
     */
    #[Test]
    public function theActOfATicketAnAdministratorIssuedNamesThem(): void
    {
        // Given
        $administrator = new Subject('administrator-subject');

        // When
        $this->issue->issueByAnAdministrator($this->alice, $administrator, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(TotpTicketIssued::class);
        static::assertCount(1, $acts);
        static::assertEquals(new AnAdministrator($administrator), $acts[0]->author());
    }

    #[Test]
    public function aPersonWhoCannotSignInGetsNoTicket(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs('The account of "alice" is disabled; a ticket would open nothing.');

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
    }

    /**
     * Decision 0025
     */
    #[Test]
    public function aTenantThatAdmitsNoCodeGivesNoTotpTicket(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant(), 'carol');

        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIsOrContains('A ticket that poses a one-time code would open nothing. A one-time code proves no login of the tenant');

        // When
        $this->issue->issue($carol, Fixtures::context($this->clock->now()));
    }

    /**
     * Decision 0029
     */
    #[Test]
    public function aPersonOfAFederatedDomainGetsNoTotpTicket(): void
    {
        // Given
        $this->upstreamProviders->declare($this->alice->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIsOrContains('A ticket that poses a one-time code would open nothing. A one-time code is posed for nobody of an e-mail domain');

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
    }

    #[Test]
    public function aTicketRefusedTakesNoTicketAway(): void
    {
        // Given
        $first = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        $this->alice->disable($this->clock->now());

        // When
        try {
            $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        } catch (TicketRefusedException) {
        }

        // Then
        static::assertSame($first->ticket, $this->tickets->find($first->ticket->id));
    }
}
