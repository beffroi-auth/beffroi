<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Enrolment;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Application\Ticket\TicketIssuing;
use Beffroi\Core\Bridge\InMemory\InMemoryEnrolmentTicketRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Clock\MockClock;

final class EnrolmentTicketIssueTest extends TestCase
{
    private User $alice;

    private FakePasswordHasher $hasher;

    private InMemoryEnrolmentTicketRepository $tickets;

    private RecordingEventDispatcher $events;

    private RecordingCredentialChangeNotifier $notifier;

    private MockClock $clock;

    private EnrolmentTicketIssue $issue;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->hasher = new FakePasswordHasher();
        $this->tickets = new InMemoryEnrolmentTicketRepository();
        $this->events = new RecordingEventDispatcher();
        $this->notifier = new RecordingCredentialChangeNotifier();
        $this->clock = new MockClock('2026-10-11T12:00:00+00:00');
        $this->issue = new EnrolmentTicketIssue(
            $this->tickets,
            new TicketIssuing(new SymfonyUuidGenerator(), new PlatformRandomness(), $this->hasher, $this->clock),
            $this->events,
            $this->notifier,
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
    public function aTicketOpensItsEnrolmentForSeventyTwoHours(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now()->modify('+72 hours'), $issued->ticket->expiresAt);
    }

    #[Test]
    public function theIssuingIsAnActOfThatAccount(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(EnrolmentTicketIssued::class);
        static::assertCount(1, $acts);
        static::assertSame($issued->ticket, $acts[0]->ticket);
        static::assertSame($this->alice->subject, $acts[0]->subject());
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function thePersonIsToldALinkToAddAPasskeyWasIssued(): void
    {
        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([[EnrolmentTicketIssued::NAME, null]], $this->notifier->acts());
        static::assertEquals($this->clock->now(), $this->notifier->told[0]->occurredAt);
        static::assertTrue($this->alice->id->equals($this->notifier->told[0]->userId));
    }

    #[Test]
    public function theActOfATicketTheHostIssuedNamesIt(): void
    {
        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(EnrolmentTicketIssued::class);
        static::assertCount(1, $acts);
        static::assertEquals(new TheHost(), $acts[0]->author());
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
        $issued = $this->issue->issueByAnAdministrator($this->alice, $administrator, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(EnrolmentTicketIssued::class);
        static::assertCount(1, $acts);
        static::assertSame($issued->ticket, $acts[0]->ticket);
        static::assertEquals(new AnAdministrator($administrator), $acts[0]->author());
    }

    #[Test]
    public function aSecondTicketTakesTheFirstAway(): void
    {
        // Given
        $first = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // When
        $second = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertNull($this->tickets->find($first->ticket->id));
        static::assertSame([$second->ticket], $this->tickets->unspentOf($this->alice));
    }

    #[Test]
    public function everyUnspentTicketOfThatPersonGoes(): void
    {
        // Given
        $first = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        $second = new EnrolmentTicket(
            Uuid::v7(),
            $this->alice,
            $this->hasher->hash('the value of another link'),
            $this->clock->now(),
            $this->clock->now()->modify('+72 hours'),
        );
        $this->tickets->save($second);

        // When
        $third = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([$third->ticket], $this->tickets->unspentOf($this->alice));
        static::assertNull($this->tickets->find($first->ticket->id));
        static::assertNull($this->tickets->find($second->id));
    }

    #[Test]
    public function theTicketOfAnotherPersonIsLeftWhereItIs(): void
    {
        // Given
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $theirs = $this->issue->issue($bob, Fixtures::context($this->clock->now()));

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($theirs->ticket, $this->tickets->find($theirs->ticket->id));
    }

    #[Test]
    public function aTicketAlreadySpentIsLeftWhereItIs(): void
    {
        // Given
        $spent = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        $spent->ticket->spend($this->clock->now());
        $this->tickets->save($spent->ticket);

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($spent->ticket, $this->tickets->find($spent->ticket->id));
    }

    #[Test]
    public function aDisabledPersonGetsNoTicket(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs('The account of "alice" is disabled; a ticket would open nothing.');

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
    }

    #[Test]
    public function nothingIsWrittenForADisabledPerson(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // When
        try {
            $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        } catch (TicketRefusedException) {
        }

        // Then
        static::assertSame([], $this->tickets->unspentOf($this->alice));
        static::assertSame([], $this->events->of(EnrolmentTicketIssued::class));
    }

    #[Test]
    public function aDisabledPersonIsToldNothing(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // When
        try {
            $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        } catch (TicketRefusedException) {
        }

        // Then
        static::assertSame([], $this->notifier->told);
    }
}
