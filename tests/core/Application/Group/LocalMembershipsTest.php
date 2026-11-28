<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Group;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Application\Group\LocalMemberships;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\GroupMembershipException;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Domain\Event\GroupMembershipAdded;
use Beffroi\Core\Domain\Event\GroupMembershipRemoved;
use Beffroi\Core\Domain\Identity\Subject;
use function array_map;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002: the members the tenant holds itself in its groups, given and taken back from a console; what a
 * directory holds is written by that directory alone.
 */
final class LocalMembershipsTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private Group $group;

    private InMemoryGroupMembershipRepository $memberships;

    private MockClock $clock;

    private RecordingEventDispatcher $events;

    private LocalMemberships $local;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->group = new Group(Uuid::v7(), $this->tenant, 'administrators', GroupSource::Local, Fixtures::now());
        $this->memberships = new InMemoryGroupMembershipRepository();
        $this->clock = new MockClock('2026-11-04T12:00:00+00:00');
        $this->events = new RecordingEventDispatcher();
        $this->local = new LocalMemberships($this->memberships, $this->memberships, new SymfonyUuidGenerator(), $this->clock, $this->events);
    }

    /**
     * Decision 0038: a membership can make an administrator, so the person reads that it changed.
     */
    #[Test]
    public function aMembershipAddedFromTheConsoleIsAnActOfThePersonThatNamesTheHost(): void
    {
        // When
        $this->local->add($this->group, $this->user, Fixtures::context());

        // Then
        static::assertEquals(
            [[$this->user->subject->value, $this->group->id, 'administrators', new TheHost()]],
            array_map(
                static fn (GroupMembershipAdded $act): array => [$act->subject()->value, $act->groupId, $act->group, $act->author()],
                $this->events->of(GroupMembershipAdded::class),
            ),
        );
    }

    #[Test]
    public function aMembershipAnAdministratorAddedNamesThem(): void
    {
        // When
        $this->local->addByAnAdministrator($this->group, $this->user, new Subject('administrator-subject'), Fixtures::context());

        // Then
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $this->events->of(GroupMembershipAdded::class)[0]->author());
    }

    #[Test]
    public function aMembershipTakenBackIsAnActOfThePerson(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // When
        $this->local->remove($this->group, $this->user, Fixtures::context());

        // Then
        static::assertEquals(
            [[$this->user->subject->value, $this->group->id, 'administrators', new TheHost()]],
            array_map(
                static fn (GroupMembershipRemoved $act): array => [$act->subject()->value, $act->groupId, $act->group, $act->author()],
                $this->events->of(GroupMembershipRemoved::class),
            ),
        );
    }

    #[Test]
    public function aMembershipAnAdministratorTookBackNamesThem(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // When
        $this->local->removeByAnAdministrator($this->group, $this->user, new Subject('administrator-subject'), Fixtures::context());

        // Then
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $this->events->of(GroupMembershipRemoved::class)[0]->author());
    }

    #[Test]
    public function aMembershipRefusedAnnouncesNothing(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // When
        try {
            $this->local->add($this->group, $this->user, Fixtures::context());
        } catch (GroupMembershipException) {
        }

        // Then
        static::assertCount(1, $this->events->of(GroupMembershipAdded::class));
    }

    #[Test]
    public function aPersonIsMadeAMemberTheTenantHoldsItself(): void
    {
        // When
        $this->local->add($this->group, $this->user, Fixtures::context());

        // Then
        $memberships = $this->memberships->of($this->user);
        static::assertSame(
            [[$this->group, GroupSource::Local, $this->clock->now()->getTimestamp()]],
            [[$memberships[0]->group, $memberships[0]->source, $memberships[0]->addedAt->getTimestamp()]],
        );
    }

    #[Test]
    public function aMemberIsNotMadeOneTwice(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // Then
        $this->expectException(GroupMembershipException::class);
        $this->expectExceptionMessageIs('This person is already a member of the group "administrators".');

        // When
        $this->local->add($this->group, $this->user, Fixtures::context());
    }

    #[Test]
    public function aGroupScimFillsTakesNoMemberFromTheTenant(): void
    {
        // Given
        $directory = new Group(Uuid::v7(), $this->tenant, 'engineering', GroupSource::Scim, Fixtures::now());

        // Then
        $this->expectException(GroupMembershipException::class);
        $this->expectExceptionMessageIs('The members of the group "engineering" are written by the directory that fills it, never by the tenant.');

        // When
        $this->local->add($directory, $this->user, Fixtures::context());
    }

    #[Test]
    public function aMembershipTheTenantHoldsIsTakenBack(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // When
        $this->local->remove($this->group, $this->user, Fixtures::context());

        // Then
        static::assertSame([], $this->memberships->of($this->user));
    }

    #[Test]
    public function aPersonWhoIsNoMemberIsNotTakenOut(): void
    {
        // Then
        $this->expectException(GroupMembershipException::class);
        $this->expectExceptionMessageIs('This person is not a member of the group "administrators".');

        // When
        $this->local->remove($this->group, $this->user, Fixtures::context());
    }

    #[Test]
    public function aMembershipAnotherRemovalTookAwayFirstIsRefusedAsOneThePersonDoesNotHold(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // Then
        $this->expectException(GroupMembershipException::class);
        $this->expectExceptionMessageIs('This person is not a member of the group "administrators".');

        // When
        $this->removedMeanwhile()->remove($this->group, $this->user, Fixtures::context());
    }

    #[Test]
    public function aMembershipAnotherRemovalTookAwayFirstIsNotAnnouncedAgain(): void
    {
        // Given
        $this->local->add($this->group, $this->user, Fixtures::context());

        // When
        try {
            $this->removedMeanwhile()->remove($this->group, $this->user, Fixtures::context());
        } catch (GroupMembershipException) {
        }

        // Then
        static::assertSame([], $this->events->of(GroupMembershipRemoved::class));
    }

    /**
     * The next assertion of the upstream provider would write it again.
     */
    #[Test]
    public function aMembershipAnUpstreamProviderGaveIsNotTakenBackByTheTenant(): void
    {
        // Given
        $this->memberships->save(new GroupMembership(Uuid::v7(), $this->group, $this->user, GroupSource::UpstreamClaims, Fixtures::now()));

        // Then
        $this->expectException(GroupMembershipException::class);
        $this->expectExceptionMessageIs('This person is a member of the group "administrators" by a directory, which alone takes the membership back.');

        // When
        $this->local->remove($this->group, $this->user, Fixtures::context());
    }

    /**
     * The use case on a store whose row another removal deleted between the reading and the deletion.
     */
    private function removedMeanwhile(): LocalMemberships
    {
        $writer = new readonly class($this->memberships) implements GroupMembershipRepositoryInterface {
            public function __construct(
                private GroupMembershipRepositoryInterface $stored,
            ) {
            }

            public function save(GroupMembership $membership): void
            {
                $this->stored->save($membership);
            }

            public function remove(GroupMembership $membership): bool
            {
                $this->stored->remove($membership);

                return false;
            }
        };

        return new LocalMemberships($writer, $this->memberships, new SymfonyUuidGenerator(), $this->clock, $this->events);
    }
}
