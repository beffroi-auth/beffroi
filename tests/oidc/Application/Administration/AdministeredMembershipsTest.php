<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Administration;

use Beffroi\Core\Application\Group\LocalMemberships;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\GroupMembershipException;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Administration\AdministeredMemberships;
use Beffroi\Oidc\Application\Administration\PersonsOfTheTenant;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038
 */
final class AdministeredMembershipsTest extends TestCase
{
    private Tenant $tenant;

    private Group $group;

    private User $bob;

    private InMemoryGroupMembershipRepository $memberships;

    private InMemoryGroupRepository $groups;

    private InMemoryUserRepository $users;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->group = new Group(Uuid::v7(), $this->tenant, 'auditors', GroupSource::Local, Fixtures::now());
        $this->bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->memberships = new InMemoryGroupMembershipRepository();
        $this->groups = new InMemoryGroupRepository();
        $this->groups->save($this->group);
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->bob);
    }

    #[Test]
    public function aMembershipAnotherRemovalTookAwayFirstIsAnsweredAsOneThePersonDoesNotHold(): void
    {
        // Given
        $this->memberships->save(new GroupMembership(Uuid::v7(), $this->group, $this->bob, GroupSource::Local, Fixtures::now()));
        $removedMeanwhile = new readonly class($this->memberships) implements GroupMembershipRepositoryInterface {
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

        // When
        $removed = $this->memberships($removedMeanwhile)->remove($this->administrator(), $this->group->id, $this->bob->id, Fixtures::context());

        // Then
        static::assertNull($removed);
    }

    #[Test]
    public function aMembershipADirectoryGaveIsStillRefused(): void
    {
        // Given
        $this->memberships->save(new GroupMembership(Uuid::v7(), $this->group, $this->bob, GroupSource::UpstreamClaims, Fixtures::now()));

        // Then
        $this->expectException(GroupMembershipException::class);
        $this->expectExceptionMessageIs('This person is a member of the group "auditors" by a directory, which alone takes the membership back.');

        // When
        $this->memberships($this->memberships)->remove($this->administrator(), $this->group->id, $this->bob->id, Fixtures::context());
    }

    private function memberships(GroupMembershipRepositoryInterface $writer): AdministeredMemberships
    {
        return new AdministeredMemberships(
            $this->groups,
            new PersonsOfTheTenant($this->users),
            $this->memberships,
            new LocalMemberships($writer, $this->memberships, new SymfonyUuidGenerator(), new MockClock(), new RecordingEventDispatcher()),
            new ConfigurationAdministratorGroups($this->tenant->slug),
        );
    }

    private function administrator(): ActingAdministrator
    {
        return new ActingAdministrator($this->tenant, Fixtures::user($this->tenant, 'administrator', 'administrator-subject'), 'beffroi-tui', Uuid::v7());
    }
}
