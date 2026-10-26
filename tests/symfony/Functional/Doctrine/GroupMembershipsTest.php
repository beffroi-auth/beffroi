<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002, issue #782: the memberships of a person written in beffroi_group_membership, by the port
 * beside the one that reads them, and replaced there by the sign-in through an upstream provider.
 */
final class GroupMembershipsTest extends DatabaseTestCase
{
    #[Test]
    public function aMembershipSavedIsReadBack(): void
    {
        // Given
        $user = self::user();
        $admins = self::group('admins');

        // When
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $user, GroupSource::UpstreamClaims, self::now()));

        // Then
        self::reload();
        $memberships = self::groupsOf($user);
        static::assertCount(1, $memberships);
        static::assertSame('admins', $memberships[0]->group->name);
        static::assertSame(GroupSource::UpstreamClaims, $memberships[0]->source);
    }

    /**
     * The row goes; the group stays, others may be in it.
     */
    #[Test]
    public function aMembershipTakenBackLeavesTheTableAndTheGroupStays(): void
    {
        // Given
        $user = self::user();
        $admins = self::group('admins');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $user, GroupSource::UpstreamClaims, self::now()));
        self::reload();
        $membership = self::groupsOf($user)[0];

        // When
        self::memberships()->remove($membership);

        // Then
        self::reload();
        static::assertSame([], self::groupsOf($user));
        static::assertNotNull(self::entityManager()->find(Group::class, $admins->id));
    }

    /**
     * The use case as the container wires it, on the table: the membership the provider no longer asserts
     * goes, the one it asserts now comes, the local one stays.
     */
    #[Test]
    public function aSignInReplacesTheUpstreamMembershipsInTheTable(): void
    {
        // Given
        $user = self::user();
        $admins = self::group('admins');
        $sales = self::group('sales');
        $staff = self::group('staff');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $user, GroupSource::Local, self::now()));
        self::memberships()->save(new GroupMembership(Uuid::v7(), $sales, $user, GroupSource::UpstreamClaims, self::now()));
        $mapping = new GroupMapping([
            'sales-guid' => $sales,
            'staff-guid' => $staff,
        ]);

        // When
        self::service('test.beffroi.upstream_memberships', UpstreamMemberships::class)->replace($user, ['staff-guid'], $mapping);

        // Then
        self::reload();
        $sources = [];
        foreach (self::groupsOf($user) as $membership) {
            $sources[$membership->group->name] = $membership->source;
        }
        static::assertSame(
            [
                'admins' => GroupSource::Local,
                'staff' => GroupSource::UpstreamClaims,
            ],
            $sources,
        );
    }

    private static function group(string $name): Group
    {
        $group = new Group(Uuid::v7(), self::tenant(), $name, GroupSource::Local, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->flush();

        return $group;
    }

    private static function memberships(): GroupMembershipRepositoryInterface
    {
        return self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class);
    }

    /**
     * @return list<GroupMembership>
     */
    private static function groupsOf(User $user): array
    {
        return self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($user);
    }
}
