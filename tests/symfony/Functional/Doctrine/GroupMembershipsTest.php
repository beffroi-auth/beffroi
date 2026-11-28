<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Application\Group\LocalMemberships;
use Beffroi\Core\Application\Group\MembershipWrites;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\MembersOfAGroupInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function array_map;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002
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

    #[Test]
    public function theMembersOfAGroupAreListedInTheOrderTheyWereAdded(): void
    {
        // Given
        $admins = self::group('admins');
        $bob = self::user('bob', 'bob-subject');
        $alice = self::user('alice', 'alice-subject');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $bob, GroupSource::Local, self::now()->modify('-1 hour')));
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, $alice, GroupSource::Local, self::now()));
        self::reload();

        // When
        $members = self::members()->membersOf($admins, new Pagination(1, 10));

        // Then
        static::assertSame(['bob', 'alice'], array_map(static fn (GroupMembership $membership): string => $membership->user->username, $members->rows));
    }

    #[Test]
    public function aPageOfTheMembersHoldsTheMembersOfThatPageAndHowManyTheGroupHolds(): void
    {
        // Given
        $admins = self::group('admins');
        foreach (['bob', 'alice', 'carol'] as $minutes => $username) {
            self::memberships()
                ->save(new GroupMembership(
                    Uuid::v7(),
                    $admins,
                    self::user($username, $username . '-subject'),
                    GroupSource::Local,
                    self::now()->modify(sprintf('+%d minutes', $minutes)),
                ));
        }
        self::reload();

        // When
        $members = self::members()->membersOf($admins, new Pagination(2, 2));

        // Then
        static::assertSame(
            [['carol'], 3],
            [array_map(static fn (GroupMembership $membership): string => $membership->user->username, $members->rows), $members->total],
        );
    }

    #[Test]
    public function membersAddedAtTheSameMomentComeInTheOrderOfTheirIdentifiers(): void
    {
        // Given
        $admins = self::group('admins');
        $first = Uuid::fromString('01890000-0000-7000-8000-000000000001');
        $second = Uuid::fromString('01890000-0000-7000-8000-000000000002');
        self::memberships()->save(new GroupMembership($second, $admins, self::user('bob', 'bob-subject'), GroupSource::Local, self::now()));
        self::memberships()->save(new GroupMembership($first, $admins, self::user('alice', 'alice-subject'), GroupSource::Local, self::now()));
        self::reload();

        // When
        $members = self::members()->membersOf($admins, new Pagination(1, 1));

        // Then
        static::assertSame(['alice'], array_map(static fn (GroupMembership $membership): string => $membership->user->username, $members->rows));
    }

    #[Test]
    public function theMembersOfAGroupAreCounted(): void
    {
        // Given
        $admins = self::group('admins');
        self::memberships()->save(new GroupMembership(Uuid::v7(), $admins, self::user('bob', 'bob-subject'), GroupSource::Local, self::now()));
        self::memberships()->save(new GroupMembership(Uuid::v7(), self::group('staff'), self::user('alice', 'alice-subject'), GroupSource::Local, self::now()));

        // When
        $count = self::members()->countMembersOf($admins);

        // Then
        static::assertSame(1, $count);
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §3.1, §4.1.2 and §4.2
     *
     * @param list<string> $before   what the provider asserted at the sign-in before
     * @param list<string> $asserted
     */
    #[Test]
    #[DataProvider('provideChangesOfTheMembers')]
    public function aMemberASignInAddsOrTakesBackRaisesTheVersionsOfThePersonAndTheGroupInTheTable(array $before, array $asserted): void
    {
        // Given
        $user = self::user();
        $sales = self::group('sales');
        $mapping = new GroupMapping(['sales-guid' => $sales]);
        self::upstream(self::now())->replace($user, $before, $mapping);
        $versions = [$user->version, $sales->version];

        // When
        self::upstream(self::now()->modify('+1 hour'))->replace($user, $asserted, $mapping);

        // Then
        static::assertEquals(
            [[$versions[0] + 1, self::now()->modify('+1 hour')], [$versions[1] + 1, self::now()->modify('+1 hour')]],
            self::versionsInTheTable($user, $sales),
        );
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function provideChangesOfTheMembers(): iterable
    {
        yield 'joined' => [[], ['sales-guid']];
        yield 'left' => [['sales-guid'], []];
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §3.1, §4.1.2 and §4.2
     *
     * @param Closure(LocalMemberships, Group, User): mixed $before
     * @param Closure(LocalMemberships, Group, User): mixed $change
     */
    #[Test]
    #[DataProvider('provideChangesTheTenantMakes')]
    public function aMemberTheTenantAddsOrTakesBackRaisesTheVersionsOfThePersonAndTheGroupInTheTable(Closure $before, Closure $change): void
    {
        // Given
        $user = self::user();
        $staff = self::group('staff');
        $before(self::local(self::now()), $staff, $user);
        $versions = [$user->version, $staff->version];

        // When
        $change(self::local(self::now()->modify('+1 hour')), $staff, $user);

        // Then
        static::assertEquals(
            [[$versions[0] + 1, self::now()->modify('+1 hour')], [$versions[1] + 1, self::now()->modify('+1 hour')]],
            self::versionsInTheTable($user, $staff),
        );
    }

    /**
     * @return iterable<string, array{Closure(LocalMemberships, Group, User): mixed, Closure(LocalMemberships, Group, User): mixed}>
     */
    public static function provideChangesTheTenantMakes(): iterable
    {
        $nothing = static fn (LocalMemberships $local, Group $group, User $user): null => null;
        $added = static fn (LocalMemberships $local, Group $group, User $user): GroupMembership => $local->add($group, $user, Fixtures::context());

        yield 'added' => [$nothing, $added];
        yield 'taken back' => [$added, static fn (LocalMemberships $local, Group $group, User $user) => $local->remove($group, $user, Fixtures::context())];
    }

    /**
     * @return list<array{int, DateTimeImmutable}> of the person, then of the group
     */
    private static function versionsInTheTable(User $user, Group $group): array
    {
        self::reload();
        $person = self::entityManager()->find(User::class, $user->id) ?? static::fail('The person was not stored.');
        $found = self::entityManager()->find(Group::class, $group->id) ?? static::fail('The group was not stored.');

        return [[$person->version, $person->updatedAt], [$found->version, $found->updatedAt]];
    }

    private static function local(DateTimeImmutable $now): LocalMemberships
    {
        return new LocalMemberships(
            self::writes(),
            self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class),
            new SymfonyUuidGenerator(),
            new MockClock($now),
            new RecordingEventDispatcher(),
        );
    }

    private static function writes(): MembershipWrites
    {
        return self::service('test.beffroi.membership_writes', MembershipWrites::class);
    }

    private static function upstream(DateTimeImmutable $now): UpstreamMemberships
    {
        return new UpstreamMemberships(
            self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class),
            self::writes(),
            new SymfonyUuidGenerator(),
            new MockClock($now),
        );
    }

    private static function members(): MembersOfAGroupInterface
    {
        return self::service('test.beffroi.members_of_a_group', MembersOfAGroupInterface::class);
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
