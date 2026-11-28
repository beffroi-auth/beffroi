<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Group;

use Beffroi\Core\Application\Group\MembershipWrites;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Port\VersionRaisesInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class MembershipWritesTest extends TestCase
{
    /**
     * @var list<array{string, bool}> each write, and whether a unit was open when it was made
     */
    private array $written = [];

    private WritesAsTheyCome $writes;

    private User $alice;

    private Group $staff;

    protected function setUp(): void
    {
        $this->writes = new WritesAsTheyCome();
        $this->alice = Fixtures::user();
        $this->staff = $this->group('staff');
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §4.1.2 and §4.2
     */
    #[Test]
    public function aWriteOnThePersonRaisesThemAndRecordsTheRaiseOfEachGroupInOneUnit(): void
    {
        // Given
        $sales = $this->group('sales', '01890000-0000-7000-8000-000000000001');

        // When
        $this->membershipWrites()->onThePerson(
            $this->alice,
            [$this->membership($this->alice, $this->staff)],
            [$this->membership($this->alice, $sales)],
            Fixtures::now(),
        );

        // Then
        static::assertSame(
            [
                1,
                [
                    ['alice',                 true],
                    ['left sales of alice',   true],
                    ['joined staff of alice', true],
                    ['raise sales',           true],
                    ['raise staff',           true],
                ],
            ],
            [$this->writes->units, $this->written],
        );
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §4.1.2 and §4.2
     */
    #[Test]
    public function aWriteOnTheGroupRaisesItAndRecordsTheRaiseOfEachPersonInOneUnit(): void
    {
        // Given
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $carol = User::create(
            Uuid::fromString('01890000-0000-7000-8000-000000000001'),
            $this->alice->tenant,
            new Subject('carol-subject'),
            'carol',
            Fixtures::now(),
        );

        // When
        $this->membershipWrites()->onTheGroup(
            $this->staff,
            [$this->membership($bob, $this->staff)],
            [$this->membership($carol, $this->staff)],
            Fixtures::now(),
        );

        // Then
        static::assertSame(
            [
                1,
                [
                    ['staff',               true],
                    ['left staff of carol', true],
                    ['joined staff of bob', true],
                    ['raise carol',         true],
                    ['raise bob',           true],
                ],
            ],
            [$this->writes->units, $this->written],
        );
    }

    /**
     * RFC 7644 §3.14
     *
     * @param Closure(MembershipWrites, User, Group): void $write
     */
    #[Test]
    #[DataProvider('provideWritesOfNoMembership')]
    public function aWriteOfNoMembershipWritesNothing(Closure $write): void
    {
        // When
        $write($this->membershipWrites(), $this->alice, $this->staff);

        // Then
        static::assertSame([[], 1, 1], [$this->written, $this->alice->version, $this->staff->version]);
    }

    /**
     * @return iterable<string, array{Closure(MembershipWrites, User, Group): void}>
     */
    public static function provideWritesOfNoMembership(): iterable
    {
        yield 'on the person' => [static fn (MembershipWrites $writes, User $user, Group $group) => $writes->onThePerson($user, [], [], Fixtures::now())];
        yield 'on the group' => [static fn (MembershipWrites $writes, User $user, Group $group) => $writes->onTheGroup($group, [], [], Fixtures::now())];
    }

    private function membershipWrites(): MembershipWrites
    {
        $users = static::createStub(UserRepositoryInterface::class);
        $users->method('save')->willReturnCallback(fn (User $user): null => $this->record($user->username));
        $memberships = static::createStub(GroupMembershipRepositoryInterface::class);
        $memberships->method('save')->willReturnCallback(fn (GroupMembership $joined): null => $this->record('joined ' . self::named($joined)));
        $memberships->method('remove')->willReturnCallback(fn (GroupMembership $left): null => $this->record('left ' . self::named($left)));
        $groups = static::createStub(GroupRepositoryInterface::class);
        $groups->method('save')->willReturnCallback(fn (Group $group): null => $this->record($group->name));
        $versions = static::createStub(VersionRaisesInterface::class);
        $versions->method('raiseThePerson')->willReturnCallback(fn (User $user): null => $this->record('raise ' . $user->username));
        $versions->method('raiseTheGroup')->willReturnCallback(fn (Group $group): null => $this->record('raise ' . $group->name));

        return new MembershipWrites($users, $memberships, $groups, $this->writes, $versions);
    }

    private function record(string $write): null
    {
        $this->written[] = [$write, $this->writes->open];

        return null;
    }

    private static function named(GroupMembership $membership): string
    {
        return $membership->group->name . ' of ' . $membership->user->username;
    }

    private function group(string $name, ?string $id = null): Group
    {
        return new Group($id === null ? Uuid::v7() : Uuid::fromString($id), $this->alice->tenant, $name, GroupSource::Local, Fixtures::now());
    }

    private function membership(User $user, Group $group): GroupMembership
    {
        return new GroupMembership(Uuid::v7(), $group, $user, GroupSource::Local, Fixtures::now());
    }
}
