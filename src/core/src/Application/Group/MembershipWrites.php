<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Group;

use function array_values;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Port\VersionRaisesInterface;
use DateTimeImmutable;
use function usort;

/**
 * Memberships written on one resource, the person or the group, whose version rises with them in one unit; the raise
 * of each resource on the other side is recorded in that unit and made once it is committed (RFC 7644 §3.14, RFC 7643
 * §4.1.2 and §4.2). No unit holds a person and a group at once, so two of them never wait on each other; the raises are
 * recorded in the order of the identifiers, so that a kernel that makes them at once, as the suites do, takes their rows
 * in one order.
 */
final readonly class MembershipWrites
{
    public function __construct(
        private UserRepositoryInterface $users,
        private GroupMembershipRepositoryInterface $memberships,
        private GroupRepositoryInterface $groups,
        private AtomicWritesInterface $writes,
        private VersionRaisesInterface $versions,
    ) {
    }

    /**
     * @param list<GroupMembership> $joined of the person
     * @param list<GroupMembership> $left   of the person
     *
     * @throws MembershipAlreadyHeldException when a concurrent connection wrote one of the memberships joined
     */
    public function onThePerson(User $user, array $joined, array $left, DateTimeImmutable $now): void
    {
        if ($joined === [] && $left === []) {
            return;
        }
        $this->writes->atomically(function () use ($user, $joined, $left, $now): void {
            $user->membershipChanged($now);
            $this->users->save($user);
            $this->writeTheRows($joined, $left);
            $groups = [];
            foreach ([...$joined, ...$left] as $membership) {
                $groups[$membership->group->id->toRfc4122()] = $membership->group;
            }
            foreach (self::inTheOrderOfTheirIdentifiers($groups) as $group) {
                $this->versions->raiseTheGroup($group, $now);
            }
        });
    }

    /**
     * @param list<GroupMembership> $joined of the group
     * @param list<GroupMembership> $left   of the group
     *
     * @throws MembershipAlreadyHeldException when a concurrent connection wrote one of the memberships joined
     */
    public function onTheGroup(Group $group, array $joined, array $left, DateTimeImmutable $now): void
    {
        if ($joined === [] && $left === []) {
            return;
        }
        $this->writes->atomically(function () use ($group, $joined, $left, $now): void {
            $group->membershipChanged($now);
            $this->groups->save($group);
            $this->writeTheRows($joined, $left);
            $persons = [];
            foreach ([...$joined, ...$left] as $membership) {
                $persons[$membership->user->id->toRfc4122()] = $membership->user;
            }
            foreach (self::inTheOrderOfTheirIdentifiers($persons) as $user) {
                $this->versions->raiseThePerson($user, $now);
            }
        });
    }

    /**
     * @param list<GroupMembership> $joined
     * @param list<GroupMembership> $left
     *
     * @throws MembershipAlreadyHeldException
     */
    private function writeTheRows(array $joined, array $left): void
    {
        foreach ($left as $membership) {
            $this->memberships->remove($membership);
        }
        foreach ($joined as $membership) {
            $this->memberships->save($membership);
        }
    }

    /**
     * @template T of User|Group
     *
     * @param array<string, T> $resources by the identifier they are sorted on
     *
     * @return list<T>
     */
    private static function inTheOrderOfTheirIdentifiers(array $resources): array
    {
        $sorted = array_values($resources);
        usort($sorted, static fn (User|Group $a, User|Group $b): int => $a->id->toRfc4122() <=> $b->id->toRfc4122());

        return $sorted;
    }
}
