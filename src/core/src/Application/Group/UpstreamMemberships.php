<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Group;

use function array_map;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Psr\Clock\ClockInterface;

/**
 * Synchronous, never queued: a membership taken away must be gone before the session of the sign-in serves
 * anything. Called inside the atomic unit of that sign-in, which makes the removals and additions one write, it
 * announces nothing: its caller announces what it changed once that unit is written.
 */
final readonly class UpstreamMemberships
{
    public function __construct(
        private GroupsOfAPersonInterface $groups,
        private GroupMembershipRepositoryInterface $memberships,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param list<mixed> $asserted
     *
     * @throws InvalidArgumentException when the mapping leads to a group of another tenant than the person's
     */
    public function replace(User $user, array $asserted, GroupMapping $mapping): UpstreamMembershipChange
    {
        $mapped = [];
        foreach ($mapping->groupsOf($asserted) as $group) {
            $mapped[$group->id->toRfc4122()] = $group;
        }

        $held = [];
        $left = [];
        foreach ($this->groups->of($user) as $membership) {
            $group = $membership->group->id->toRfc4122();
            if ($membership->source === GroupSource::UpstreamClaims && ! isset($mapped[$group])) {
                $left[] = $membership;

                continue;
            }
            $held[$group] = true;
        }

        $now = $this->clock->now();
        $joined = [];
        foreach ($mapped as $group => $mappedGroup) {
            if (! isset($held[$group])) {
                $joined[] = new GroupMembership($this->uuids->timeOrdered(), $mappedGroup, $user, GroupSource::UpstreamClaims, $now);
            }
        }

        foreach ($left as $membership) {
            $this->memberships->remove($membership);
        }
        foreach ($joined as $membership) {
            $this->memberships->save($membership);
        }

        return new UpstreamMembershipChange(self::groupsOf($joined), self::groupsOf($left), $now);
    }

    /**
     * @param list<GroupMembership> $memberships
     *
     * @return list<Group>
     */
    private static function groupsOf(array $memberships): array
    {
        return array_map(static fn (GroupMembership $membership): Group => $membership->group, $memberships);
    }
}
