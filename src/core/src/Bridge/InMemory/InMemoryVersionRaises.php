<?php

declare(strict_types=1);

namespace Beffroi\Core\Bridge\InMemory;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\VersionRaisesInterface;
use DateTimeImmutable;

/**
 * Raises at once: the objects are the ones the repositories of this bridge hold, and no unit is ever committed.
 */
final class InMemoryVersionRaises implements VersionRaisesInterface
{
    public function raiseThePerson(User $user, DateTimeImmutable $at): void
    {
        $user->membershipChanged($at);
    }

    public function raiseTheGroup(Group $group, DateTimeImmutable $at): void
    {
        $group->membershipChanged($at);
    }
}
