<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Identity\User;
use DateTimeImmutable;

/**
 * The version of the other side of a membership, raised by an increment of its own once the unit of the write that
 * changed the membership is committed, recorded in that unit and retried until it is made: it rises at least once for
 * each change, its last change with it (RFC 7644 §3.14, RFC 7643 §3.1, RFC 9110 §8.8.1).
 */
interface VersionRaisesInterface
{
    public function raiseThePerson(User $user, DateTimeImmutable $at): void;

    public function raiseTheGroup(Group $group, DateTimeImmutable $at): void;
}
