<?php

declare(strict_types=1);

namespace App\Messenger;

use App\Message\RaiseTheVersionOfAGroup;
use App\Message\RaiseTheVersionOfAPerson;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\VersionRaisesInterface;
use DateTimeImmutable;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * Queued on a lane of the database, the raise is a row of the transaction of the write that asks for it: it leaves
 * once that write is committed, and never when it rolls back.
 */
final readonly class QueuedVersionRaises implements VersionRaisesInterface
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function raiseThePerson(User $user, DateTimeImmutable $at): void
    {
        $this->commandBus->dispatch(new RaiseTheVersionOfAPerson($user->id, $at));
    }

    public function raiseTheGroup(Group $group, DateTimeImmutable $at): void
    {
        $this->commandBus->dispatch(new RaiseTheVersionOfAGroup($group->id, $at));
    }
}
