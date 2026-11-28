<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Doctrine\EntityManagers;
use App\Message\RaiseTheVersionOfAGroup;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Nothing here catches a failure, which the lane retries: a raise made twice is a version a weak tag tolerates, a raise
 * never made a version behind its change (RFC 9110 §8.8.1).
 */
#[AsMessageHandler]
final readonly class RaiseTheVersionOfAGroupHandler
{
    public function __construct(
        private EntityManagers $managers,
        private GroupRepositoryInterface $groups,
    ) {
    }

    public function __invoke(RaiseTheVersionOfAGroup $command): void
    {
        $group = $this->managers->forClass(Group::class)->find(Group::class, $command->group);
        if ($group === null) {
            return;
        }
        $group->membershipChanged($command->at);
        $this->groups->save($group);
    }
}
