<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\RaiseTheVersionOfAPerson;
use Beffroi\Core\Port\UserRepositoryInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Nothing here catches a failure, which the lane retries: a raise made twice is a version a weak tag tolerates, a raise
 * never made a version behind its change (RFC 9110 §8.8.1).
 */
#[AsMessageHandler]
final readonly class RaiseTheVersionOfAPersonHandler
{
    public function __construct(
        private UserRepositoryInterface $users,
    ) {
    }

    public function __invoke(RaiseTheVersionOfAPerson $command): void
    {
        $user = $this->users->find($command->user);
        if ($user === null) {
            return;
        }
        $user->membershipChanged($command->at);
        $this->users->save($user);
    }
}
