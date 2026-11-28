<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\RevokeTheTokensOfTheSession;
use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler(bus: 'command.bus')]
final readonly class RevokeTheTokensOfTheSessionHandler
{
    public function __construct(
        private SessionTokensRevocation $revocation,
    ) {
    }

    public function __invoke(RevokeTheTokensOfTheSession $command): void
    {
        $this->revocation->sessionEnded(
            $command->sessionId,
            $command->endedAt,
            $command->tenant,
            $command->subject,
            $command->context,
            $command->administrator,
        );
    }
}
