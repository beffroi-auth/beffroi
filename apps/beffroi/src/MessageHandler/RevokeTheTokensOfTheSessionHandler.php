<?php

declare(strict_types=1);

namespace App\MessageHandler;

use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler(bus: 'event.bus')]
final readonly class RevokeTheTokensOfTheSessionHandler
{
    public function __construct(
        private SessionTokensRevocation $revocation,
    ) {
    }

    public function __invoke(AuthenticationSessionEnded $event): void
    {
        $this->revocation->sessionEnded(
            $event->session->id,
            $event->occurredAt,
            $event->tenant,
            $event->subject(),
            $event->context,
            $event->administrator,
        );
    }
}
