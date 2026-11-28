<?php

declare(strict_types=1);

namespace App\MessageHandler;

use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Beffroi\Oidc\Domain\Event\RefreshTokenOutlivedItsSession;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * A refresh in flight when the session ended may save its successor after RevokeTheTokensOfTheSessionHandler ran, and a
 * refresh may present a token of the session before that handler has run.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class RevokeWhatOutlivedTheSessionHandler
{
    public function __construct(
        private SessionTokensRevocation $revocation,
    ) {
    }

    public function __invoke(RefreshTokenOutlivedItsSession $event): void
    {
        $this->revocation->outlived($event->sessionId, $event->sessionEndedAt);
    }
}
