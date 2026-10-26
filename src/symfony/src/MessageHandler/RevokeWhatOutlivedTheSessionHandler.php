<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Beffroi\Oidc\Domain\Event\RefreshTokenOutlivedItsSession;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The tokens a session still holds once it has ended revoked again, when the token endpoint refuses one of
 * them: a refresh in flight when the session ended saved its successor after RevokeTheTokensOfTheSessionHandler
 * ran (architecture §4.9, issue #741). Dated by the end of the session, as that first revocation was.
 *
 * On the lane the events travel, as that first revocation is: the token endpoint refuses the token by its
 * session and needs nothing of this write before it answers (architecture §5.6).
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
        $this->revocation->sessionEnded($event->sessionId, $event->sessionEndedAt);
    }
}
