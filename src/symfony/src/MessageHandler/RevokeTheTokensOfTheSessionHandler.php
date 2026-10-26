<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The tokens issued under a session revoked on the event of the core that says it ended, beside the
 * back-channel logout, so that the end session endpoint, the page of the account, the console, a service
 * provider of SAML and a sign-in that replaced the session all lead here (architecture §4.9, issue #741).
 *
 * On the lane the events travel and never on the path of the request: the session the terminator wrote
 * as ended is what refuses a token presented in the meantime, so the protocol needs nothing of this write
 * before it answers (architecture §5.6, SessionTokensRevocation).
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class RevokeTheTokensOfTheSessionHandler
{
    public function __construct(
        private SessionTokensRevocation $revocation,
    ) {
    }

    public function __invoke(AuthenticationSessionEnded $event): void
    {
        $this->revocation->sessionEnded($event->session->id, $event->occurredAt);
    }
}
