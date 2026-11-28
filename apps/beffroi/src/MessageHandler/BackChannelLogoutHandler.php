<?php

declare(strict_types=1);

namespace App\MessageHandler;

use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Oidc\Application\EndSession\BackChannelLogout;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * An expired session is not ended, so it announces nothing (decision 0031).
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class BackChannelLogoutHandler
{
    public function __construct(
        private BackChannelLogout $logout,
    ) {
    }

    public function __invoke(AuthenticationSessionEnded $event): void
    {
        $this->logout->sessionEnded($event->session, $event->context, $event->author);
    }
}
