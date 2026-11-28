<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\RevokeTheTokensOfTheSession;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * Sent at once, and not after the end is handled: a message held for later is one a failing handler of the end drops,
 * which has the retry run every handler again and write the end a second time. A retry that runs this one again sends
 * the command again, which announces nothing the second time.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class QueueTheRevocationOfTheSessionTokensHandler
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function __invoke(AuthenticationSessionEnded $event): void
    {
        $this->commandBus->dispatch(new RevokeTheTokensOfTheSession(
            $event->tenant,
            $event->session->id,
            $event->occurredAt,
            $event->subject(),
            $event->context,
            $event->author(),
        ));
    }
}
