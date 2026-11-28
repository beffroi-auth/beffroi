<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\RevokeTheTokensOfTheSession;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DispatchAfterCurrentBusStamp;

/**
 * Sent once the end is handled whole: a handler of it that fails drops the command, and the end handled again sends it
 * again, so that it is sent once.
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
        $this->commandBus->dispatch(Envelope::wrap(new RevokeTheTokensOfTheSession(
            $event->tenant,
            $event->session->id,
            $event->occurredAt,
            $event->subject(),
            $event->context,
            $event->administrator,
        ), [new DispatchAfterCurrentBusStamp()]));
    }
}
