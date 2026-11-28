<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\EndSession\LogoutChannelInterface;
use App\Message\SendLogoutToken;
use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\MessageBusInterface;

#[AsMessageHandler(bus: 'event.bus')]
final readonly class QueueLogoutTokenHandler implements LogoutChannelInterface
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function channel(): LogoutChannel
    {
        return LogoutChannel::BackChannel;
    }

    public function __invoke(LogoutTokenIssued $event): void
    {
        $this->commandBus->dispatch(new SendLogoutToken(
            $event->tenant,
            $event->clientId,
            $event->logoutUri->value,
            $event->token,
            $event->sessionId,
            $event->subject,
            $event->context,
            $event->author,
        ));
    }
}
