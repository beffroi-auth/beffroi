<?php

declare(strict_types=1);

namespace App\EndSession;

use App\Message\IssueLogoutToken;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\LogoutTokenRetriesInterface;
use Symfony\Component\Messenger\MessageBusInterface;

final readonly class QueuedLogoutTokenRetries implements LogoutTokenRetriesInterface
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function issueLater(Client $client, AuthenticationSession $session, RequestContext $context, AuthorInterface $author): void
    {
        $this->commandBus->dispatch(new IssueLogoutToken(
            $session->tenant,
            $client->registration->clientId,
            $session->id,
            $session->user->subject,
            $context,
            $author,
        ));
    }
}
