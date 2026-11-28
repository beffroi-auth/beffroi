<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\IssueLogoutToken;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Application\EndSession\BackChannelLogout;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * What it issues is handed to the delivery of every logout token, whose retries ask neither the KMS nor the client
 * again.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class IssueLogoutTokenHandler
{
    public function __construct(
        private AuthenticationSessionRepositoryInterface $sessions,
        private ClientRepositoryInterface $clients,
        private BackChannelLogout $logout,
    ) {
    }

    /**
     * @throws ClientKeysUnavailableException when the key of the client still cannot be obtained or receives no JWE, which the lane tries again
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function __invoke(IssueLogoutToken $message): void
    {
        $session = $this->sessions->find($message->sessionId);
        $client = $this->clients->findByClientId($message->tenant, $message->clientId);
        if ($session === null || $client === null) {
            return;
        }
        $this->logout->tell($client, $session, $message->context, $message->author);
    }
}
