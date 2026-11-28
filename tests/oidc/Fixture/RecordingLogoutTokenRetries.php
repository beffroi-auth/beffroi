<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\LogoutTokenRetriesInterface;

final class RecordingLogoutTokenRetries implements LogoutTokenRetriesInterface
{
    /**
     * @var list<array{clientId: string, session: AuthenticationSession, context: RequestContext, author: AuthorInterface}>
     */
    public private(set) array $later = [];

    public function issueLater(Client $client, AuthenticationSession $session, RequestContext $context, AuthorInterface $author): void
    {
        $this->later[] = [
            'clientId' => $client->registration->clientId,
            'session' => $session,
            'context' => $context,
            'author' => $author,
        ];
    }
}
