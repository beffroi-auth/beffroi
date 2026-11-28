<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Author\AuthorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class SessionTokensRevoked implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'session_tokens.revoked';

    /**
     * @param non-negative-int $refreshTokens the refresh tokens of the client the end of the session revoked
     * @param non-negative-int $accessTokens the opaque access tokens of the client the end of the session removed
     * @param AuthorInterface $author who ended the session
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $subject,
        public Uuid $sessionId,
        public int $refreshTokens,
        public int $accessTokens,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->subject;
    }

    public function author(): AuthorInterface
    {
        return $this->author;
    }
}
