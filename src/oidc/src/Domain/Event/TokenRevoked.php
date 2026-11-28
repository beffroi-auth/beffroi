<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7009 §2
 */
final readonly class TokenRevoked implements ConcernsAPersonInterface, NamesItsAuthorInterface
{
    public const string NAME = 'token.revoked';

    public const string REFRESH_TOKEN = 'refresh_token';

    public const string ACCESS_TOKEN = 'access_token';

    /**
     * @param string $revokedBy the client that revoked it, by the identifier it was registered under
     * @param string $tokenType "refresh_token" or "access_token"
     * @param list<string> $revokedAccessTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $revokedBy,
        public ?Subject $subject,
        public string $tokenType,
        public string $tokenHash,
        public Uuid $grantId,
        public array $revokedAccessTokenHashes,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): ?Subject
    {
        return $this->subject;
    }

    public function author(): AuthorInterface
    {
        return new AClient($this->revokedBy);
    }
}
