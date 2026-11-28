<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2
 *
 * An act of the tenant and of no person: the token names nobody, and the clients it registers are not yet.
 */
final readonly class InitialAccessTokenIssued implements NamesItsAuthorInterface
{
    public const string NAME = 'initial_access_token.issued';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $tokenId,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function author(): AuthorInterface
    {
        return $this->author;
    }
}
