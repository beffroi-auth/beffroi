<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2
 *
 * An act of the tenant and of no person: the token names nobody, and the clients it registers are not yet.
 */
final readonly class InitialAccessTokenIssued implements DomainEventInterface
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

    /**
     * What a queue holds, a body written before acts named the kind of their author included, which names its
     * administrator or nobody (decision 0066).
     *
     * @param array<array-key, mixed> $data
     *
     * @throws InvalidArgumentException
     */
    public function __unserialize(array $data): void
    {
        $read = new SerializedProperties($data);
        $context = $read->object('context', RequestContext::class);
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->tenant = $read->object('tenant', Tenant::class);
        $this->tokenId = $read->object('tokenId', Uuid::class);
        $this->context = $context;
        $this->author = $read->author($context, new TheHost());
    }
}
