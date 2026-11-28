<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
use Beffroi\Core\Domain\Author\AuthorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class RegisteredClientDeleted implements ConcernsAClientInterface
{
    public const string NAME = 'registered_client.deleted';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
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
        $clientId = $read->string('clientId');
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->tenant = $read->object('tenant', Tenant::class);
        $this->clientId = $clientId;
        $this->context = $context;
        $this->author = $read->author($context, new AClient($clientId));
    }
}
