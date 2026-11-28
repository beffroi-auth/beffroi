<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnUnauthenticatedCaller;
use Beffroi\Core\Domain\Author\AClient;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * Carries no secret, no assertion, no token, and nothing of what the request asked for.
 */
final readonly class LoadBudgetSpent implements DomainEventInterface
{
    public const string NAME = 'load.budget_spent';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public string $budget,
        public string $route,
        public ?string $client,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    /**
     * The client the request authenticated as, when it did, or whoever sent it (decision 0066).
     */
    public function author(): AuthorInterface
    {
        return $this->client === null ? new AnUnauthenticatedCaller() : new AClient($this->client);
    }
}
