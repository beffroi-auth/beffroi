<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * Carries no secret, no assertion, no token, and nothing of what the request asked for. The journal writes the budget
 * as the reason of the refusal and the route as what it refused, both names this provider gives them (decision 0062).
 */
final class LoadBudgetSpent implements MayConcernAClientInterface, SaysWhyItWasRefusedInterface
{
    public const string NAME = 'load.budget_spent';

    public ?string $clientId {
        get => $this->client;
    }

    /**
     * @param non-empty-string $budget
     * @param string           $route  the name of the route, empty when the request was routed nowhere
     * @param string|null      $client the client the request authenticated as, null for a budget counted on its origin
     */
    public function __construct(
        public readonly DateTimeImmutable $occurredAt,
        public readonly Tenant $tenant,
        public readonly RequestContext $context,
        public readonly string $budget,
        public readonly string $route,
        public readonly ?string $client,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function refusalReason(): string
    {
        return $this->budget;
    }

    public function refusedMethod(): ?string
    {
        return $this->route === '' ? null : $this->route;
    }
}
