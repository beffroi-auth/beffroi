<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

final readonly class UpstreamMembershipRemoved implements ConcernsAPersonInterface
{
    public const string NAME = 'upstream_membership.removed';

    /**
     * @param string $group    the name of the group, which names an organisational unit and not a person
     * @param string $provider the upstream provider whose assertion no longer maps to the group, by the identifier the deployment declares it under
     */
    public function __construct(
        public Tenant $tenant,
        public Subject $person,
        public string $group,
        public string $provider,
        public DateTimeImmutable $occurredAt,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->person;
    }
}
