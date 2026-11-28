<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * Never carries the value the provider asserted, only the group of the tenant its declaration maps it to.
 */
final readonly class UpstreamMembershipGranted implements ConcernsAPersonInterface
{
    public const string NAME = 'upstream_membership.granted';

    /**
     * @param string $group    the name of the group when it happened, which names an organisational unit and not a person; a rename leaves the identifier
     * @param string $provider the upstream provider by the identifier the deployment declares it under
     */
    public function __construct(
        public Tenant $tenant,
        public Subject $person,
        public Uuid $groupId,
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
