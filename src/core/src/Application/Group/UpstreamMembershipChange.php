<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Group;

use Beffroi\Core\Domain\Group\Group;
use DateTimeImmutable;

final readonly class UpstreamMembershipChange
{
    /**
     * @param list<Group> $granted
     * @param list<Group> $removed
     */
    public function __construct(
        public array $granted,
        public array $removed,
        public DateTimeImmutable $replacedAt,
    ) {
    }
}
