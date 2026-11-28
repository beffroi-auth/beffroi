<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Identity;

use Beffroi\Core\Domain\Listing\Period;

/**
 * What a history of changes is narrowed to, a criterion left null admitting every change.
 */
final readonly class ClaimChangeQuestion
{
    /**
     * @param string|null $claim the name ClaimChange::$claim holds
     * @param string|null $by the kind of the author of the changes asked, by the name the kind gives itself
     */
    public function __construct(
        public ?Period $period = null,
        public ?string $claim = null,
        public ?string $by = null,
    ) {
    }

    public function admits(ClaimChange $change): bool
    {
        return (
            $this->period?->holds($change->changedAt) !== false
            && ($this->claim === null || $change->claim === $this->claim)
            && ($this->by === null || $change->author->kind() === $this->by)
        );
    }
}
