<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Port\RotationSchedulesInterface;

/**
 * The schedules of the families of keys under test: one for every algorithm, and another for the algorithms
 * a test names, so that a key of another family waits and ages by figures of its own.
 */
final readonly class FixedRotationSchedules implements RotationSchedulesInterface
{
    /**
     * @param array<string, RotationSchedule> $byAlgorithm the schedule of the algorithms of that name
     */
    public function __construct(
        private RotationSchedule $schedule,
        private array $byAlgorithm = [],
    ) {
    }

    public function of(KeyAlgorithmInterface $algorithm): RotationSchedule
    {
        return $this->byAlgorithm[$algorithm->name()] ?? $this->schedule;
    }
}
