<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Port\AtomicWritesInterface;
use Closure;

/**
 * The writes run as they come and are counted, one unit per call: what the adapters in memory can offer,
 * which hold no transaction to roll back. That the writes of a unit are kept all or none is the store's
 * promise, proved against Doctrine by the suite of the bundle (DoctrineAtomicWritesTest).
 */
final class WritesAsTheyCome implements AtomicWritesInterface
{
    public private(set) int $units = 0;

    /**
     * Whether a unit is running, which a store of the suite reads to say a write was made inside one.
     */
    public private(set) bool $open = false;

    public function atomically(Closure $writes): mixed
    {
        ++$this->units;
        $this->open = true;
        try {
            return $writes();
        } finally {
            $this->open = false;
        }
    }
}
