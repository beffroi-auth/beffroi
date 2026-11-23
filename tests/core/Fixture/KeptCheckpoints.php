<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_key_last;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Chain\Checkpoint;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\CheckpointCopiesInterface;
use Beffroi\Core\Port\SignedCheckpointsInterface;

/**
 * The signatures of one chain kept beside the keys, and the copies that left the instance.
 */
final class KeptCheckpoints implements SignedCheckpointsInterface, CheckpointCopiesInterface
{
    /**
     * @var list<non-empty-string> every one kept, the last one last
     */
    public private(set) array $kept = [];

    /**
     * @var list<Checkpoint>
     */
    public private(set) array $copies = [];

    public function last(Tenant $tenant, ChainInterface $chain): ?string
    {
        $last = array_key_last($this->kept);

        return $last === null ? null : $this->kept[$last];
    }

    public function keep(Tenant $tenant, ChainInterface $chain, string $compactJws): void
    {
        if ($compactJws !== '') {
            $this->kept[] = $compactJws;
        }
    }

    public function copy(Tenant $tenant, Checkpoint $checkpoint, string $compactJws): void
    {
        $this->copies[] = $checkpoint;
    }

    /**
     * @param non-empty-string $compactJws
     */
    public function putBack(string $compactJws): void
    {
        $this->kept[] = $compactJws;
    }
}
