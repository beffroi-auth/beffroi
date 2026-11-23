<?php

declare(strict_types=1);

namespace App\Chain;

use Beffroi\Core\Domain\Chain\Checkpoint;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\CheckpointCopiesInterface;
use const DATE_ATOM;
use Psr\Log\LoggerInterface;

/**
 * A line of the channel "chain", which production writes out at once, never held back for an error: the log collector
 * of a deployment keeps a copy of each signed head that neither the database nor the key storage holds, and
 * "beffroi:chain:verify --against" compares one with the chain.
 */
final readonly class LoggedCheckpointCopies implements CheckpointCopiesInterface
{
    public function __construct(
        private LoggerInterface $logger,
    ) {
    }

    public function copy(Tenant $tenant, Checkpoint $checkpoint, string $compactJws): void
    {
        $this->logger->notice('The chain "{chain}" of the tenant "{tenant}" is signed up to position {position}.', [
            'tenant' => $tenant->slug,
            'chain' => $checkpoint->chain,
            'position' => $checkpoint->head->position,
            'hash' => $checkpoint->head->hash,
            'kept_after' => $checkpoint->keptAfter->position,
            'signed_at' => $checkpoint->signedAt->format(DATE_ATOM),
            'checkpoint' => $compactJws,
        ]);
    }
}
