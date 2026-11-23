<?php

declare(strict_types=1);

namespace App\Doctrine\Chain;

use Beffroi\Core\Domain\Identity\ClaimHistoryChain;

final readonly class ClaimHistoryTable implements ChainedTableInterface
{
    public function chain(): string
    {
        return ClaimHistoryChain::NAME;
    }

    public function table(): string
    {
        return 'beffroi_claim_change';
    }

    public function momentColumn(): string
    {
        return 'changed_at';
    }

    public function chainedColumns(): array
    {
        return ['user_id', 'claim', 'was', 'became', 'context', 'author'];
    }
}
