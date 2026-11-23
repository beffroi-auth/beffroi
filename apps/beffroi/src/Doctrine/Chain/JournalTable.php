<?php

declare(strict_types=1);

namespace App\Doctrine\Chain;

use Beffroi\Core\Domain\Journal\JournalChain;

final readonly class JournalTable implements ChainedTableInterface
{
    public function chain(): string
    {
        return JournalChain::NAME;
    }

    public function table(): string
    {
        return 'beffroi_journal';
    }

    public function momentColumn(): string
    {
        return 'occurred_at';
    }

    public function chainedColumns(): array
    {
        return ['act', 'subject', 'client', 'author', 'context'];
    }
}
