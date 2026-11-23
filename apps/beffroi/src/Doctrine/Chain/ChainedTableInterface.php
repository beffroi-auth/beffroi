<?php

declare(strict_types=1);

namespace App\Doctrine\Chain;

/**
 * The table of a record the provider chains (decision 0060), and the columns a link of its chain is computed from.
 */
interface ChainedTableInterface
{
    /**
     * @return non-empty-string the name of the chain, as ChainInterface::name() gives it
     */
    public function chain(): string;

    public function table(): string;

    /**
     * @return non-empty-string the column of the moment the retention reads
     */
    public function momentColumn(): string;

    /**
     * @return non-empty-list<non-empty-string> besides the identifier, the tenant and the moment, in the order they are hashed
     */
    public function chainedColumns(): array;
}
