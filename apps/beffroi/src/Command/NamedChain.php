<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Chain\ChainInterface;
use function array_map;
use function implode;
use function sprintf;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The chains a command names by their name, from the ones the provider wires.
 */
final readonly class NamedChain
{
    /**
     * @param iterable<ChainInterface> $chains
     */
    public function __construct(
        private iterable $chains,
    ) {
    }

    /**
     * @return list<ChainInterface> the one named, every one when none is, nothing when the name is no chain's
     */
    public function orTold(SymfonyStyle $io, ?string $name): array
    {
        $chains = [];
        foreach ($this->chains as $chain) {
            if ($name === null || $chain->name() === $name) {
                $chains[] = $chain;
            }
        }
        if ($chains === []) {
            $io->error(sprintf('"%s" is no chain of this provider, whose chains are %s.', $name, $this->names()));
        }

        return $chains;
    }

    private function names(): string
    {
        $names = [];
        foreach ($this->chains as $chain) {
            $names[] = $chain->name();
        }

        return implode(', ', array_map(static fn (string $name): string => sprintf('"%s"', $name), $names));
    }
}
