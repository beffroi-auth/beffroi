<?php

declare(strict_types=1);

namespace App\Chain;

use Beffroi\Core\Application\Chain\ChainCut;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use DateTimeImmutable;
use Psr\Log\LoggerInterface;

/**
 * A timed step cuts a chain and says what it did, at error when the chain was not cut: one chain that does not follow
 * stops no other.
 */
final readonly class LoggedCut
{
    public function __construct(
        private ChainCut $cut,
        private LoggerInterface $logger,
    ) {
    }

    public function cut(Tenant $tenant, ChainInterface $chain, DateTimeImmutable $keptSince): void
    {
        try {
            $forgotten = $this->cut->forgetPastTheWindow($tenant, $chain, $keptSince);
        } catch (BrokenChainException|KeyNotFoundException|KmsUnavailableException|RuntimeException $failure) {
            $this->logger->error('Forgot no row of the chain "{chain}" of the tenant "{tenant}": {reason}', [
                'chain' => $chain->name(),
                'tenant' => $tenant->slug,
                'reason' => ExceptionTrail::of($failure),
            ]);

            return;
        }
        if ($forgotten > 0) {
            $this->logger->info('Forgot {count} row(s) of the chain "{chain}" of the tenant "{tenant}", kept past their retention, and signed the cut.', [
                'count' => $forgotten,
                'chain' => $chain->name(),
                'tenant' => $tenant->slug,
            ]);
        }
    }
}
