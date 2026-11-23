<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use App\Message\SignTheChains;
use Beffroi\Core\Application\Chain\ChainSignature;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * One chain that does not follow, or cannot be signed, stops no other.
 */
#[AsMessageHandler]
final readonly class SignTheChainsHandler
{
    /**
     * @param iterable<ChainInterface> $chains
     */
    public function __construct(
        private TenantProvider $tenants,
        private iterable $chains,
        private ChainSignature $signature,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(SignTheChains $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // Nothing to do before the first provisioning, and a tick is not the place to say so.
            return;
        }
        foreach ($this->chains as $chain) {
            try {
                $this->signature->sign($tenant, $chain);
            } catch (BrokenChainException|KeyNotFoundException|KmsUnavailableException|RuntimeException $failure) {
                $this->logger->error('The chain "{chain}" of the tenant "{tenant}" was not signed: {reason}', [
                    'chain' => $chain->name(),
                    'tenant' => $tenant->slug,
                    'reason' => ExceptionTrail::of($failure),
                ]);
            }
        }
    }
}
