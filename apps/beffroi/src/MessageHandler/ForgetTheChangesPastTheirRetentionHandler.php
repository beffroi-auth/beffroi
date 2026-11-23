<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Chain\LoggedCut;
use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use App\Message\ForgetTheChangesPastTheirRetention;
use Beffroi\Core\Application\Identity\ClaimHistoryRetention;
use Beffroi\Core\Domain\Identity\ClaimHistoryChain;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final readonly class ForgetTheChangesPastTheirRetentionHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private LoggedCut $cut,
        private ClaimHistoryRetention $retention,
    ) {
    }

    public function __invoke(ForgetTheChangesPastTheirRetention $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // Nothing to do before the first provisioning, and a tick is not the place to say so.
            return;
        }
        $this->cut->cut($tenant, new ClaimHistoryChain(), $this->retention->keptSince());
    }
}
