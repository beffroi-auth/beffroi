<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Chain\LoggedCut;
use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use App\Message\ForgetTheActsPastTheirRetention;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Oidc\Application\Disclosure\DisclosureRetention;
use Beffroi\Oidc\Domain\Disclosure\DisclosureChain;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final readonly class ForgetTheActsPastTheirRetentionHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private LoggedCut $cut,
        private JournalRetention $journal,
        private DisclosureRetention $disclosures,
    ) {
    }

    public function __invoke(ForgetTheActsPastTheirRetention $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // Nothing to do before the first provisioning, and a tick is not the place to say so.
            return;
        }
        $this->cut->cut($tenant, new JournalChain(), $this->journal->keptSince());
        $this->cut->cut($tenant, new DisclosureChain(), $this->disclosures->keptSince());
    }
}
