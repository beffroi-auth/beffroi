<?php

declare(strict_types=1);

namespace App\Doctrine;

use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Tenant\TenantFactory;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class TenantSynchronizer
{
    public function __construct(
        private TenantFactory $factory,
        private EntityManagers $managers,
        private BlindIndexDerivations $derivations,
    ) {
    }

    /**
     * @throws TenantNotSynchronizedException when the configuration changed the issuer of a stored tenant
     */
    public function synchronize(): Tenant
    {
        $configured = $this->factory->create();
        $manager = $this->managers->forClass(Tenant::class);
        $tenant = $manager->find(Tenant::class, $configured->id);
        if ($tenant === null) {
            $manager->persist($configured);
            $manager->flush();
            // A tenant created now holds no person, so that none of its tags was derived under another derivation.
            $this->derivations->record($configured, 0, 0);

            return $configured;
        }
        if (! $tenant->issuer->equals($configured->issuer)) {
            throw TenantNotSynchronizedException::issuerChangeRefused($configured->slug, (string) $tenant->issuer, (string) $configured->issuer);
        }
        if ($tenant->name !== $configured->name) {
            $tenant->rename($configured->name);
        }
        if (! $tenant->authenticationContextPolicy->equals($configured->authenticationContextPolicy)) {
            $tenant->adoptAuthenticationContextPolicy($configured->authenticationContextPolicy);
        }
        if (! $tenant->look->equals($configured->look)) {
            $tenant->adoptLook($configured->look);
        }
        if (! $tenant->selfServedClaims->equals($configured->selfServedClaims)) {
            $tenant->adoptSelfServedClaims($configured->selfServedClaims);
        }
        if (! $tenant->passkeyAttestation->equals($configured->passkeyAttestation)) {
            $tenant->adoptPasskeyAttestation($configured->passkeyAttestation);
        }
        $manager->flush();

        return $tenant;
    }
}
