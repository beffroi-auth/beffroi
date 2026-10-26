<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\PairwiseSaltInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;

/**
 * The secret the persistent identifiers of SAML are computed with is the one the pairwise subjects of OpenID Connect
 * are (beffroi/saml, spec/saml.md S-13): one secret of the tenant for every pseudonym of its users, drawn once, sealed
 * by its KMS and backed up with its keys. The two computations hash different inputs, the entity ID of a service
 * provider in the one and the host of a sector in the other, so that no identifier of one is an identifier of the
 * other.
 */
final readonly class TenantPersistentIdentifierSalt implements PersistentIdentifierSaltInterface
{
    public function __construct(
        private PairwiseSaltInterface $salts,
    ) {
    }

    public function saltOf(Tenant $tenant): string
    {
        return $this->salts->saltOf($tenant);
    }
}
