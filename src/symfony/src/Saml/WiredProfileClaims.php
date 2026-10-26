<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Identity\WiredClaims;
use Beffroi\Saml\Port\ProfileClaimsInterface;

/**
 * The claims an attribute of an upstream identity provider fills are the claims a person describes themselves with on
 * the pages of the account (beffroi/saml, spec/saml.md S-45): what is wired, the one source there is, so that a claim
 * the deployment adds is fillable the day its class is wired, and a name no wired claim answers is a mistake of the
 * configuration.
 */
final readonly class WiredProfileClaims implements ProfileClaimsInterface
{
    public function __construct(
        private WiredClaims $claims,
    ) {
    }

    public function names(): array
    {
        return $this->claims->names();
    }
}
