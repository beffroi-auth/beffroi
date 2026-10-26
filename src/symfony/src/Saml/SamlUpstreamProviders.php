<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_map;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UpstreamProvidersInterface;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;

/**
 * The upstream providers of a tenant as the core reads them (beffroi/saml S-60): the SAML upstream identity providers
 * the tenant declares, each the upstream provider of the core it is, so that the login page and every login of a local
 * credential read their domains by the one rule of the core. A tenant whose service provider is not enabled declares
 * none, and has none.
 */
final readonly class SamlUpstreamProviders implements UpstreamProvidersInterface
{
    public function __construct(
        private UpstreamIdentityProvidersInterface $identityProviders,
    ) {
    }

    public function of(Tenant $tenant): array
    {
        return array_map(
            static fn (UpstreamIdentityProvider $identityProvider): UpstreamProvider => $identityProvider->provider(),
            $this->identityProviders->of($tenant),
        );
    }
}
