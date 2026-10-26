<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\IdentityProviderEndpoints;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;

/**
 * The endpoints of the identity provider of a tenant under its issuer, as the bundle locates them from its routes.
 */
final readonly class FixedEndpoints implements IdentityProviderEndpointsInterface
{
    public const string METADATA = '/saml/metadata';

    public const string SINGLE_SIGN_ON = '/saml/sso';

    public const string SINGLE_LOGOUT = '/saml/slo';

    public function locate(Tenant $tenant): IdentityProviderEndpoints
    {
        $issuer = $tenant->issuer->value;

        return new IdentityProviderEndpoints($issuer . self::METADATA, $issuer . self::SINGLE_SIGN_ON, $issuer . self::SINGLE_LOGOUT);
    }
}
