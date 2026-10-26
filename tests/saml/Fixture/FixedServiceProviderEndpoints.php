<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;

/**
 * The endpoints of the service provider of a tenant under its issuer, as the bundle locates them from its routes, its
 * entity ID the URL of its metadata unless one is named (spec/saml.md S-38).
 */
final readonly class FixedServiceProviderEndpoints implements ServiceProviderEndpointsInterface
{
    public const string METADATA = '/saml/sp/metadata';

    public const string ASSERTION_CONSUMER_SERVICE = '/saml/sp/acs';

    public function __construct(
        private ?string $entityId = null,
    ) {
    }

    public function locate(Tenant $tenant): ServiceProviderEndpoints
    {
        $issuer = $tenant->issuer->value;

        return new ServiceProviderEndpoints($this->entityId ?? $issuer . self::METADATA, $issuer . self::METADATA, $issuer . self::ASSERTION_CONSUMER_SERVICE);
    }
}
