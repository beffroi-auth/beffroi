<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Upstream\UpstreamIdentityProviderRole;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Bridge\Model\ModelUpstreamMetadataReader;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Tests\Fixture\FixedProfileClaims;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.10: the role of the upstream identity providers reads the metadata of an upstream identity
 * provider and of nothing else.
 */
final class UpstreamIdentityProviderRoleTest extends TestCase
{
    /**
     * Section 6.10: a peer of another role handed to the role of the upstream identity providers is a programming
     * error, refused before anything is read.
     */
    #[Test]
    public function aPeerOfAnotherRoleIsRefused(): void
    {
        // Given
        $role = new UpstreamIdentityProviderRole(
            new ConfigurationUpstreamIdentityProviders('acme', [], new FixedProfileClaims()),
            new ModelUpstreamMetadataReader(new MockClock(Fixtures::now())),
        );
        $serviceProvider = new ServiceProvider(ServiceProviderDocuments::SIMPLESAMLPHP, new MetadataLocation('/srv/saml/sp.xml'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The role of the upstream identity providers reads the metadata of an upstream identity provider (spec/saml.md section 6.10).');

        // When
        $role->read($serviceProvider, ServiceProviderDocuments::simpleSamlPhp());
    }
}
