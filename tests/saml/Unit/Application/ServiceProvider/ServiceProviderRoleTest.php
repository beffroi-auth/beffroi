<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\ServiceProvider;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderRole;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.2: the role of the service providers reads the metadata of a service provider and of nothing
 * else.
 */
final class ServiceProviderRoleTest extends TestCase
{
    /**
     * Section 6.2: a peer of another role handed to the role of the service providers is a programming error, refused
     * before anything is read.
     */
    #[Test]
    public function aPeerOfAnotherRoleIsRefused(): void
    {
        // Given
        $role = new ServiceProviderRole(
            new ConfigurationServiceProviders('acme', [], new FixedClaims()),
            new ModelServiceProviderMetadataReader(new MockClock(Fixtures::now())),
        );
        $identityProvider = new UpstreamIdentityProvider(
            IdentityProviderDocuments::SIMPLESAMLPHP,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            [new EmailDomain('example.org')],
            'mail',
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The role of the service providers reads the metadata of a service provider (spec/saml.md section 6.2).');

        // When
        $role->read($identityProvider, IdentityProviderDocuments::simpleSamlPhp());
    }
}
