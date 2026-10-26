<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-38: the entity ID of the service provider of a tenant is its own, never the one of its identity
 * provider.
 */
final class ServiceProviderEndpointsTest extends TestCase
{
    /**
     * S-38: the entity ID of the identity provider of the tenant is not the one of its service provider.
     */
    #[Test]
    public function theEntityIdOfTheIdentityProviderIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of the service provider of the tenant, "https://id.acme.example/saml/metadata", is the one of its identity provider: each role is an entity of its own (spec/saml.md S-38).');

        // When
        ServiceProviderEndpoints::assertOwnEntityId('https://id.acme.example/saml/metadata', 'https://id.acme.example/saml/metadata');
    }

    /**
     * S-38, M-8: the two are compared exactly, so an entity ID that differs from the one of the identity provider by
     * a character is the service provider's own.
     */
    #[Test]
    public function anotherEntityIdIsTheServiceProvidersOwn(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        ServiceProviderEndpoints::assertOwnEntityId('https://id.acme.example/saml/metadata/', 'https://id.acme.example/saml/metadata');
    }
}
