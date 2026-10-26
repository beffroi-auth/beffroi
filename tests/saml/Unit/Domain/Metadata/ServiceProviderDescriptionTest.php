<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\ServiceProviderDescription;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-38, section 6.9 steps 1 and 3: what the metadata of the service provider of a tenant says.
 */
final class ServiceProviderDescriptionTest extends TestCase
{
    private const string ENTITY_ID = 'urn:acme:service-provider';

    /**
     * S-38: the entity ID of the metadata is the one the endpoints were located with.
     */
    #[Test]
    public function itsEntityIdIsTheOneItWasLocatedWith(): void
    {
        // Given
        $description = new ServiceProviderDescription(self::endpoints(), [new Certificate('MIIBAA==')], 86_400);

        // When / Then
        static::assertSame(self::ENTITY_ID, $description->entityId());
    }

    /**
     * Section 6.9 step 1: metadata announcing signed requests with no key to verify them by is not metadata to
     * publish.
     */
    #[Test]
    public function itRefusesToDescribeAServiceProviderWithoutACertificate(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The metadata of a service provider carries the certificate of a key at least (spec/saml.md section 6.9 step 1).');

        // When
        new ServiceProviderDescription(self::endpoints(), [], 86_400);
    }

    private static function endpoints(): ServiceProviderEndpoints
    {
        return new ServiceProviderEndpoints(self::ENTITY_ID, 'https://id.acme.example/saml/sp/metadata', 'https://id.acme.example/saml/sp/acs');
    }
}
