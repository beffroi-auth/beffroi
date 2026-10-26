<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Configuration;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Domain\ServiceProvider\AttributeMapping;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-5, section 5.2, section 6.2 step 1: the service providers the configuration of the deployment
 * declares, keyed by entity ID, validated when they are built, those of one tenant.
 */
final class ConfigurationServiceProvidersTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    private const string LOCATION = 'https://sp.example.com/saml/metadata';

    /**
     * S-5, section 5.2: a declaration is read whole into its ServiceProvider, its entity ID, its metadata location,
     * the certificates that sign its metadata, its attribute mappings with their name format and friendly name,
     * encryptAssertions and signsAuthnRequests.
     */
    #[Test]
    public function aDeclarationIsReadWhole(): void
    {
        // Given
        $serviceProviders = new ConfigurationServiceProviders(
            'acme',
            [
                self::ENTITY_ID => [
                    'metadata' => self::LOCATION,
                    'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
                    'attributes' => [
                        'urn:oid:0.9.2342.19200300.100.1.3' => [
                            'claim' => 'email',
                            'friendly_name' => 'mail',
                        ],
                        'displayName' => [
                            'claim' => 'name',
                            'name_format' => 'basic',
                        ],
                    ],
                    'encrypt_assertions' => true,
                    'signs_authn_requests' => false,
                ],
            ],
            new FixedClaims(),
        );

        // When
        $serviceProvider = $serviceProviders->find(Fixtures::tenant(), self::ENTITY_ID);

        // Then
        static::assertEquals(
            new ServiceProvider(
                self::ENTITY_ID,
                new MetadataLocation(self::LOCATION),
                [ServiceProviderDocuments::signer()],
                [
                    new AttributeMapping('email', 'urn:oid:0.9.2342.19200300.100.1.3', AttributeNameFormat::Uri, 'mail'),
                    new AttributeMapping('name', 'displayName', AttributeNameFormat::Basic),
                ],
                true,
                false,
            ),
            $serviceProvider,
        );
    }

    /**
     * S-7 and issue #730: what a declaration leaves out is no encryption and requests signed.
     */
    #[Test]
    public function aDeclarationLeftOutTakesTheDefaults(): void
    {
        // Given
        $serviceProviders = new ConfigurationServiceProviders(
            'acme',
            [
                self::ENTITY_ID => [
                    'metadata' => self::LOCATION,
                ],
            ],
            new FixedClaims(),
        );

        // When
        $serviceProvider = $serviceProviders->find(Fixtures::tenant(), self::ENTITY_ID);

        // Then
        static::assertEquals(new ServiceProvider(self::ENTITY_ID, new MetadataLocation(self::LOCATION)), $serviceProvider);
    }

    /**
     * Section 5.2: ServiceProvidersInterface::of() lists the service providers of the tenant in the order of the
     * declaration, the order in which refreshAll() reads them (section 6.2).
     */
    #[Test]
    public function theServiceProvidersAreListedInTheOrderOfTheDeclaration(): void
    {
        // Given
        $serviceProviders = new ConfigurationServiceProviders(
            'acme',
            [
                'https://b.example.com/saml' => [
                    'metadata' => self::LOCATION,
                ],
                'https://a.example.com/saml' => [
                    'metadata' => self::LOCATION,
                ],
            ],
            new FixedClaims(),
        );

        // When
        $listed = $serviceProviders->of(Fixtures::tenant());

        // Then
        static::assertSame(['https://b.example.com/saml', 'https://a.example.com/saml'], [$listed[0]->entityId, $listed[1]->entityId]);
        static::assertCount(2, $listed);
    }

    /**
     * Section 5.2: the declarations are those of one tenant, named by its slug, so another tenant lists none.
     */
    #[Test]
    public function anotherTenantListsNone(): void
    {
        // Given
        $serviceProviders = new ConfigurationServiceProviders(
            'acme',
            [
                self::ENTITY_ID => [
                    'metadata' => self::LOCATION,
                ],
            ],
            new FixedClaims(),
        );

        // When / Then
        static::assertSame([], $serviceProviders->of(Fixtures::tenant('other')));
    }

    /**
     * Section 5.2: the declarations are those of one tenant, named by its slug, so another tenant finds none of them,
     * even by an entity ID declared for the first.
     */
    #[Test]
    public function anotherTenantFindsNone(): void
    {
        // Given
        $serviceProviders = new ConfigurationServiceProviders(
            'acme',
            [
                self::ENTITY_ID => [
                    'metadata' => self::LOCATION,
                ],
            ],
            new FixedClaims(),
        );

        // When / Then
        static::assertNull($serviceProviders->find(Fixtures::tenant('other'), self::ENTITY_ID));
    }

    /**
     * S-5, section 5.2: a service provider is the one the configuration declares, found by its entity ID compared
     * exactly, so an entity ID that differs by a character finds none.
     */
    #[Test]
    public function anEntityIdNobodyDeclaredIsFoundNowhere(): void
    {
        // Given
        $serviceProviders = new ConfigurationServiceProviders(
            'acme',
            [
                self::ENTITY_ID => [
                    'metadata' => self::LOCATION,
                ],
            ],
            new FixedClaims(),
        );

        // When / Then
        static::assertNull($serviceProviders->find(Fixtures::tenant(), self::ENTITY_ID . '/'));
    }

    /**
     * Section 6.2 step 1: a declaration that does not hold together fails where it is built, naming its service
     * provider.
     *
     * @param array<array-key, mixed> $definition
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatAreNotOne')]
    public function aDeclarationThatIsNotOneFailsAtBoot(mixed $definition, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The service provider "https://sp.example.com/saml": ' . $message);

        // When
        new ConfigurationServiceProviders(
            'acme',
            [
                self::ENTITY_ID => $definition,
            ],
            new FixedClaims(),
        );
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideDeclarationsThatAreNotOne(): iterable
    {
        yield 'not a map' => ['https://sp.example.com/saml/metadata', 'a declaration is a map (spec/saml.md section 5.2).'];
        yield 'no metadata' => [[], '"metadata" is a string.'];
        yield 'a plain http location' => [
            ['metadata' => 'http://sp.example.com/saml/metadata'],
            'The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).',
        ];
        yield 'a signer that is not a string' => [['metadata' => self::LOCATION, 'metadata_signers' => [1]], '"metadata_signers" is a string.'];
        yield 'a signer that is not base64' => [
            ['metadata' => self::LOCATION, 'metadata_signers' => ['not base64']],
            'A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).',
        ];
        yield 'signers that are not a list' => [['metadata' => self::LOCATION, 'metadata_signers' => 'MIIBAA=='], '"metadata_signers" is a map.'];
        yield 'attributes that are not a map' => [['metadata' => self::LOCATION, 'attributes' => 'email'], '"attributes" is a map.'];
        yield 'an attribute that is not a map' => [
            ['metadata' => self::LOCATION, 'attributes' => ['mail' => 'email']],
            'an attribute is a map (spec/saml.md section 5.2).',
        ];
        yield 'an attribute without a claim' => [['metadata' => self::LOCATION, 'attributes' => ['urn:oid:2.5.4.3' => []]], '"claim" is a string.'];
        yield 'an unknown name format' => [
            ['metadata' => self::LOCATION, 'attributes' => ['mail' => ['claim' => 'email', 'name_format' => 'x500']]],
            '"x500" is not a name format of Core section 8.2: uri, basic or unspecified.',
        ];
        yield 'a name format that is not a string' => [
            ['metadata' => self::LOCATION, 'attributes' => ['mail' => ['claim' => 'email', 'name_format' => true]]],
            '"name_format" is a string.',
        ];
        yield 'a friendly name that is not a string' => [
            ['metadata' => self::LOCATION, 'attributes' => ['urn:oid:2.5.4.3' => ['claim' => 'name', 'friendly_name' => 1]]],
            '"friendly_name" is a string.',
        ];
        yield 'a claim the provider does not serve (S-16)' => [
            ['metadata' => self::LOCATION, 'attributes' => ['urn:oid:2.5.4.10' => ['claim' => 'organization']]],
            'the attribute "urn:oid:2.5.4.10" maps the claim "organization", which this provider does not serve (spec/saml.md S-16).',
        ];
        yield 'an encryption that is not a boolean' => [['metadata' => self::LOCATION, 'encrypt_assertions' => 'yes'], '"encrypt_assertions" is a boolean.'];
        yield 'a signing of requests that is not a boolean' => [
            ['metadata' => self::LOCATION, 'signs_authn_requests' => 1],
            '"signs_authn_requests" is a boolean.',
        ];
    }
}
