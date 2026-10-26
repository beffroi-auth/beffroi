<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use function array_map;
use Beffroi\Bundle\Saml\IdentityProviderSegment;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Bridge\Model\UpstreamDecryptionKeys;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Enc\PeerKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * beffroi/saml, spec/saml.md S-64 to S-66, section 6.12: in a deployment whose tenant is a SAML service provider
 * (config_test_service_provider.yml), two upstream identity providers wired, each given its key by the key commands:
 * the metadata at the URL of the entity ID carry no key for encryption, those given to each provider the certificate
 * of its own key and never the other's, and the key the bundle wires opens what was encrypted for that certificate.
 */
final class UpstreamEncryptionMetadataTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    /**
     * The upstream identity provider config_test_service_provider.yml declares, the SimpleSAMLphp one of the judge.
     */
    private const string DECLARED_PROVIDER = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * S-39, S-65: the metadata at the URL of the entity ID carry no key for encryption, whatever keys the providers
     * hold.
     */
    #[Test]
    public function theMetadataOfTheEntityIdCarryNoKeyForEncryption(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::OTHER_PROVIDER);

        // When
        $this->browser->request('GET', ServiceProviderRoutes::METADATA_PATH);

        // Then
        static::assertSame([], $this->servedDescriptor()->serviceProvider?->encryptionCertificates);
    }

    /**
     * The acceptance, S-65: the metadata given to a provider, at the URL the router writes for its entity ID, carry the
     * certificate of its key and not the other provider's.
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function eachProviderIsGivenTheCertificateOfItsOwnKey(string $provider): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        $keys = [
            self::PROVIDER => self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER),
            self::OTHER_PROVIDER => self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::OTHER_PROVIDER),
        ];

        // When
        $this->browser->request('GET', self::metadataOf($provider));

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($keys[$provider])],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->serviceProvider->encryptionCertificates ?? []),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideProviders(): iterable
    {
        yield 'the first' => [self::PROVIDER];
        yield 'the second' => [self::OTHER_PROVIDER];
    }

    /**
     * S-64, S-65: the provider the configuration declares has the algorithm of its key wired by the SAML section, the
     * key commands draw that key, and the metadata given to that provider carry its certificate.
     */
    #[Test]
    public function theProviderTheConfigurationDeclaresIsGivenTheCertificateOfItsKey(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        $key = self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::DECLARED_PROVIDER);

        // When
        $this->browser->request('GET', self::metadataOf(self::DECLARED_PROVIDER));

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($key)],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->serviceProvider->encryptionCertificates ?? []),
        );
    }

    /**
     * Section 6.12 step 5: the metadata given to a provider are served as the metadata of the entity ID are.
     */
    #[Test]
    public function theyAreServedAsSamlMetadataForTheMaxAgeOfTheKeys(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);

        // When
        $this->browser->request('GET', self::metadataOf(self::PROVIDER));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            ['application/samlmetadata+xml', true, '120'],
            [
                $response->headers->get('Content-Type'),
                $response->headers->hasCacheControlDirective('public'),
                $response->headers->getCacheControlDirective('max-age'),
            ],
        );
    }

    /**
     * S-65: a provider nothing wires, a provider the tenant holds no key of, a segment that is not base64url and one
     * whose value is no entity ID are given no metadata.
     */
    #[Test]
    #[DataProvider('provideUrlsOfNoMetadata')]
    public function noMetadataIsGivenWhereNoProviderHoldsAKey(string $url): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);

        // When
        $this->browser->request('GET', $url);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUrlsOfNoMetadata(): iterable
    {
        yield 'a provider nothing wires' => ['/saml/sp/metadata/' . IdentityProviderSegment::of('https://idp-c.example/metadata')];
        yield 'a provider without a key' => ['/saml/sp/metadata/' . IdentityProviderSegment::of(self::OTHER_PROVIDER)];
        yield 'a segment that is not base64url' => ['/saml/sp/metadata/aHR0cHM6Ly9pZHAtYS5leGFtcGxlL21ldGFkYXRh='];
        yield 'a segment that names no entity ID' => ['/saml/sp/metadata/' . IdentityProviderSegment::of('not an entity ID')];
    }

    /**
     * S-64: the key a provider encrypts for is one the tenant keeps, never in its JWK Set.
     */
    #[Test]
    public function theJwkSetDoesNotCarryTheKeyOfAProvider(): void
    {
        // Given
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame([], self::json($this->browser->getResponse())['keys'] ?? null);
    }

    /**
     * S-66: the key the bundle wires for a provider opens an assertion encrypted for the certificate its metadata
     * serve, through the KMS of this kernel.
     */
    #[Test]
    public function theKeyOfAProviderOpensWhatWasEncryptedForTheCertificateServed(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);
        $this->browser->request('GET', self::metadataOf(self::PROVIDER));
        $certificate = $this->servedDescriptor()->serviceProvider->encryptionCertificates[0] ?? static::fail('No certificate was served.');
        $response = ResponseWriterFixtures::response();
        $encrypted = new ResponseWriter()->write(
            $response,
            new Signing(MetadataFixtures::signingKey('idp')),
            SignedParts::AssertionAndResponse,
            new Encryption(PeerKey::fromCertificateBase64($certificate)),
        );

        // When
        $key = self::service('test.beffroi.upstream_decryption_keys', UpstreamDecryptionKeys::class)->of(
            self::tenant(),
            self::PROVIDER,
        ) ?? static::fail('The provider is given no key.');
        $accepted = ResponseWriterFixtures::validator()->validate(
            UnverifiedResponse::of(SamlLoader::create()->load(new Serializer()->serialize($encrypted))),
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($key),
            ResponseWriterFixtures::expected(),
        );

        // Then
        static::assertEquals($response->assertion, $accepted->assertion);
    }

    /**
     * The URL the router writes for the metadata given to that provider.
     */
    private static function metadataOf(string $provider): string
    {
        return self::service('router', UrlGeneratorInterface::class)
            ->generate(ServiceProviderRoutes::METADATA_FOR_IDENTITY_PROVIDER, [
                'identityProvider' => IdentityProviderSegment::of($provider),
            ]);
    }

    /**
     * A key of the tenant, drawn by the command an operator runs and active at once.
     */
    private static function generate(string $algorithm): TenantKey
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => $algorithm,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        foreach (self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findInService(self::tenant()) as $key) {
            if ($key->algorithm->name() === $algorithm) {
                return $key;
            }
        }

        return static::fail('The command drew no key.');
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }
}
