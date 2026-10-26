<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataWriter;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Tests\Fixture\FixedServiceProviderEndpoints;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.9, S-38 to S-40: the metadata of the service provider of a tenant, written by saml2-model's
 * MetadataWriter and read back by its MetadataReader.
 */
final class ServiceProviderMetadataHandlerTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', self::ISSUER);
        $this->keys = new InMemoryTenantKeyRepository();
    }

    /**
     * S-39, section 6.9 steps 3 and 4: the entity ID is the URL of the metadata, the one assertion consumer service is
     * on HTTP-POST at its URL under the issuer, of index 0, the certificate of the key is a signing one, the requests
     * are said signed and the assertions wanted signed; no single logout service, no key for encryption and no NameID
     * format.
     */
    #[Test]
    public function itIsReadBackByTheMetadataReaderOfTheModel(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);

        // When
        $metadata = $this->handler()->handle($this->tenant);

        // Then
        $entityId = self::ISSUER . FixedServiceProviderEndpoints::METADATA;
        static::assertEquals(new EntityDescriptor($entityId, null, null, new ServiceProvider(
            $entityId,
            [$this->certificateOf($key)],
            [],
            new IndexedEndpoints([
                new IndexedEndpoint(Binding::HttpPost, self::ISSUER . FixedServiceProviderEndpoints::ASSERTION_CONSUMER_SERVICE, 0),
            ]),
            [],
            [],
            authnRequestsSigned: true,
            wantAssertionsSigned: true,
        )), self::read($metadata->document));
    }

    /**
     * S-38: the entity ID the deployment names is the one the metadata carry, in place of the URL of the metadata.
     */
    #[Test]
    public function itCarriesTheEntityIdTheDeploymentNames(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $handler = $this->handler(new FixedServiceProviderEndpoints('urn:acme:service-provider'));

        // When
        $metadata = $handler->handle($this->tenant);

        // Then
        $descriptor = self::read($metadata->document);
        static::assertSame(
            ['urn:acme:service-provider', 'urn:acme:service-provider'],
            [$descriptor->entityId, $descriptor->serviceProvider?->entityId],
        );
    }

    /**
     * S-2, S-40: during a rotation, the certificate of the staged key is published beside the active one's before the
     * staged key signs a request.
     */
    #[Test]
    public function itPublishesTheNextCertificateBesideTheCurrentOne(): void
    {
        // Given
        $active = SamlKeys::activeKey($this->tenant);
        $staged = SamlKeys::key($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $this->keys->save($active);
        $this->keys->save($staged);

        // When
        $metadata = $this->handler()->handle($this->tenant);

        // Then
        static::assertSame(
            [$this->certificateOf($active), $this->certificateOf($staged)],
            self::read($metadata->document)->serviceProvider?->signingCertificates,
        );
    }

    /**
     * S-65, section 6.12: the metadata given to an upstream identity provider are those of S-39 with the certificate
     * of its key as a key for encryption.
     */
    #[Test]
    public function aProviderIsGivenTheCertificateOfItsKey(): void
    {
        // Given
        $signing = SamlKeys::activeKey($this->tenant);
        $encryption = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $this->keys->save($signing);
        $this->keys->save($encryption);

        // When
        $metadata = $this->handler()->handleFor($this->tenant, self::PROVIDER);

        // Then
        $entityId = self::ISSUER . FixedServiceProviderEndpoints::METADATA;
        static::assertEquals(new EntityDescriptor($entityId, null, null, new ServiceProvider(
            $entityId,
            [$this->certificateOf($signing)],
            [$this->certificateOf($encryption)],
            new IndexedEndpoints([
                new IndexedEndpoint(Binding::HttpPost, self::ISSUER . FixedServiceProviderEndpoints::ASSERTION_CONSUMER_SERVICE, 0),
            ]),
            [],
            [],
            authnRequestsSigned: true,
            wantAssertionsSigned: true,
        )), self::read($metadata->document));
    }

    /**
     * S-65: the metadata given to a provider never carry the certificate of the key of another.
     */
    #[Test]
    public function aProviderIsNeverGivenTheCertificateOfAnother(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $other = SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1);
        $this->keys->save($other);

        // When
        $metadata = $this->handler()->handleFor($this->tenant, self::OTHER_PROVIDER);

        // Then
        static::assertSame([$this->certificateOf($other)], self::read($metadata->document)->serviceProvider?->encryptionCertificates);
    }

    /**
     * S-65: during a rotation, the certificate of the next key comes first, the one a provider takes from its staging.
     */
    #[Test]
    public function theNextCertificateOfAProviderComesFirst(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $current = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $current->activate(Fixtures::now());
        $next = SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 1, Fixtures::now()->modify('+1 day'));
        $this->keys->save($current);
        $this->keys->save($next);

        // When
        $metadata = $this->handler()->handleFor($this->tenant, self::PROVIDER);

        // Then
        static::assertSame(
            [$this->certificateOf($next), $this->certificateOf($current)],
            self::read($metadata->document)->serviceProvider?->encryptionCertificates,
        );
    }

    /**
     * S-39, S-65: the metadata at the URL of the entity ID carry no key for encryption, whatever keys the providers
     * hold.
     */
    #[Test]
    public function theMetadataOfTheEntityIdCarryNoKeyForEncryption(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));

        // When
        $metadata = $this->handler()->handle($this->tenant);

        // Then
        static::assertSame([], self::read($metadata->document)->serviceProvider?->encryptionCertificates);
    }

    /**
     * Section 6.12 step 1: a provider for which the tenant holds no key in service is given no metadata.
     */
    #[Test]
    public function aProviderWithoutAKeyIsGivenNoMetadata(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER));

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no key the identity provider "https://idp-a.example/metadata" encrypts for: its service provider has no metadata to give it (spec/saml.md section 6.12 step 1).');

        // When
        $this->handler()->handleFor($this->tenant, self::PROVIDER);
    }

    /**
     * Section 6.12 step 3: a provider is given no metadata while the tenant holds no SAML signing key in service.
     */
    #[Test]
    public function aProviderIsGivenNoMetadataWithoutASigningKey(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no SAML signing key: its service provider has no metadata to publish (spec/saml.md section 6.9 step 1).');

        // When
        $this->handler()->handleFor($this->tenant, self::PROVIDER);
    }

    /**
     * Section 6.9 step 1: a tenant that holds no SAML key in service has no metadata of its service provider.
     */
    #[Test]
    public function aTenantWithoutASamlKeyHasNoMetadata(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no SAML signing key: its service provider has no metadata to publish (spec/saml.md section 6.9 step 1).');

        // When
        $this->handler()->handle($this->tenant);
    }

    /**
     * Section 6.9 step 5, S-40: the metadata may be cached for the max-age of the keys of the tenant and no longer.
     */
    #[Test]
    public function itIsCachedForTheMaxAgeOfTheKeys(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $metadata = $this->handler(maxAge: 120)->handle($this->tenant);

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'public, max-age=120',
            ],
            $metadata->headers,
        );
    }

    /**
     * Section 6.9 step 5: a lifetime that is not a number of seconds is refused when the handler is built.
     */
    #[Test]
    public function itRefusesALifetimeThatIsNotANumberOfSeconds(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The cache lifetime of the metadata is a number of seconds (spec/saml.md section 6.1 step 6).');

        // When
        $this->handler(maxAge: -1);
    }

    /**
     * S-12, S-40: unless the deployment says otherwise, an upstream identity provider may keep the metadata a day, as
     * a service provider keeps the metadata of the identity provider, written on the md:EntityDescriptor.
     */
    #[Test]
    public function anUpstreamIdentityProviderMayKeepItADayByDefault(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $handler = new ServiceProviderMetadataHandler(
            new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new EncryptionCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new FixedServiceProviderEndpoints(),
            new ModelServiceProviderMetadataWriter(),
        );

        // When
        $metadata = $handler->handle($this->tenant);

        // Then
        static::assertSame('PT86400S', self::cacheDurationOf($metadata->document));
    }

    /**
     * S-12, S-40: the shortest cacheDuration a deployment may set is one second, under a staging delay one second
     * longer.
     */
    #[Test]
    public function aCacheDurationOneSecondShortOfTheStagingDelayIsWritten(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $metadata = $this->handler(cacheDuration: 1, stagingDelay: 2)->handle($this->tenant);

        // Then
        static::assertSame('PT1S', self::cacheDurationOf($metadata->document));
    }

    /**
     * S-12, S-40: a cacheDuration under one second, or one an upstream identity provider would still be inside when
     * the next key signs, is refused when the handler is built.
     */
    #[Test]
    #[DataProvider('provideCacheDurationsRefused')]
    public function itRefusesACacheDurationTheStagingDelayDoesNotOutlast(int $cacheDuration, int $stagingDelay, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->handler(cacheDuration: $cacheDuration, stagingDelay: $stagingDelay);
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function provideCacheDurationsRefused(): iterable
    {
        yield 'no second' => [0, 10, 'The cacheDuration of the metadata is a number of seconds, one at least (spec/saml.md S-12).'];
        yield 'as long as the staging delay' => [
            604_800,
            604_800,
            'The cacheDuration of the metadata, 604800 s, is shorter than the staging delay of a SAML key, 604800 s, or a service provider that honours it meets the next key before its certificate (spec/saml.md S-12).',
        ];
    }

    private function handler(
        FixedServiceProviderEndpoints $endpoints = new FixedServiceProviderEndpoints(),
        int $maxAge = IdentityProviderMetadataHandler::DEFAULT_MAX_AGE,
        int $cacheDuration = IdentityProviderMetadataHandler::DEFAULT_CACHE_DURATION,
        int $stagingDelay = SamlSigningAlgorithmInterface::STAGING_DELAY,
    ): ServiceProviderMetadataHandler {
        return new ServiceProviderMetadataHandler(
            new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new EncryptionCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            $endpoints,
            new ModelServiceProviderMetadataWriter(),
            $maxAge,
            $cacheDuration,
            $stagingDelay,
        );
    }

    private static function cacheDurationOf(string $document): string
    {
        return SamlLoader::create()->load($document)->root()->getAttribute('cacheDuration') ?? '';
    }

    private function certificateOf(TenantKey $key): string
    {
        return new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($key))->base64;
    }

    private static function read(string $document): EntityDescriptor
    {
        return new MetadataReader(SamlLoader::create(), new MockClock(Fixtures::now()))->readTrusted(SamlLoader::create()->load($document));
    }
}
