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
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\ModelMetadataWriter;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.1, S-2, S-4: the metadata of the identity provider of a tenant, written by saml2-model's
 * MetadataWriter and read back by its MetadataReader.
 */
final class IdentityProviderMetadataHandlerTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', self::ISSUER);
        $this->keys = new InMemoryTenantKeyRepository();
    }

    /**
     * Section 6.1 steps 3 to 5, S-4: the entity ID is the URL of the metadata, each service is listed with
     * HTTP-Redirect then HTTP-POST at its URL under the issuer, the certificate of the key is a signing one, the one
     * NameID format is the persistent one of S-13, and WantAuthnRequestsSigned is true when the tenant says nothing.
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
        $entityId = self::ISSUER . FixedEndpoints::METADATA;
        static::assertEquals(new EntityDescriptor($entityId, null, new IdentityProvider(
            $entityId,
            [$this->certificateOf($key)],
            [],
            [
                new Endpoint(Binding::HttpRedirect, self::ISSUER . FixedEndpoints::SINGLE_SIGN_ON),
                new Endpoint(Binding::HttpPost, self::ISSUER . FixedEndpoints::SINGLE_SIGN_ON),
            ],
            [
                new Endpoint(Binding::HttpRedirect, self::ISSUER . FixedEndpoints::SINGLE_LOGOUT),
                new Endpoint(Binding::HttpPost, self::ISSUER . FixedEndpoints::SINGLE_LOGOUT),
            ],
            [NameIdFormat::Persistent],
            wantAuthnRequestsSigned: true,
        )), self::read($metadata->document));
    }

    /**
     * S-4, model.md section 6.9: a tenant that turns WantAuthnRequestsSigned off says so in its metadata.
     */
    #[Test]
    public function itSaysWhatTheTenantSetOfSignedRequests(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $metadata = $this->handler(wantAuthnRequestsSigned: false)->handle($this->tenant);

        // Then
        static::assertFalse(self::read($metadata->document)->identityProvider?->wantAuthnRequestsSigned);
    }

    /**
     * S-2: during a rotation, the certificate of the staged key is published beside the active one's before the
     * staged key signs anything.
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
            self::read($metadata->document)->identityProvider?->signingCertificates,
        );
    }

    /**
     * Section 6.1 step 1: a tenant that holds no SAML key in service has no metadata.
     */
    #[Test]
    public function aTenantWithoutASamlKeyHasNoMetadata(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no SAML signing key: its identity provider has no metadata to publish (spec/saml.md section 6.1 step 1).');

        // When
        $this->handler()->handle($this->tenant);
    }

    /**
     * Section 6.1 step 6, S-2: the metadata may be cached for the max-age of the keys of the tenant and no longer.
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
     * Section 6.1 step 6: a lifetime that is not a number of seconds is refused when the handler is built, so that a
     * deployment learns it at boot.
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
     * S-12, section 6.1 step 5: unless the deployment says otherwise, a service provider may keep the metadata a day,
     * written on the md:EntityDescriptor as the xs:duration of its seconds.
     */
    #[Test]
    public function aServiceProviderMayKeepItADayByDefault(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $handler = new IdentityProviderMetadataHandler(
            new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new FixedEndpoints(),
            new ModelMetadataWriter(),
        );

        // When
        $metadata = $handler->handle($this->tenant);

        // Then
        static::assertSame('PT86400S', self::cacheDurationOf($metadata->document));
    }

    /**
     * S-12: the shortest cacheDuration a deployment may set is one second, under a staging delay one second longer.
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
     * S-12: a cacheDuration under one second, or one a service provider would still be inside when the next key signs,
     * is refused when the handler is built, so that a deployment learns it at boot.
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
        bool $wantAuthnRequestsSigned = true,
        int $maxAge = IdentityProviderMetadataHandler::DEFAULT_MAX_AGE,
        int $cacheDuration = IdentityProviderMetadataHandler::DEFAULT_CACHE_DURATION,
        int $stagingDelay = SamlSigningAlgorithmInterface::STAGING_DELAY,
    ): IdentityProviderMetadataHandler {
        return new IdentityProviderMetadataHandler(
            new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new FixedEndpoints(),
            new ModelMetadataWriter(),
            $wantAuthnRequestsSigned,
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
