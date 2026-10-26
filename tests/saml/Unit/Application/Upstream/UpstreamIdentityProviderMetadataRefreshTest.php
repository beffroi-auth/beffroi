<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Upstream;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Metadata\AcceptedMetadataForgetting;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Application\Metadata\MetadataRefreshment;
use Beffroi\Saml\Application\Upstream\UpstreamIdentityProviderRole;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Bridge\Model\ModelUpstreamMetadataReader;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Tests\Fixture\FixedMetadataFetcher;
use Beffroi\Saml\Tests\Fixture\FixedProfileClaims;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function sprintf;

/**
 * spec/saml.md section 6.10, S-42, S-43, S-6: the metadata of an upstream identity provider registered the first time
 * and refreshed every time after, by the procedure the service providers are refreshed with, the declarations of the
 * configuration, the reader of the model and a fetcher of the test, at 2026-09-15T10:00:00Z.
 */
final class UpstreamIdentityProviderMetadataRefreshTest extends TestCase
{
    private const string LOCATION = '/srv/saml/simplesamlphp-idp-metadata.xml';

    private const string SIGNED_LOCATION = 'https://idp.example.org/saml/metadata';

    private Tenant $tenant;

    private MockClock $clock;

    private FixedMetadataFetcher $fetcher;

    private InMemoryAcceptedMetadata $accepted;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->fetcher = new FixedMetadataFetcher();
        $this->accepted = new InMemoryAcceptedMetadata();
    }

    /**
     * The acceptance of issue #779: the SimpleSAMLphp identity provider of the judge is registered from its metadata,
     * the bytes that were read kept in the row of the upstream identity providers (S-8, S-42).
     */
    #[Test]
    public function theIdentityProviderOfTheJudgeIsRegisteredFromItsMetadata(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
        static::assertSame(
            sprintf('The identity provider "%s" is registered from its metadata.', IdentityProviderDocuments::SIMPLESAMLPHP),
            $refreshment->what,
        );
        $accepted = $this->acceptedSimpleSamlPhp();
        static::assertInstanceOf(AcceptedUpstreamMetadata::class, $accepted);
        static::assertSame(IdentityProviderDocuments::simpleSamlPhp(), $accepted->document);
        static::assertNull($accepted->validUntil);
        static::assertEquals(Fixtures::now(), $accepted->acceptedAt);
    }

    /**
     * Section 6.10 step 5, section 6.2 step 6: the same bytes read again write nothing.
     */
    #[Test]
    public function theSameDocumentReadAgainWritesNothing(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp();

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(
            sprintf('The metadata of the identity provider "%s" are the ones accepted already.', IdentityProviderDocuments::SIMPLESAMLPHP),
            $refreshment->what,
        );
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * Section 6.10 step 5: a newer document takes the place of the accepted one.
     */
    #[Test]
    public function aNewerDocumentIsAccepted(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $this->clock->sleep(3600);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(sprintf('The metadata of the identity provider "%s" are refreshed.', IdentityProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $this->acceptedSimpleSamlPhp()->validUntil);
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $this->acceptedSimpleSamlPhp()->acceptedAt);
    }

    /**
     * S-42, S-6, the acceptance of issue #779: an expired document is refused, the accepted one kept.
     */
    #[Test]
    public function anExpiredDocumentIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:00:00Z'));

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            sprintf(
                'The metadata of the identity provider "%s" are refused, the document accepted kept: The metadata is past its validUntil (M-7).',
                IdentityProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $this->acceptedSimpleSamlPhp()->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-42, S-6, the acceptance of issue #779: a document read under the signers the declaration pins that is older
     * than the one accepted is refused, the accepted one kept, an older document signed by the same key verifying as
     * well.
     */
    #[Test]
    public function aSignedDocumentOlderThanTheAcceptedOneIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, IdentityProviderDocuments::signed(new DateTimeImmutable('2026-10-08T00:00:00Z')));
        $this->refreshSigned();
        $this->fetcher->answer(self::SIGNED_LOCATION, IdentityProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));

        // When
        $refreshment = $this->refreshSigned();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            sprintf(
                'The metadata of the identity provider "%s" are refused, the document accepted kept: The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).',
                IdentityProviderDocuments::SIGNED,
            ),
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $this->accepted($this->tenant, IdentityProviderDocuments::SIGNED)->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-42, the acceptance of issue #779: a document without an identity provider role, the metadata of the service
     * provider of a SimpleSAMLphp installation, is refused.
     */
    #[Test]
    public function aDocumentWithoutAnIdentityProviderRoleIsRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => self::declaration(self::LOCATION, 'acme.example'),
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertSame(
            sprintf(
                'The metadata of the identity provider "%s" are refused, the document accepted kept: The metadata hold no identity provider role of SAML 2.0 (spec/saml.md S-42).',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
        static::assertSame(0, $this->accepted->saves);
    }

    /**
     * S-42: the metadata of another entity than the one declared are refused.
     */
    #[Test]
    public function theMetadataOfAnotherEntityAreRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhp());
        $refresh = $this->refresh([
            'https://idp.example.com/saml' => self::declaration(self::LOCATION, 'acme.example'),
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertSame(
            'The metadata of the identity provider "https://idp.example.com/saml" are refused, the document accepted kept: The metadata name another entity than the identity provider declared (spec/saml.md S-42).',
            $refreshment->what,
        );
        static::assertSame(0, $this->accepted->saves);
    }

    /**
     * S-43: an identity provider whose metadata hold no key for signing is refused at its registration.
     */
    #[Test]
    public function anIdentityProviderWithoutAKeyForSigningIsRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).',
            $refreshment->what,
        );
        static::assertSame(0, $this->accepted->saves);
    }

    /**
     * S-42: the accepted document of an upstream identity provider is forgotten by the operator, through the
     * forgetting of its role, and the next refresh registers it as a first one.
     */
    #[Test]
    public function aForgottenIdentityProviderIsRegisteredAgain(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, IdentityProviderDocuments::signed(new DateTimeImmutable('2026-10-08T00:00:00Z')));
        $this->refreshSigned();
        new AcceptedMetadataForgetting($this->accepted, $this->accepted)->forget($this->tenant, IdentityProviderDocuments::SIGNED);
        $this->fetcher->answer(self::SIGNED_LOCATION, IdentityProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));

        // When
        $refreshment = $this->refreshSigned();

        // Then
        static::assertSame(sprintf('The identity provider "%s" is registered from its metadata.', IdentityProviderDocuments::SIGNED), $refreshment->what);
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $this->accepted($this->tenant, IdentityProviderDocuments::SIGNED)->validUntil);
    }

    private function refreshSimpleSamlPhp(): MetadataRefreshment
    {
        return $this->refresh([
            IdentityProviderDocuments::SIMPLESAMLPHP => self::declaration(self::LOCATION, 'acme.example'),
        ])->refreshAll($this->tenant)[0];
    }

    private function refreshSigned(): MetadataRefreshment
    {
        return $this->refresh([
            IdentityProviderDocuments::SIGNED => [
                ...self::declaration(self::SIGNED_LOCATION, 'example.org'),
                'metadata_signers' => [IdentityProviderDocuments::signer()->base64],
            ],
        ])->refreshAll($this->tenant)[0];
    }

    private function acceptedSimpleSamlPhp(): AcceptedMetadata
    {
        return $this->accepted($this->tenant, IdentityProviderDocuments::SIMPLESAMLPHP);
    }

    private function accepted(Tenant $tenant, string $entityId): AcceptedMetadata
    {
        return $this->accepted->find($tenant, $entityId) ?? static::fail('Nothing is accepted.');
    }

    /**
     * @param array<string, array<string, mixed>> $definitions
     *
     * @return MetadataRefresh<UpstreamIdentityProvider>
     */
    private function refresh(array $definitions): MetadataRefresh
    {
        return new MetadataRefresh(
            new UpstreamIdentityProviderRole(
                new ConfigurationUpstreamIdentityProviders($this->tenant->slug, $definitions, new FixedProfileClaims()),
                new ModelUpstreamMetadataReader($this->clock),
            ),
            $this->fetcher,
            $this->accepted,
            $this->clock,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function declaration(string $location, string $domain): array
    {
        return [
            'metadata' => $location,
            'domains' => [$domain],
            'email_attribute' => 'mail',
        ];
    }
}
