<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\ServiceProvider;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Metadata\AcceptedMetadataForgetting;
use Beffroi\Saml\Application\Metadata\MetadataRefreshment;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderRole;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedMetadataFetcher;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.2: the metadata of a service provider registered the first time and refreshed every time
 * after, by the declarations of the configuration, the reader of the model and a fetcher of the test, at
 * 2026-09-15T10:00:00Z.
 */
final class ServiceProviderMetadataRefreshTest extends TestCase
{
    private const string LOCATION = 'https://sp.example.com/saml/metadata';

    private const string SIGNED_LOCATION = '/srv/saml/signed-sp-metadata.xml';

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
     * The acceptance of issue #729: a SimpleSAMLphp service provider is registered from its metadata, the bytes that
     * were read kept (S-8).
     */
    #[Test]
    public function aServiceProviderIsRegisteredFromItsMetadata(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
        static::assertSame(\sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        $accepted = $this->acceptedSimpleSamlPhp();
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $accepted->document);
        static::assertNull($accepted->validUntil);
        static::assertEquals(Fixtures::now(), $accepted->acceptedAt);
        static::assertSame($this->tenant, $accepted->tenant);
    }

    /**
     * Section 6.2 step 6: the same bytes read again write nothing.
     */
    #[Test]
    public function theSameDocumentReadAgainWritesNothing(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp();

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused);
        static::assertSame(
            \sprintf('The metadata of the service provider "%s" are the ones accepted already.', ServiceProviderDocuments::SIMPLESAMLPHP),
            $refreshment->what,
        );
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * Section 6.2 step 6: a newer document takes the place of the accepted one.
     */
    #[Test]
    public function aNewerDocumentIsAccepted(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $this->clock->sleep(3600);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(\sprintf('The metadata of the service provider "%s" are refreshed.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        $accepted = $this->acceptedSimpleSamlPhp();
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $accepted->validUntil);
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $accepted->acceptedAt);
        static::assertSame(2, $this->accepted->saves);
    }

    /**
     * S-6, the acceptance of issue #729: an expired document is refused, the accepted one kept.
     */
    #[Test]
    public function anExpiredDocumentIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:00:00Z'));

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            \sprintf(
                'The metadata of the service provider "%s" are refused, the document accepted kept: The metadata is past its validUntil (M-7).',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $this->acceptedSimpleSamlPhp()->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-6, the acceptance of issue #729: a document read under the signers the declaration pins that is older than the
     * one accepted is refused, the accepted one kept, an older document signed by the same key verifying as well.
     */
    #[Test]
    public function aSignedDocumentOlderThanTheAcceptedOneIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-08T00:00:00Z')));
        $this->refreshSigned();
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));

        // When
        $refreshment = $this->refreshSigned();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).',
            $refreshment->what,
        );
        static::assertEquals(new DateTimeImmutable('2026-10-08T00:00:00Z'), $this->acceptedSigned()->validUntil);
        static::assertSame(1, $this->accepted->saves);
    }

    /**
     * S-6, the security review of 20 October 2026 (finding B-1): a document its channel vouches for replaces the
     * accepted one whatever its validUntil, so that a document a metadata host wrote with a far validUntil while it was
     * held by somebody else gives way to the next one the service provider publishes there, the genuine SimpleSAMLphp
     * file carrying none.
     */
    #[Test]
    #[DataProvider('provideDocumentsTrustedByTheirChannel')]
    public function aDocumentTrustedByItsChannelReplacesTheAcceptedOneWhateverItsValidUntil(
        string $accepted,
        string $read,
        ?DateTimeImmutable $validUntil,
    ): void {
        // Given
        $this->fetcher->answer(self::LOCATION, $accepted);
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, $read);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertSame(\sprintf('The metadata of the service provider "%s" are refreshed.', ServiceProviderDocuments::SIMPLESAMLPHP), $refreshment->what);
        static::assertSame($read, $this->acceptedSimpleSamlPhp()->document);
        static::assertEquals($validUntil, $this->acceptedSimpleSamlPhp()->validUntil);
    }

    /**
     * @return iterable<string, array{string, string, ?DateTimeImmutable}>
     */
    public static function provideDocumentsTrustedByTheirChannel(): iterable
    {
        yield 'none after a far validUntil' => [
            ServiceProviderDocuments::simpleSamlPhpValidUntil('2099-01-01T00:00:00Z'),
            ServiceProviderDocuments::simpleSamlPhp(),
            null,
        ];
        yield 'an earlier validUntil' => [
            ServiceProviderDocuments::simpleSamlPhpValidUntil('2099-01-01T00:00:00Z'),
            ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'),
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
        ];
    }

    /**
     * S-6, section 6.2, forgotten: a service provider whose signed metadata went back to an earlier validUntil, refused
     * for it, is registered again from them once an operator forgot the document accepted.
     */
    #[Test]
    public function aServiceProviderForgottenIsRegisteredAgainFromAnOlderSignedDocument(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-08T00:00:00Z')));
        $this->refreshSigned();
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        new AcceptedMetadataForgetting($this->accepted, $this->accepted)->forget($this->tenant, ServiceProviderDocuments::SIGNED);

        // When
        $refreshment = $this->refreshSigned();

        // Then
        static::assertSame(\sprintf('The service provider "%s" is registered from its metadata.', ServiceProviderDocuments::SIGNED), $refreshment->what);
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $this->acceptedSigned()->validUntil);
    }

    /**
     * S-7, the acceptance of issue #729: a service provider asking for encryption without an encryption key in its
     * metadata is refused at registration.
     */
    #[Test]
    public function aServiceProviderAskingForEncryptionWithoutAKeyIsRefusedAtRegistration(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp(encrypt: true);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The service provider asks for encrypted assertions and its metadata hold no key for encryption (spec/saml.md S-7).',
            $refreshment->what,
        );
        static::assertNull($this->accepted->find($this->tenant, ServiceProviderDocuments::SIMPLESAMLPHP));
    }

    /**
     * S-7: a service provider asking for encryption whose metadata hold a key for it is registered.
     */
    #[Test]
    public function aServiceProviderAskingForEncryptionWithAKeyIsRegistered(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp(encrypt: true);

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-7: a refresh that drops the key for encryption is refused, the accepted document kept.
     */
    #[Test]
    public function aRefreshThatDropsTheEncryptionKeyIsRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp(encrypt: true);
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp(encrypt: true);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $this->acceptedSimpleSamlPhp()->document);
    }

    /**
     * S-11, the acceptance of issue #730: Entra's guest federation, which publishes no key, declared without
     * `signs_authn_requests: false` is refused at its registration.
     */
    #[Test]
    public function aServiceProviderThatSignsWithoutAKeyInItsMetadataIsRefusedAtRegistration(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::entra());

        // When
        $refreshment = $this->refreshEntra(signs: true);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith(
            'The requests of the service provider need a signature and its metadata hold no key for signing (spec/saml.md S-11).',
            $refreshment->what,
        );
        static::assertNull($this->accepted->find($this->tenant, ServiceProviderDocuments::ENTRA));
    }

    /**
     * S-11, S-9: Entra's guest federation declared unsigned, its metadata saying nothing of a signature, needs no key.
     */
    #[Test]
    public function aServiceProviderDeclaredUnsignedNeedsNoKeyInItsMetadata(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::entra());

        // When
        $refreshment = $this->refreshEntra(signs: false);

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-11, S-9: a provider declared unsigned whose metadata say `AuthnRequestsSigned="true"` needs a signature all the
     * same, so a key to verify it by.
     */
    #[Test]
    public function aServiceProviderDeclaredUnsignedWhoseMetadataSayItSignsIsRefusedWithoutAKey(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::entraSigningItsRequests());

        // When
        $refreshment = $this->refreshEntra(signs: false);

        // Then
        static::assertTrue($refreshment->refused);
        static::assertNull($this->accepted->find($this->tenant, ServiceProviderDocuments::ENTRA));
    }

    /**
     * S-11: a service provider that signs, whose metadata hold the key for it, is registered.
     */
    #[Test]
    public function aServiceProviderThatSignsWithAKeyInItsMetadataIsRegistered(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-11: a refresh that drops the key for signing is refused, the accepted document kept.
     */
    #[Test]
    public function aRefreshThatDropsTheSigningKeyIsRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $this->refreshSimpleSamlPhp();
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutSigningKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $this->acceptedSimpleSamlPhp()->document);
    }

    /**
     * A service provider that does not ask for encryption needs no key for it.
     */
    #[Test]
    public function aServiceProviderThatAsksForNoEncryptionNeedsNoKeyForIt(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
    }

    /**
     * S-5: the metadata of another entity than the one declared are refused.
     */
    #[Test]
    public function theMetadataOfAnotherEntityAreRefused(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());
        $refresh = $this->refresh([
            'https://sp.example.com/saml' => [
                'metadata' => self::LOCATION,
            ],
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            'The metadata of the service provider "https://sp.example.com/saml" are refused, the document accepted kept: The metadata name another entity than the service provider declared (spec/saml.md S-5).',
            $refreshment->what,
        );
        static::assertSame(0, $this->accepted->saves);
    }

    /**
     * Section 6.2 step 2: a location that cannot be read is a refusal, returned rather than thrown.
     */
    #[Test]
    public function aLocationThatCannotBeReadIsRefused(): void
    {
        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith('The location answers nothing.', $refreshment->what);
    }

    /**
     * S-5: a declaration that pins a signer has its metadata read signed, and a document of the channel alone is
     * refused.
     */
    #[Test]
    public function aDeclarationThatPinsASignerRefusesAnUnsignedDocument(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertTrue($refreshment->refused);
        static::assertStringEndsWith('The metadata carries no ds:Signature as the first child of its root (M-2).', $refreshment->what);
    }

    /**
     * S-5: a document signed by the pinned key registers its service provider.
     */
    #[Test]
    public function aDocumentSignedByThePinnedKeyIsRegistered(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshment = $refresh->refreshAll($this->tenant)[0];

        // Then
        static::assertFalse($refreshment->refused, $refreshment->what);
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * Section 6.2: every service provider the tenant declares is read, whatever one of them answers.
     */
    #[Test]
    public function everyServiceProviderIsReadWhateverOneOfThemAnswers(): void
    {
        // Given
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::LOCATION,
            ],
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshments = $refresh->refreshAll($this->tenant);

        // Then
        static::assertSame(
            [
                [ServiceProviderDocuments::SIMPLESAMLPHP, true],
                [ServiceProviderDocuments::SIGNED,        false],
            ],
            \array_map(static fn (MetadataRefreshment $refreshment): array => [$refreshment->entityId, $refreshment->refused], $refreshments),
        );
    }

    /**
     * Section 6.2 step 6: another process, the console and the hourly step at the same minute, registered the service
     * provider between the reading of the accepted document and the write; the unique index keeps its row, and this
     * reading is skipped rather than refused.
     */
    #[Test]
    public function aServiceProviderRegisteredByAnotherProcessMeanwhileIsSkipped(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-08T00:00:00Z'));
        $theOther = new AcceptedServiceProviderMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIMPLESAMLPHP,
            ServiceProviderDocuments::simpleSamlPhp(),
            null,
            Fixtures::now(),
        );
        $this->accepted->registeredMeanwhile($theOther);

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertFalse($refreshment->refused);
        static::assertSame(
            \sprintf(
                'The service provider "%s" was registered by another process meanwhile; this reading is skipped.',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
        static::assertSame($theOther, $this->acceptedSimpleSamlPhp());
    }

    /**
     * Section 6.2: a service provider whose reading throws what no rule refuses, a store or a fetcher that fails, does
     * not stop the ones declared after it.
     */
    #[Test]
    public function aServiceProviderThatFailsDoesNotStopTheNextOne(): void
    {
        // Given
        $this->fetcher->fail(self::LOCATION, new RuntimeException('The store is gone.'));
        $this->fetcher->answer(self::SIGNED_LOCATION, ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')));
        $refresh = $this->refresh([
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::LOCATION,
            ],
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ]);

        // When
        $refreshments = $refresh->refreshAll($this->tenant);

        // Then
        static::assertSame(
            [
                [ServiceProviderDocuments::SIMPLESAMLPHP, true],
                [ServiceProviderDocuments::SIGNED,        false],
            ],
            \array_map(static fn (MetadataRefreshment $refreshment): array => [$refreshment->entityId, $refreshment->refused], $refreshments),
        );
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * Section 6.2, M-16: a failure is named by the class of what was thrown, never by its message, which may carry a
     * value of the document or of a query.
     */
    #[Test]
    public function aFailureIsNamedByItsClassAndNotByItsMessage(): void
    {
        // Given
        $this->fetcher->fail(self::LOCATION, new RuntimeException('INSERT INTO beffroi_saml_service_provider VALUES (grace.hopper@sp.example.org)'));

        // When
        $refreshment = $this->refreshSimpleSamlPhp();

        // Then
        static::assertTrue($refreshment->refused);
        static::assertSame(
            \sprintf(
                'The metadata of the service provider "%s" could not be refreshed, the document accepted kept: RuntimeException was thrown.',
                ServiceProviderDocuments::SIMPLESAMLPHP,
            ),
            $refreshment->what,
        );
    }

    /**
     * The declarations are those of one tenant: another has nothing to refresh.
     */
    #[Test]
    public function anotherTenantHasNothingToRefresh(): void
    {
        // Given
        $this->fetcher->answer(self::LOCATION, ServiceProviderDocuments::simpleSamlPhp());

        // When
        $refreshments = $this->refresh(self::simpleSamlPhpDeclaration(false))->refreshAll(Fixtures::tenant('other'));

        // Then
        static::assertSame([], $refreshments);
    }

    private function refreshSimpleSamlPhp(bool $encrypt = false): MetadataRefreshment
    {
        return $this->refresh(self::simpleSamlPhpDeclaration($encrypt))->refreshAll($this->tenant)[0];
    }

    private function refreshEntra(bool $signs): MetadataRefreshment
    {
        return $this->refresh([
            ServiceProviderDocuments::ENTRA => [
                'metadata' => self::LOCATION,
                'signs_authn_requests' => $signs,
            ],
        ])->refreshAll($this->tenant)[0];
    }

    private function refreshSigned(): MetadataRefreshment
    {
        return $this->refresh([
            ServiceProviderDocuments::SIGNED => [
                'metadata' => self::SIGNED_LOCATION,
                'metadata_signers' => [ServiceProviderDocuments::signer()->base64],
            ],
        ])->refreshAll($this->tenant)[0];
    }

    private function acceptedSigned(): AcceptedMetadata
    {
        return $this->accepted->find($this->tenant, ServiceProviderDocuments::SIGNED) ?? static::fail('Nothing is accepted.');
    }

    private function acceptedSimpleSamlPhp(): AcceptedMetadata
    {
        return $this->accepted->find($this->tenant, ServiceProviderDocuments::SIMPLESAMLPHP) ?? static::fail('Nothing is accepted.');
    }

    /**
     * @param array<string, array<string, mixed>> $definitions
     *
     * @return MetadataRefresh<ServiceProvider>
     */
    private function refresh(array $definitions): MetadataRefresh
    {
        return new MetadataRefresh(
            new ServiceProviderRole(
                new ConfigurationServiceProviders($this->tenant->slug, $definitions, new FixedClaims()),
                new ModelServiceProviderMetadataReader($this->clock),
            ),
            $this->fetcher,
            $this->accepted,
            $this->clock,
        );
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private static function simpleSamlPhpDeclaration(bool $encrypt): array
    {
        return [
            ServiceProviderDocuments::SIMPLESAMLPHP => [
                'metadata' => self::LOCATION,
                'encrypt_assertions' => $encrypt,
            ],
        ];
    }
}
