<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function substr;

/**
 * spec/saml.md S-5, S-6, section 6.2 steps 3 and 4: the metadata of a service provider read by saml2-model's
 * MetadataReader, by the channel or under the signers a declaration pins, at 2026-09-15T10:00:00Z.
 */
final class ModelServiceProviderMetadataReaderTest extends TestCase
{
    private const string ASSERTION_CONSUMER = 'https://sp.example.org/saml/acs';

    private ModelServiceProviderMetadataReader $reader;

    protected function setUp(): void
    {
        $this->reader = new ModelServiceProviderMetadataReader(new MockClock(Fixtures::now()));
    }

    /**
     * The acceptance of issue #729: the metadata a SimpleSAMLphp 2.5.3.1 service provider publishes, read by the
     * channel, its entity ID and its key for encryption.
     */
    #[Test]
    public function itReadsTheMetadataOfASimpleSamlPhpServiceProvider(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertSame(ServiceProviderDocuments::SIMPLESAMLPHP, $metadata->entityId);
        static::assertNull($metadata->validUntil);
        static::assertCount(1, $metadata->encryptionCertificates);
        static::assertStringStartsWith('MIIDcTCCAlmgAwIBAgIUcUbLWObVO2r2', $metadata->encryptionCertificates[0]->base64);
    }

    /**
     * S-9, section 6.2 step 3: the SimpleSAMLphp service provider says it signs its requests.
     */
    #[Test]
    public function itReadsThatAServiceProviderSignsItsRequests(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertTrue($metadata->authnRequestsSigned);
    }

    /**
     * S-9, section 6.2 step 3, Metadata §2.4.4: a document without AuthnRequestsSigned, as Entra's is written, says
     * nothing of a signature.
     */
    #[Test]
    public function itReadsAnAbsentAuthnRequestsSignedAsFalse(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::entra());

        // Then
        static::assertSame(ServiceProviderDocuments::ENTRA, $metadata->entityId);
        static::assertFalse($metadata->authnRequestsSigned);
        static::assertSame([], $metadata->encryptionCertificates);
    }

    /**
     * S-11, section 6.2 step 3: the signing certificates of a document are those of its `KeyDescriptor` for signing.
     */
    #[Test]
    public function itReadsTheSigningCertificatesOfADocument(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertCount(1, $metadata->signingCertificates);
    }

    /**
     * S-11, section 6.2 step 3: a `KeyDescriptor` for encryption is not a key for signing.
     */
    #[Test]
    public function itDoesNotReadAnEncryptionCertificateAsASigningOne(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhpWithoutSigningKey());

        // Then
        static::assertSame([], $metadata->signingCertificates);
        static::assertCount(1, $metadata->encryptionCertificates);
    }

    /**
     * S-11, section 6.2 step 3: a document without a key, as Entra's is written, has no signing certificate.
     */
    #[Test]
    public function itReadsADocumentWithoutAKeyAsHoldingNoSigningCertificate(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::entra());

        // Then
        static::assertSame([], $metadata->signingCertificates);
    }

    #[Test]
    public function itReadsTheValidUntilOfADocument(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));

        // Then
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * S-6, the acceptance of issue #729: an expired document is refused (M-7), the skew of the model past.
     */
    #[Test]
    public function itRefusesAnExpiredDocument(): void
    {
        // Given
        $document = ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:57:00Z');

        // When
        try {
            $this->reader->readTrusted($document);
            static::fail('An expired document is read.');
        } catch (MetadataRefusedException $exception) {
            // Then
            static::assertSame('The metadata is past its validUntil (M-7).', $exception->getMessage());
            static::assertInstanceOf(OutsideValidityWindow::class, $exception->getPrevious());
        }
    }

    /**
     * Section 5.1: a certificate the model reads and that is not the canonical base64 of its DER, one whose unused bits
     * are set, is refused rather than kept in another spelling than the one it is compared in.
     */
    #[Test]
    public function itRefusesACertificateThatIsNotCanonicalBase64(): void
    {
        // Given
        $certificate = ServiceProviderDocuments::signer()->base64;
        $document = ServiceProviderDocuments::simpleSamlPhpWithCertificate(substr($certificate, 0, -3) . 'x==');

        // When
        try {
            $this->reader->readTrusted($document);
            static::fail('A certificate in another spelling is read.');
        } catch (MetadataRefusedException $exception) {
            // Then
            static::assertSame(
                'A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).',
                $exception->getMessage(),
            );
            static::assertInstanceOf(InvalidArgumentException::class, $exception->getPrevious());
        }
    }

    /**
     * S-5: a document without a service provider role is no service provider's.
     */
    #[Test]
    public function itRefusesADocumentWithoutAServiceProviderRole(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');

        // When
        $this->reader->readTrusted(ServiceProviderDocuments::identityProvider());
    }

    /**
     * Section 6.2 step 3: what Core refuses is refused, with its message.
     */
    #[Test]
    public function itRefusesWhatCoreRefuses(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The input is empty (I-3).');

        // When
        $this->reader->readTrusted('');
    }

    /**
     * S-5: a document signed by a key the declaration pins is read under it.
     */
    #[Test]
    public function itReadsADocumentSignedByAPinnedKey(): void
    {
        // When
        $metadata = $this->reader->readSigned(
            ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')),
            [ServiceProviderDocuments::signer()],
        );

        // Then
        static::assertSame(ServiceProviderDocuments::SIGNED, $metadata->entityId);
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * S-6: a document read under a key the declaration pins says so, which holds it to the document accepted.
     */
    #[Test]
    public function itSaysADocumentReadUnderAPinnedKeyWasReadSigned(): void
    {
        // When
        $metadata = $this->reader->readSigned(
            ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')),
            [ServiceProviderDocuments::signer()],
        );

        // Then
        static::assertTrue($metadata->readSigned);
    }

    /**
     * S-6: a document read by its channel says it was not read signed, which lets it replace the document accepted
     * whatever its validUntil.
     */
    #[Test]
    public function itSaysADocumentReadByItsChannelWasNotReadSigned(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertFalse($metadata->readSigned);
    }

    /**
     * S-11, the security review of 20 October 2026 (findings B-3, C-2, C-3): a document one of whose endpoints the
     * identity provider sends a browser to is not an https URL on a host is refused at its reading, the refusal naming
     * the endpoint and never its value (M-16).
     *
     * @param list<Endpoint> $singleLogoutServices
     */
    #[Test]
    #[DataProvider('provideDocumentsWithAnEndpointOffTheWeb')]
    public function itRefusesADocumentAnEndpointOfWhichIsNotHttpsOnAHost(string $assertionConsumerService, array $singleLogoutServices, string $message): void
    {
        // Given
        $document = ServiceProviderDocuments::signed(
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
            singleLogoutServices: $singleLogoutServices,
            assertionConsumerService: $assertionConsumerService,
        );

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader->readTrusted($document);
    }

    /**
     * @return iterable<string, array{string, list<Endpoint>, string}>
     */
    public static function provideDocumentsWithAnEndpointOffTheWeb(): iterable
    {
        yield 'an assertion consumer service in plain http' => [
            'http://sp.example.org/saml/acs',
            [],
            'The Location of an md:AssertionConsumerService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).',
        ];
        yield 'a single logout service that runs a script' => [
            self::ASSERTION_CONSUMER,
            [new Endpoint(Binding::HttpRedirect, 'javascript:fetch(document.cookie)')],
            'The Location of an md:SingleLogoutService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).',
        ];
        yield 'a response location whose host carries a directive' => [
            self::ASSERTION_CONSUMER,
            [new Endpoint(Binding::HttpPost, 'https://sp.example.org/saml/slo', 'https://sp.example.org;sandbox/saml/slo')],
            'The ResponseLocation of an md:SingleLogoutService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).',
        ];
    }

    /**
     * S-11: endpoints in https on a port, on an IPv6 literal, their scheme in capitals, are read.
     */
    #[Test]
    public function itReadsADocumentWhoseEndpointsAreHttpsOnAHost(): void
    {
        // Given
        $document = ServiceProviderDocuments::signed(
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
            singleLogoutServices: [new Endpoint(Binding::HttpPost, 'https://[2001:db8::1]/saml/slo', 'https://sp.example.org:8443/saml/slo')],
            assertionConsumerService: 'HTTPS://sp.example.org:8443/saml/acs',
        );

        // When
        $metadata = $this->reader->readTrusted($document);

        // Then
        static::assertSame(ServiceProviderDocuments::SIGNED, $metadata->entityId);
    }

    /**
     * S-5: a document signed by another key than the pinned ones is refused.
     */
    #[Test]
    public function itRefusesADocumentSignedByAnotherKey(): void
    {
        // Given
        $document = ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z'), 'idp');

        // Then
        $this->expectException(MetadataRefusedException::class);

        // When
        $this->reader->readSigned($document, [ServiceProviderDocuments::signer()]);
    }

    /**
     * S-5, M-2: an unsigned document is refused where a signer is pinned.
     */
    #[Test]
    public function itRefusesAnUnsignedDocumentWhereASignerIsPinned(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata carries no ds:Signature as the first child of its root (M-2).');

        // When
        $this->reader->readSigned(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'), [ServiceProviderDocuments::signer()]);
    }

    /**
     * S-6: a signed document without validUntil is bounded by nothing, and an older one signed by the same key would
     * verify as well (model.md section 6.5 step 3).
     */
    #[Test]
    public function itRefusesASignedDocumentWithoutValidUntil(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('Signed metadata carry a validUntil, without which an older document signed by the same key verifies as well (spec/saml.md S-6).');

        // When
        $this->reader->readSigned(ServiceProviderDocuments::signed(null), [ServiceProviderDocuments::signer()]);
    }

    #[Test]
    public function itRefusesToReadSignedMetadataUnderNoSigner(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('Signed metadata are verified under one certificate at least (spec/saml.md S-5).');

        // When
        $this->reader->readSigned(ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')), []);
    }

    /**
     * Section 6.3 step 1: the accepted document read back once, into what the signature of a request needs and into
     * the model's role, which holds the assertion consumer services (S-10).
     */
    #[Test]
    public function itReadsAnAcceptedDocumentOnceIntoBothReadings(): void
    {
        // When
        $read = $this->reader->readAccepted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertSame(
            [ServiceProviderDocuments::SIMPLESAMLPHP, ServiceProviderDocuments::SIMPLESAMLPHP, true, true],
            [$read->metadata->entityId, $read->role->entityId, $read->metadata->authnRequestsSigned, $read->role->authnRequestsSigned],
        );
    }

    /**
     * Section 6.3 step 1, S-6: the accepted document read back is read by its store, never under a signer.
     */
    #[Test]
    public function itSaysAnAcceptedDocumentReadBackWasNotReadSigned(): void
    {
        // When
        $read = $this->reader->readAccepted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertFalse($read->metadata->readSigned);
    }

    /**
     * Section 6.3 step 1: an accepted document the reading refuses now is refused.
     */
    #[Test]
    public function itRefusesAnAcceptedDocumentPastItsValidity(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(M-7)');

        // When
        $this->reader->readAccepted(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-01T00:00:00Z'));
    }

    /**
     * Section 6.3 step 1, S-11: an accepted document read back is held to the same rule as a document read at a
     * refresh, so that one accepted before the rule serves no request.
     */
    #[Test]
    public function itRefusesAnAcceptedDocumentAnEndpointOfWhichIsNotHttpsOnAHost(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The Location of an md:AssertionConsumerService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).');

        // When
        $this->reader->readAccepted(ServiceProviderDocuments::signed(null, assertionConsumerService: 'http://sp.example.org/saml/acs'));
    }

    /**
     * S-5: an accepted document that holds no service provider role is refused.
     */
    #[Test]
    public function itRefusesAnAcceptedDocumentWithoutAServiceProviderRole(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');

        // When
        $this->reader->readAccepted(ServiceProviderDocuments::identityProvider());
    }
}
