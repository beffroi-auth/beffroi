<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures as Fixtures;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\PeerKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace_callback;

/**
 * Sections 5.7, 6.6 step 3 and 6.7, §9.3 row 20, SAML Core §6.2: the assertion a response writer signed, encrypted for
 * the test key of the service provider, then the response signed over the ciphertext on request.
 */
final class ResponseWriterEncryptionTest extends TestCase
{
    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * §9.3 row 20, section 6.7: the response holds one saml:EncryptedAssertion where its assertion stood, the last
     * child, holding one xenc:EncryptedData, and no saml:Assertion.
     */
    #[Test]
    public function itPutsAnEncryptedAssertionInPlaceOfTheAssertion(): void
    {
        // When
        $root = $this->encrypted(SignedParts::Assertion)->root();

        // Then
        static::assertSame(
            [['saml:Issuer', 'samlp:Status', 'saml:EncryptedAssertion'], ['xenc:EncryptedData']],
            [
                Fixtures::names(Children::all($root)),
                Fixtures::names(Children::all(Children::one($root, new Name(self::ASSERTION, 'EncryptedAssertion')))),
            ],
        );
    }

    /**
     * §9.3 row 20, section 6.7, core.md section 6.5: the saml prefix is declared on the saml:EncryptedAssertion that
     * introduces it under the samlp:Response, so that the response serializes and loads again.
     */
    #[Test]
    public function itDeclaresTheSamlPrefixOnTheEncryptedAssertion(): void
    {
        // When
        $root = $this->encrypted(SignedParts::Assertion)->root();

        // Then
        static::assertSame(
            ['saml' => self::ASSERTION],
            Fixtures::declarations(Children::one($root, new Name(self::ASSERTION, 'EncryptedAssertion'))),
        );
    }

    /**
     * §9.3 row 20, section 5.7, enc.md E-1: the content algorithm and the key transport of the Encryption are the ones
     * written, aes256-gcm under rsa-oaep-mgf1p by default.
     */
    #[Test]
    #[DataProvider('provideSchemes')]
    public function itEncryptsUnderTheSchemeOfTheEncryption(Encryption $encryption, string $content, string $transport): void
    {
        // When
        $data = $this->encryptedData(new ResponseWriter()->write(
            Fixtures::response(),
            $this->signing(),
            SignedParts::Assertion,
            $encryption,
        ));

        // Then
        static::assertSame([$content, $transport], [
            $this->algorithm(Children::one($data, new Name(self::XMLENC, 'EncryptionMethod'))),
            $this->algorithm(Children::one($this->encryptedKey($data), new Name(self::XMLENC, 'EncryptionMethod'))),
        ]);
    }

    /**
     * @return iterable<string, array{Encryption, string, string}>
     */
    public static function provideSchemes(): iterable
    {
        yield 'the default' => [
            new Encryption(self::peer()),
            ContentAlgorithm::Aes256Gcm->value,
            KeyTransport::RSA_OAEP_MGF1P,
        ];
        yield 'aes128-gcm' => [
            new Encryption(self::peer(), ContentAlgorithm::Aes128Gcm, KeyTransport::mgf1p()),
            ContentAlgorithm::Aes128Gcm->value,
            KeyTransport::RSA_OAEP_MGF1P,
        ];
    }

    /**
     * Section 6.7, enc.md section 5.3: the xenc:EncryptedKey sits inside the ds:KeyInfo of the xenc:EncryptedData and
     * carries no KeyInfo of its own, the service provider decrypting with the key it holds.
     */
    #[Test]
    public function itWritesNoKeyInfoUnderTheEncryptedKey(): void
    {
        // When
        $key = $this->encryptedKey($this->encryptedData($this->encrypted(SignedParts::Assertion)));

        // Then
        static::assertSame(
            ['xenc:EncryptionMethod', 'xenc:CipherData'],
            Fixtures::names(Children::all($key)),
        );
    }

    /**
     * §9.3 row 20, section 9.1, section 6.7, SAML Core §6.2, enc.md E-9: read back by a validator, the identity provider
     * given the test key of the service provider (section 5.5), the assertion is the one written, signed by the identity provider and verified once
     * decrypted, the response signed over the ciphertext when asked.
     */
    #[Test]
    #[DataProvider('provideSignedParts')]
    public function theValidatorReadsTheAssertionAsWritten(SignedParts $parts, SignatureCoverage $coverage): void
    {
        // Given
        $response = Fixtures::response();
        $encrypted = new ResponseWriter()->write($response, $this->signing(), $parts, new Encryption(self::peer()));

        // When
        $accepted = Fixtures::validator()->validate(
            UnverifiedResponse::of(SamlLoader::create()->load(new Serializer()->serialize($encrypted))),
            Fixtures::identityProvider()->withDecryptionKey(
                PrivateDecryptionKey::fromPem(MetadataFixtures::bytes('keys/sp-signing-key.pem')),
            ),
            Fixtures::expected(),
        );

        // Then
        static::assertEquals([$response->assertion, $coverage], [$accepted->assertion, $accepted->coverage]);
    }

    /**
     * @return iterable<string, array{SignedParts, SignatureCoverage}>
     */
    public static function provideSignedParts(): iterable
    {
        yield 'the assertion signed' => [SignedParts::Assertion, SignatureCoverage::Assertion];
        yield 'the response signed too' => [SignedParts::AssertionAndResponse, SignatureCoverage::AssertionAndResponse];
    }

    /**
     * §9.3 row 20, section 6.6 step 3, SAML Core §6.2: on request, the response is signed after the assertion was
     * encrypted, its Signature after its Issuer, and verifies under the identity provider's key.
     */
    #[Test]
    public function itSignsTheResponseOverTheEncryptedAssertion(): void
    {
        // Given
        $document = $this->encrypted(SignedParts::AssertionAndResponse);

        // When
        $verified = new Verifier(SamlLoader::create())->verify(
            $document->root(),
            MetadataFixtures::verificationKeys('idp'),
        );

        // Then
        static::assertSame(
            [['saml:Issuer', 'ds:Signature', 'samlp:Status', 'saml:EncryptedAssertion'], 'saml:EncryptedAssertion'],
            [
                Fixtures::names(Children::all($document->root())),
                Children::one($verified->document->root(), new Name(self::ASSERTION, 'EncryptedAssertion'))->nodeName,
            ],
        );
    }

    /**
     * §9.3 row 20, SAML Core §6.2, dsig.md section 5.5: the signature of the response covers the ciphertext, so that a
     * byte of it changed is refused before anything is decrypted.
     */
    #[Test]
    public function theSignatureOfTheResponseCoversTheCiphertext(): void
    {
        // Given
        $altered = SamlLoader::create()->load((string) preg_replace_callback(
            '~(</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>)(.)~',
            static fn (array $match): string => $match[1] . ($match[2] === 'A' ? 'B' : 'A'),
            new Serializer()->serialize($this->encrypted(SignedParts::AssertionAndResponse)),
        ));

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        new Verifier(SamlLoader::create())->verify($altered->root(), MetadataFixtures::verificationKeys('idp'));
    }

    /**
     * A response of the fixtures written with its assertion encrypted for the service provider's test key.
     */
    private function encrypted(SignedParts $parts): Document
    {
        return new ResponseWriter()->write(Fixtures::response(), $this->signing(), $parts, new Encryption(self::peer()));
    }

    private function encryptedData(Document $document): Element
    {
        return Children::one(
            Children::one($document->root(), new Name(self::ASSERTION, 'EncryptedAssertion')),
            new Name(self::XMLENC, 'EncryptedData'),
        );
    }

    private function encryptedKey(Element $data): Element
    {
        return Children::one(
            Children::one($data, new Name(self::DSIG, 'KeyInfo')),
            new Name(self::XMLENC, 'EncryptedKey'),
        );
    }

    private function algorithm(Element $method): string
    {
        return Attributes::required($method, new Name(null, 'Algorithm'));
    }

    private static function peer(): PeerKey
    {
        return PeerKey::fromCertificatePem(MetadataFixtures::certificatePem('sp'));
    }

    private function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('idp'));
    }
}
