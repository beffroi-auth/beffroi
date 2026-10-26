<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Internal\Response\DecryptedAssertion;
use Beffroi\Saml2\Model\Internal\Response\SignedAssertion;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Enc\Decryptor;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 5, section 6.7, M-1, M-2, M-4, M-5: the document the assertion is read from, its own signature
 * verified where the assertion arrived, or on the root of its decryption, or the response's.
 */
final class SignedAssertionTest extends TestCase
{
    use ResponseFixtures;

    /**
     * M-2, section 6.1 step 5: an assertion signed under a signed response is read from its own verification.
     */
    #[Test]
    public function itReadsASignedAssertionFromItsOwnVerification(): void
    {
        // Given
        $document = $this->document('behaviour/response-signed-both-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // When
        $assertion = SignedAssertion::of(
            $this->assertion($document),
            $response,
            self::identityProvider(),
            SamlLoader::create(),
        );

        // Then
        static::assertTrue($assertion->signed);
        static::assertSame(
            '_assertion',
            Attributes::optional($assertion->document->root(), new Name(null, 'ID')),
        );
    }

    /**
     * M-2, E26: an unsigned assertion is read from the verification of the response that covers it.
     */
    #[Test]
    public function itReadsAnUnsignedAssertionFromTheResponsesVerification(): void
    {
        // Given
        $document = $this->document('behaviour/response-signed-response-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // When
        $assertion = SignedAssertion::of(
            $this->assertion($document),
            $response,
            self::identityProvider(),
            SamlLoader::create(),
        );

        // Then
        static::assertFalse($assertion->signed);
        static::assertSame($response->verification?->document, $assertion->document);
    }

    /**
     * §9.2 row 9, M-2: neither the response nor the assertion signed.
     */
    #[Test]
    public function itRefusesAnAssertionNoSignatureCovers(): void
    {
        // Given
        $document = $this->document('hostile/response-unsigned-refused.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).');

        // When
        SignedAssertion::of($this->assertion($document), $response, self::identityProvider(), SamlLoader::create());
    }

    /**
     * M-4, M-5, D-10: two ds:Signature, or one before the Issuer, refused on the received assertion, whose
     * verification would remove the one it verified from the document the reader reads.
     */
    #[Test]
    #[DataProvider('provideSignaturesOutOfTheSchema')]
    public function itRefusesASignatureTheSchemaDoesNotAllowThere(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        SignedAssertion::of($this->assertion($document), $response, self::identityProvider(), SamlLoader::create());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSignaturesOutOfTheSchema(): iterable
    {
        yield 'two ds:Signature' => [
            'hostile/response-assertion-two-signatures-refused.xml',
            'The saml:Assertion holds more than one ds:Signature (M-4).',
        ];
        yield 'a ds:Signature before the Issuer' => [
            'hostile/response-assertion-signature-before-issuer-refused.xml',
            'The saml:Assertion holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
    }

    /**
     * §9.3 row 4, section 6.1 step 5: an assertion signed with a PrefixList naming a prefix the response declares is
     * verified where it arrived, the declaration in scope.
     */
    #[Test]
    public function itVerifiesTheAssertionWhereItArrived(): void
    {
        // Given
        $document = $this->document('behaviour/response-signed-both-prefix-list-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // When
        $assertion = SignedAssertion::of(
            $this->assertion($document),
            $response,
            self::identityProvider(),
            SamlLoader::create(),
        );

        // Then
        static::assertNotSame($response->verification?->document, $assertion->document);
    }

    /**
     * §9.3 row 4, dsig.md section 6.3: the same assertion verified inside the response's Verified::$document fails
     * its digest, the declaration its PrefixList names not rendered by the response's exclusive form; this is why
     * section 6.1 step 5 never verifies it there.
     */
    #[Test]
    public function theSameAssertionFailsInsideTheResponsesReParse(): void
    {
        // Given
        $document = $this->document('behaviour/response-signed-both-prefix-list-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        new Verifier(SamlLoader::create())->verify(
            Children::one($response->root, new Name(Saml::ASSERTION, 'Assertion')),
            MetadataFixtures::verificationKeys('idp'),
        );
    }

    /**
     * §9.3 row 23, M-2, section 6.7: a decrypted assertion that carries a signature is read from the verification of
     * that signature, made on the root of the document its decryption gave.
     */
    #[Test]
    public function itReadsADecryptedAssertionFromItsOwnVerification(): void
    {
        // Given
        $document = $this->document('encrypted/response-encrypted-signed-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
        $decrypted = self::decrypted($response);

        // When
        $assertion = SignedAssertion::decrypted($decrypted, $response, self::identityProvider(), SamlLoader::create());

        // Then
        static::assertTrue($assertion->signed);
        static::assertNotSame($decrypted->document, $assertion->document);
        static::assertSame('_assertion', Attributes::optional($assertion->document->root(), new Name(null, 'ID')));
    }

    /**
     * §9.3 row 24, M-1, M-2, section 6.7: a decrypted assertion without a signature is read from the document of its
     * decryption when the response's signature covered the ciphertext.
     */
    #[Test]
    public function itReadsAnUnsignedDecryptedAssertionWhoseCiphertextTheResponsesSignatureCovered(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
        $decrypted = self::decrypted($response);

        // When
        $assertion = SignedAssertion::decrypted($decrypted, $response, self::identityProvider(), SamlLoader::create());

        // Then
        static::assertFalse($assertion->signed);
        static::assertSame($decrypted->document, $assertion->document);
    }

    /**
     * §9.2 row 40, M-2, section 6.7: a decrypted assertion that no signature covers, its response unsigned, is refused:
     * anyone encrypts for the key of the service provider.
     */
    #[Test]
    public function itRefusesADecryptedAssertionNoSignatureCovers(): void
    {
        // Given
        $document = $this->document('encrypted/response-encrypted-unsigned-assertion-refused.xml');
        $response = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
        $decrypted = self::decrypted($response);

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).');

        // When
        SignedAssertion::decrypted($decrypted, $response, self::identityProvider(), SamlLoader::create());
    }

    /**
     * The plaintext of the one saml:EncryptedAssertion of $response, decrypted by Enc with the service provider's key.
     */
    private static function decrypted(SignedResponse $response): DecryptedAssertion
    {
        return DecryptedAssertion::of(new Decryptor(SamlLoader::create())->decrypt(
            Children::one(
                Children::one($response->root, new Name(Saml::ASSERTION, 'EncryptedAssertion')),
                new Name('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData'),
            ),
            self::decryptionKey(),
        ));
    }

    private function assertion(Document $document): Element
    {
        return Children::one($document->root(), new Name(Saml::ASSERTION, 'Assertion'));
    }
}
