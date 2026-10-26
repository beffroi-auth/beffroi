<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Support\RecordingDecryptionKey;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Response\ResponseFixtures;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\CoveringSignatureRequired;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.7, section 6.1 steps 2 to 6, M-1, M-2, M-4, M-8, M-11: a response whose assertion is encrypted, read by a
 * validator built with the key of the service provider, the response's signature verified before any decryption, every
 * failure of the decryption Enc's own (SAML Core §2.3.4, §6.2; enc.md E-3). The responses are those xmlsec1 encrypted,
 * under tests/saml2-model/Fixture/encrypted/.
 */
final class ResponseValidatorDecryptionTest extends TestCase
{
    use ResponseFixtures;

    /**
     * §9.3 row 23, section 6.7, M-1: the signed assertion xmlsec1 encrypted in AES-GCM for the test key of the service
     * provider is read as the same assertion in clear, its own signature verified once it is decrypted.
     */
    #[Test]
    public function itReadsAnEncryptedAssertionAsTheSameAssertionInClear(): void
    {
        // Given
        $clear = $this->validator()->validate(
            $this->unverified('behaviour/response-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertEquals(
            [$clear->responseId, $clear->assertion, $clear->coverage],
            [$accepted->responseId, $accepted->assertion, $accepted->coverage],
        );
    }

    /**
     * §9.3 row 26, M-18, section 6.1 step 14: an assertion the model decrypted is said to have arrived encrypted, which the
     * consumer that requires a provider to encrypt reads (saml.md S-67).
     */
    #[Test]
    public function itSaysAnAssertionItDecryptedArrivedEncrypted(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertTrue($accepted->encrypted);
    }

    /**
     * §9.3 row 26, M-18: the same assertion in clear is said to have arrived in clear, whoever signed it.
     */
    #[Test]
    public function itSaysAnAssertionInClearArrivedInClear(): void
    {
        // Given
        $response = $this->unverified('behaviour/response-signed-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertFalse($accepted->encrypted);
    }

    /**
     * §9.3 row 24, M-1, M-2, section 6.7: an assertion encrypted without a signature, under a response xmlsec1 signed
     * over its ciphertext, is read from the document of its decryption, the response's signature covering it.
     */
    #[Test]
    public function itReadsAnUnsignedAssertionWhoseCiphertextTheResponsesSignatureCovered(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-accepted.xml');

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertSame(
            [SignatureCoverage::Response, '_response', '_assertion', '_7a2f4c1d9e'],
            [$accepted->coverage, $accepted->responseId, $accepted->assertion->id, $accepted->assertion->nameId->value],
        );
    }

    /**
     * §9.2 row 38, section 6.7, enc.md E-3: a ciphertext altered by one byte, a key that is not the one it was
     * encrypted for, and a tag truncated by one byte are refused with the one failure of Enc, whatever failed.
     *
     * @param 'idp'|'sp' $key
     */
    #[Test]
    #[DataProvider('provideCiphertextsTheKeyDoesNotOpen')]
    public function itRefusesWithOneErrorWhateverFailedInTheDecryption(string $fixture, string $key): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey($key)), self::expected());
    }

    /**
     * @return iterable<string, array{string, 'idp'|'sp'}>
     */
    public static function provideCiphertextsTheKeyDoesNotOpen(): iterable
    {
        yield 'a tampered ciphertext' => ['encrypted/response-encrypted-ciphertext-altered-refused.xml', 'sp'];
        yield 'a wrong key' => ['encrypted/response-encrypted-signed-assertion-accepted.xml', 'idp'];
        yield 'a truncated tag' => ['encrypted/response-encrypted-tag-truncated-refused.xml', 'sp'];
    }

    /**
     * §9.2 row 39, M-2, section 6.7, SAML Core §6.2: under a signed response, an altered ciphertext is refused by the
     * signature of the response, which is verified before any decryption: decrypted first, it would have failed as
     * DecryptionFailed.
     */
    #[Test]
    public function itVerifiesTheSignatureOfTheResponseBeforeAnyDecryption(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-ciphertext-altered-refused.xml');

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.2 row 40, M-2, section 6.7: an assertion encrypted without a signature, in an unsigned response, is covered by
     * nothing: anyone encrypts for the key of the service provider.
     */
    #[Test]
    public function itRefusesAnEncryptedAssertionNoSignatureCovers(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-unsigned-assertion-refused.xml');
        $message = 'Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).';

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.2 row 41, M-4, section 6.7: a plaintext that is not a saml:Assertion, a samlp:Response here, is refused,
     * whatever it holds.
     */
    #[Test]
    public function itRefusesAPlaintextThatIsNotAnAssertion(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-encrypted-not-an-assertion-refused.xml');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.2 row 42, section 6.7, M-8, M-10, SAML Profiles §4.1.4.2 as corrected by E17: the envelope of an unsigned
     * response, which needs nothing of the plaintext, is refused before any operation of the decryption key, the
     * Issuer E17 requires at step 2 and the rest of step 6 before the decryption.
     *
     * @param class-string<MessageRefused> $exception
     */
    #[Test]
    #[DataProvider('provideEnvelopesRefusedBeforeTheKey')]
    public function itRefusesTheEnvelopeBeforeAnyOperationOfTheKey(
        string $fixture,
        string $requestId,
        string $exception,
        string $message,
    ): void {
        // Given
        $response = $this->unverified($fixture);
        $key = $this->createMock(DecryptionKeyInterface::class);
        $key->expects($this->never())->method('unwrap');

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey($key), self::expected($requestId));
    }

    /**
     * @return iterable<string, array{string, string, class-string<MessageRefused>, string}>
     */
    public static function provideEnvelopesRefusedBeforeTheKey(): iterable
    {
        yield 'no Issuer of its own' => [
            'encrypted/response-encrypted-without-issuer-refused.xml',
            '_request',
            MalformedMessage::class,
            'The response holds a saml:EncryptedAssertion and has no saml:Issuer (M-8).',
        ];
        yield 'an answer to another request' => [
            'encrypted/response-encrypted-signed-assertion-accepted.xml',
            '_another-request',
            InResponseToMismatch::class,
            'The InResponseTo of the response is not the one the consumer expects (M-10).',
        ];
    }

    /**
     * §9.2 row 46, M-2, section 6.7, SAML Core §6.2: an assertion whose NameID was changed after it was signed,
     * encrypted for the key of the service provider, is refused by its own signature once decrypted, in an unsigned
     * response as under a response whose signature over the ciphertext holds.
     */
    #[Test]
    #[DataProvider('provideAssertionsChangedAfterSigning')]
    public function itRefusesADecryptedAssertionWhoseOwnSignatureFails(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DigestMismatch::class);
        $this->expectExceptionMessageIs('The claimed element is not what was signed (D-8).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAssertionsChangedAfterSigning(): iterable
    {
        yield 'in an unsigned response' => ['encrypted/response-encrypted-assertion-changed-after-signing-refused.xml'];
        yield 'under a signed response' => [
            'encrypted/response-signed-over-encrypted-assertion-changed-after-signing-refused.xml',
        ];
    }

    /**
     * §9.2 row 44, section 6.7, section 6.1 step 2, section 5.5: an identity provider given without a decryption key has
     * its encrypted assertion refused by name before any key is touched: under metadata that would refuse the signature of the response, the
     * refusal is still that one.
     */
    #[Test]
    public function itRefusesAnEncryptedAssertionWithoutADecryptionKey(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-accepted.xml');
        $message = 'The response holds a saml:EncryptedAssertion and the identity provider was given no key to decrypt it (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $response->document);

        // When
        $this->validator()->validate($response, self::identityProvider(key: 'sp'), self::expected());
    }

    /**
     * §9.2 row 45, section 5.8, enc.md E-5: what the reading model of Enc refuses, an xenc:EncryptedData that holds
     * nothing, passes as Enc refuses it.
     */
    #[Test]
    public function itLetsTheRefusalOfEncThroughAsItIs(): void
    {
        // Given
        $response = $this->unverified('hostile/response-encrypted-assertion-refused.xml');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('An EncryptedData holds exactly one EncryptionMethod (E-5).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * M-11, section 6.7: an assertion accepted encrypted is remembered under its issuer and its ID, so that the same
     * assertion in clear is a replay.
     */
    #[Test]
    public function itRemembersAnAssertionThatArrivedEncrypted(): void
    {
        // Given
        $replay = new InMemoryReplayGuard();
        $this->validator($replay)->validate(
            $this->unverified('encrypted/response-encrypted-signed-assertion-accepted.xml'),
            self::identityProvider()->withDecryptionKey(self::decryptionKey()),
            self::expected(),
        );
        $response = $this->unverified('behaviour/response-signed-assertion-accepted.xml');

        // Then
        $this->expectException(Replayed::class);
        $this->expectExceptionMessageIs('The assertion was already accepted from its issuer (M-11).');

        // When
        $this->validator($replay)->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * §9.3 row 25, section 6.7, enc.md E-15, decision 0013: the signed assertion xmlsec1 encrypted in aes128-cbc, and
     * in aes256-cbc under rsa-oaep-mgf1p with its DigestMethod of SHA-1, the shape of Entra and ADFS, in a response the
     * identity provider signed over the ciphertext, is read as the same assertion in clear: AES-CBC is opened under
     * the response's signature, verified before any decryption.
     */
    #[Test]
    #[DataProvider('provideCbcResponsesTheIdentityProviderSigned')]
    public function itReadsAnAssertionEncryptedInAesCbcUnderTheResponsesSignatureAsTheAssertionInClear(
        string $fixture,
    ): void {
        // Given
        $clear = $this->validator()->validate(
            $this->unverified('behaviour/response-signed-assertion-accepted.xml'),
            self::identityProvider(),
            self::expected(),
        );
        $response = $this->unverified($fixture);

        // When
        $accepted = $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());

        // Then
        static::assertEquals(
            [$clear->assertion, SignatureCoverage::AssertionAndResponse, '_response'],
            [$accepted->assertion, $accepted->coverage, $accepted->responseId],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcResponsesTheIdentityProviderSigned(): iterable
    {
        yield 'aes128-cbc' => ['encrypted/response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml'];
        yield 'aes256-cbc under rsa-oaep-mgf1p and its DigestMethod of SHA-1' => [
            'encrypted/response-signed-over-encrypted-assertion-aes256-cbc-accepted.xml',
        ];
    }

    /**
     * §9.2 row 47, section 6.7, M-2, enc.md E-15: an assertion encrypted in AES-CBC that no signature of the response
     * covers is refused by name before any key is touched: the assertion unsigned, the assertion signed inside the
     * ciphertext, where its signature covers nothing of it, and a valid signature of the identity provider over another
     * element, in samlp:Extensions, where nothing is verified.
     */
    #[Test]
    #[DataProvider('provideCbcResponsesNoSignatureOfTheResponseCovers')]
    public function itRefusesAesCbcThatNoSignatureOfTheResponseCoversBeforeAnyKeyIsTouched(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);
        $key = new RecordingDecryptionKey(self::decryptionKey());

        // When
        try {
            $this->validator()->validate($response, self::identityProvider()->withDecryptionKey($key), self::expected());
            static::fail('The validator opened AES-CBC that no signature of the response covers.');
        } catch (CoveringSignatureRequired $refusal) {
            // Then
            static::assertSame(
                [
                    'AES-CBC is decrypted only under a verified signature that covers the encrypted element (E-15).',
                    false,
                ],
                [$refusal->getMessage(), $key->asked],
            );
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcResponsesNoSignatureOfTheResponseCovers(): iterable
    {
        yield 'no signature at all' => ['encrypted/response-encrypted-aes128-cbc-unsigned-assertion-refused.xml'];
        yield 'the assertion\'s signature only, inside the ciphertext' => [
            'encrypted/response-encrypted-aes256-cbc-signed-assertion-refused.xml',
        ];
        yield 'a signature of another element' => [
            'encrypted/response-encrypted-aes128-cbc-signature-in-extensions-refused.xml',
        ];
    }

    /**
     * §9.2 row 48, section 6.7, enc.md E-3, E-16: under a signature of the response that holds, an AES-CBC ciphertext
     * altered before the identity provider signed it, its padding or its first block, fails as a key that is not the
     * one it was encrypted for: the one DecryptionFailed, whatever failed.
     *
     * @param 'idp'|'sp' $key
     */
    #[Test]
    #[DataProvider('provideCbcCiphertextsTheSignatureHoldsAndTheKeyDoesNotOpen')]
    public function itRefusesAnAlteredAesCbcCiphertextUnderAValidSignatureAsAWrongKey(string $fixture, string $key): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey($key)), self::expected());
    }

    /**
     * @return iterable<string, array{string, 'idp'|'sp'}>
     */
    public static function provideCbcCiphertextsTheSignatureHoldsAndTheKeyDoesNotOpen(): iterable
    {
        yield 'the count of the padding altered' => [
            'encrypted/response-signed-over-encrypted-assertion-aes128-cbc-padding-altered-refused.xml',
            'sp',
        ];
        yield 'the first block garbled' => [
            'encrypted/response-signed-over-encrypted-assertion-aes128-cbc-first-block-altered-refused.xml',
            'sp',
        ];
        yield 'a wrong key' => ['encrypted/response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml', 'idp'];
    }

    /**
     * §9.2 row 49, section 5.5, section 6.7, enc.md E-15: the aes128-cbc ciphertext of the identity provider A, intact,
     * in a response a second provider B signed with its own key, under its own Issuer, to the request sent to it, is
     * opened under the key given with B, which does not open it: the one failure, and the key given with A, which would
     * open it, is never asked. The consumer chooses the provider by the unverified Issuer, as section 5.4 says.
     */
    #[Test]
    public function itOpensAResponseWithTheKeyGivenWithTheProviderThatSignedItOnly(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml');
        $keyOfA = new RecordingDecryptionKey(self::decryptionKey());
        $keyOfB = new RecordingDecryptionKey(self::decryptionKey('sp-b'));
        $providers = [
            'https://idp.example.com/saml' => self::identityProvider()->withDecryptionKey($keyOfA),
            'https://idp-b.example.com/saml' => self::identityProvider('https://idp-b.example.com/saml', 'idp-b')->withDecryptionKey($keyOfB),
        ];

        // When
        try {
            $this->validator()->validate($response, $providers[$response->issuer ?? ''], self::expected());
            static::fail('The validator read the ciphertext of a provider under the signature of another.');
        } catch (DecryptionFailed $failure) {
            // Then
            static::assertSame(
                [DecryptionFailed::MESSAGE, true, false],
                [$failure->getMessage(), $keyOfB->asked, $keyOfA->asked],
            );
        }
    }

    /**
     * §9.2 row 50, M-2, section 6.7: an aes128-cbc ciphertext altered after the identity provider signed the response
     * is refused by the signature, before the key is asked anything.
     */
    #[Test]
    public function itRefusesAnAesCbcCiphertextAlteredAfterTheSignatureBeforeAskingTheKey(): void
    {
        // Given
        $response = $this->unverified('encrypted/response-signed-over-encrypted-assertion-aes128-cbc-ciphertext-altered-after-signing-refused.xml');
        $key = new RecordingDecryptionKey(self::decryptionKey());

        // When
        try {
            $this->validator()->validate($response, self::identityProvider()->withDecryptionKey($key), self::expected());
            static::fail('The validator accepted a ciphertext altered after the signature.');
        } catch (DigestMismatch $refusal) {
            // Then
            static::assertSame(
                ['The claimed element is not what was signed (D-8).', false],
                [$refusal->getMessage(), $key->asked],
            );
        }
    }

    /**
     * §9.2 row 51, section 6.7, enc.md E-16: under AES-CBC, in a response the identity provider signed over the
     * ciphertext, what the reading after the decryption refuses, the plaintext that is not an assertion, the assertion's
     * own signature, its Issuer, is the one failure of the decryption.
     */
    #[Test]
    #[DataProvider('provideCbcPlaintextsTheReadingRefuses')]
    public function itRefusesWhatTheReadingRefusesAfterAnAesCbcDecryptionAsTheOneFailure(string $fixture): void
    {
        // Given
        $response = $this->unverified($fixture);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->validator()->validate($response, self::identityProvider()->withDecryptionKey(self::decryptionKey()), self::expected());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCbcPlaintextsTheReadingRefuses(): iterable
    {
        yield 'a samlp:Response, not an assertion (M-4)' => [
            'encrypted/response-signed-over-encrypted-aes128-cbc-not-an-assertion-refused.xml',
        ];
        yield 'the assertion\'s own signature failing, its NameID changed after signing (M-2)' => [
            'encrypted/response-signed-over-encrypted-aes128-cbc-assertion-changed-after-signing-refused.xml',
        ];
        yield 'the assertion\'s Issuer another entity (M-8)' => [
            'encrypted/response-signed-over-encrypted-aes128-cbc-assertion-of-another-issuer-refused.xml',
        ];
    }

    /**
     * A response to the request $requestId, received at our assertion consumer service, for our entity ID.
     */
    private static function expected(string $requestId = '_request'): ExpectedResponse
    {
        return ExpectedResponse::toRequest($requestId, 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml');
    }

    /**
     * The validator of the service provider, its clock frozen at 2026-09-30T12:00:00Z, a second after the responses
     * were issued; the key that decrypts is given with the identity provider (section 5.5).
     */
    private function validator(InMemoryReplayGuard $replay = new InMemoryReplayGuard()): ResponseValidator
    {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
            $replay,
            new TimeBounds(),
        );
    }
}
