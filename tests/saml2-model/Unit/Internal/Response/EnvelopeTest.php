<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Response\Envelope;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 2, M-4, M-5, M-13: the structure of the envelope of a response, read before any key is touched.
 */
final class EnvelopeTest extends TestCase
{
    use AssertionFixtures;

    /**
     * M-4, section 6.1 step 2: a status of Success and its one assertion, the direct child of the element read.
     */
    #[Test]
    public function itKeepsTheStatusAndTheOneAssertion(): void
    {
        // Given
        $response = $this->document('behaviour/response-signed-both-accepted.xml')->root();

        // When
        $envelope = Envelope::of($response);

        // Then
        static::assertSame(
            [StatusCode::Success, Children::one($response, new Name(Saml::ASSERTION, 'Assertion'))],
            [$envelope->status->code, $envelope->assertion],
        );
    }

    /**
     * M-13, SAML Profiles §4.1.4.2: a failure holds no assertion.
     */
    #[Test]
    public function itKeepsTheStatusOfAFailureWithoutAssertion(): void
    {
        // Given
        $response = $this->document('behaviour/response-status-responder-authn-failed-refused.xml')->root();

        // When
        $envelope = Envelope::of($response);

        // Then
        static::assertSame([StatusCode::Responder, null], [$envelope->status->code, $envelope->assertion]);
    }

    /**
     * §9.2 rows 5, 6, 22 and 25, M-4, M-5, M-13: a child out of the order of the schema, an Issuer repeated, the
     * assertions the status forbids or more than one.
     */
    #[Test]
    #[DataProvider('provideMalformedEnvelopes')]
    public function itRefusesAMalformedEnvelope(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        Envelope::of($document->root());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        $order = 'The samlp:Response holds a child out of the order of the schema, or one it does not allow there (M-5).';
        yield 'the Status after the assertion' => ['hostile/response-status-after-assertion-refused.xml', $order];
        yield 'the ds:Signature before the Issuer' => ['hostile/response-signature-before-issuer-refused.xml', $order];
        yield 'two Issuer' => [
            'hostile/response-two-issuers-refused.xml',
            'The samlp:Response holds more than one saml:Issuer (M-4).',
        ];
        yield 'Responder with an assertion' => [
            'hostile/response-status-responder-with-assertion-refused.xml',
            'The samlp:Response has a status other than Success and holds a saml:Assertion or a saml:EncryptedAssertion (M-13).',
        ];
        yield 'Success without assertion' => [
            'hostile/response-success-without-assertion-refused.xml',
            'The samlp:Response has the status Success and holds no saml:Assertion or saml:EncryptedAssertion (M-13).',
        ];
        yield 'two assertions' => [
            'hostile/response-two-assertions-without-issuer-refused.xml',
            'The samlp:Response holds more than one saml:Assertion or saml:EncryptedAssertion (M-4).',
        ];
    }

    /**
     * §9.3 row 23, M-4, section 6.1 step 2, section 6.7: the one saml:EncryptedAssertion of a response of Success, kept
     * as its assertion and said to be encrypted, nothing decrypted yet.
     */
    #[Test]
    public function itKeepsAnEncryptedAssertion(): void
    {
        // Given
        $response = $this->document('encrypted/response-encrypted-signed-assertion-accepted.xml')->root();

        // When
        $envelope = Envelope::of($response);

        // Then
        static::assertSame(
            [Children::one($response, new Name(Saml::ASSERTION, 'EncryptedAssertion')), true],
            [$envelope->assertion, $envelope->encrypted],
        );
    }

    /**
     * M-4, section 6.1 step 2: an assertion in clear is not said to be encrypted.
     */
    #[Test]
    public function itSaysAnAssertionInClearIsNotEncrypted(): void
    {
        // Given
        $response = $this->document('behaviour/response-signed-assertion-accepted.xml')->root();

        // When
        $envelope = Envelope::of($response);

        // Then
        static::assertFalse($envelope->encrypted);
    }

    /**
     * §9.2 rows 42 and 43, M-4, M-5, M-8, M-13, section 6.7, SAML Profiles §4.1.4.2 as corrected by E17: a
     * saml:EncryptedAssertion holding no xenc:EncryptedData or two, two of them, one next to a saml:Assertion or in a
     * failure, and a response holding one without its own Issuer, refused before any key is touched.
     */
    #[Test]
    #[DataProvider('provideMalformedEncryptedAssertions')]
    public function itRefusesAMalformedEncryptedAssertion(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        Envelope::of($document->root());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedEncryptedAssertions(): iterable
    {
        yield 'no xenc:EncryptedData' => [
            'encrypted/response-encrypted-assertion-empty-refused.xml',
            'The saml:EncryptedAssertion holds no xenc:EncryptedData (M-4).',
        ];
        yield 'two xenc:EncryptedData' => [
            'encrypted/response-encrypted-assertion-two-encrypted-data-refused.xml',
            'The saml:EncryptedAssertion holds more than one xenc:EncryptedData (M-4).',
        ];
        yield 'two saml:EncryptedAssertion' => [
            'encrypted/response-encrypted-two-encrypted-assertions-refused.xml',
            'The samlp:Response holds more than one saml:Assertion or saml:EncryptedAssertion (M-4).',
        ];
        yield 'next to a saml:Assertion' => [
            'encrypted/response-encrypted-next-to-an-assertion-refused.xml',
            'The samlp:Response holds more than one saml:Assertion or saml:EncryptedAssertion (M-4).',
        ];
        yield 'in a failure' => [
            'encrypted/response-encrypted-in-a-failure-refused.xml',
            'The samlp:Response has a status other than Success and holds a saml:Assertion or a saml:EncryptedAssertion (M-13).',
        ];
        yield 'a response without its own Issuer' => [
            'encrypted/response-encrypted-without-issuer-refused.xml',
            'The response holds a saml:EncryptedAssertion and has no saml:Issuer (M-8).',
        ];
    }

    /**
     * §9.2 row 44, section 6.7, enc.md section 12: an xenc:EncryptedKey next to the xenc:EncryptedData, the sibling
     * form, refused by name before any key is touched.
     */
    #[Test]
    public function itRefusesAnEncryptedKeyNextToTheEncryptedData(): void
    {
        // Given
        $document = $this->document('encrypted/response-encrypted-key-as-a-sibling-refused.xml');
        $message = 'The saml:EncryptedAssertion holds an xenc:EncryptedKey next to its xenc:EncryptedData, a form the package does not support (section 6.7).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        Envelope::of($document->root());
    }
}
