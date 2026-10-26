<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleSignOn;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-18, section 6.4 step 3: a request waiting for a login is written to its document and read back whole,
 * for ten minutes.
 */
final class SignOnRequestTest extends TestCase
{
    /**
     * S-18: what the browser's session keeps is the request whole, its RelayState byte for byte among it.
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function aRequestIsReadBackFromItsDocumentWhole(SignOnRequest $request): void
    {
        // When / Then
        static::assertEquals($request, SignOnRequest::fromDocument($request->toDocument()));
    }

    /**
     * @return iterable<string, array{SignOnRequest}>
     */
    public static function provideRequests(): iterable
    {
        yield 'every member' => [SignOnRequests::request(
            relayState: "a state with spaces, ~ and \u{e9}",
            forceAuthn: true,
            isPassive: true,
            nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            authnContextRequested: true,
            receivedAt: new DateTimeImmutable('2026-09-15T10:00:00.123456+00:00'),
        )];
        yield 'nothing optional' => [SignOnRequests::request(relayState: null)];
    }

    /**
     * Section 7: ten minutes after it was received.
     */
    #[Test]
    public function aRequestWaitsTenMinutes(): void
    {
        // When / Then
        static::assertEquals(new DateTimeImmutable('2026-09-15T10:10:00+00:00'), SignOnRequests::request()->expiresAt());
    }

    /**
     * S-18: a document that is not a request, edited by hand or written by something else, is refused.
     *
     * @param array<string, mixed> $change
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotOne')]
    public function aDocumentThatIsNotARequestIsRefused(array $change, string $message): void
    {
        // Given
        $document = [...SignOnRequests::request()->toDocument(), ...$change];

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        SignOnRequest::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotOne(): iterable
    {
        yield 'no service provider' => [['service_provider' => null], 'A request waiting for a login holds its member "service_provider".'];
        yield 'no ID' => [['id' => null], 'A request waiting for a login holds its member "id".'];
        yield 'no endpoint' => [['assertion_consumer_service' => null], 'A request waiting for a login holds its member "assertion_consumer_service".'];
        yield 'no ForceAuthn' => [['force_authn' => null], 'A request waiting for a login holds its member "force_authn".'];
        yield 'no IsPassive' => [['is_passive' => null], 'A request waiting for a login holds its member "is_passive".'];
        yield 'no word of the context' => [['authn_context_requested' => null], 'A request waiting for a login holds its member "authn_context_requested".'];
        yield 'no instant' => [['received_at' => null], 'A request waiting for a login holds its member "received_at".'];
        yield 'an instant that is not one' => [['received_at' => 'yesterday at noon-ish'], 'The member "received_at" is not when a request was received.'];
        yield 'a ForceAuthn written as a string' => [['force_authn' => 'true'], 'The member "force_authn" must be a boolean or absent.'];
        yield 'an empty service provider' => [
            ['service_provider' => ''],
            'A request names its service provider, its ID and where it is answered (spec/saml.md section 6.4 step 1).',
        ];
        yield 'an empty ID' => [['id' => ''], 'A request names its service provider, its ID and where it is answered (spec/saml.md section 6.4 step 1).'];
        yield 'an empty endpoint' => [
            ['assertion_consumer_service' => ''],
            'A request names its service provider, its ID and where it is answered (spec/saml.md section 6.4 step 1).',
        ];
    }

    /**
     * The receiving instant is kept to the microsecond, so that ForceAuthn compares a proof with the request itself.
     */
    #[Test]
    public function theInstantIsKeptToTheMicrosecond(): void
    {
        // Given
        $request = SignOnRequests::request(receivedAt: Fixtures::now()->modify('+250 milliseconds'));

        // When
        $read = SignOnRequest::fromDocument($request->toDocument());

        // Then
        static::assertSame('250000', $read->receivedAt->format('u'));
    }
}
