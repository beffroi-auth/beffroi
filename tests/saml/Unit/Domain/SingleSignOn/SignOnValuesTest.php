<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleSignOn;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Domain\SingleSignOn\SignOnStatus;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md sections 5.3 and 6.4: the values single sign-on writes its answers from.
 */
final class SignOnValuesTest extends TestCase
{
    /**
     * S-15: an assertion is valid five minutes from its issue.
     */
    #[Test]
    public function aResponseIsValidFiveMinutes(): void
    {
        // Given
        $response = new SignOnResponse(
            'https://id.acme.example/saml/metadata',
            SignOnRequests::request(),
            new PersistentNameId('alice-at-sp'),
            [],
            'session',
            Fixtures::now(),
            Fixtures::now(),
        );

        // When / Then
        static::assertEquals(new DateTimeImmutable('2026-09-15T10:05:00+00:00'), $response->notOnOrAfter());
    }

    /**
     * Core §3.2.2.2: the top-level code of each failure.
     */
    #[Test]
    #[DataProvider('provideStatuses')]
    public function aFailureSitsUnderTheTopLevelCodeOfItsCause(SignOnStatus $status, string $topLevel): void
    {
        // When / Then
        static::assertSame($topLevel, $status->topLevel());
    }

    /**
     * @return iterable<string, array{SignOnStatus, string}>
     */
    public static function provideStatuses(): iterable
    {
        yield 'NoPassive' => [SignOnStatus::NoPassive, 'urn:oasis:names:tc:SAML:2.0:status:Responder'];
        yield 'NoAuthnContext' => [SignOnStatus::NoAuthnContext, 'urn:oasis:names:tc:SAML:2.0:status:Responder'];
        yield 'InvalidNameIDPolicy' => [SignOnStatus::InvalidNameIdPolicy, 'urn:oasis:names:tc:SAML:2.0:status:Requester'];
    }

    /**
     * S-16: a claim the user does not hold sends no attribute, so an attribute carries one value at least.
     */
    #[Test]
    public function anAttributeWithoutValueIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An attribute an assertion carries holds one value at least (spec/saml.md S-16).');

        // When
        new ReleasedAttribute('urn:oid:0.9.2342.19200300.100.1.3', AttributeNameFormat::Uri, 'mail', []);
    }
}
