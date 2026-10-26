<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;
use Beffroi\Saml\Domain\Metadata\IdentityProviderEndpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 6.1 steps 1 and 3: what the metadata of an identity provider says.
 */
final class IdentityProviderDescriptionTest extends TestCase
{
    private const string METADATA = 'https://id.acme.example/saml/metadata';

    /**
     * Section 6.1 step 3, Metadata §4.1: the entity ID is the URL of the metadata.
     */
    #[Test]
    public function itsEntityIdIsTheUrlOfItsMetadata(): void
    {
        // Given
        $description = new IdentityProviderDescription(self::endpoints(), [new Certificate('MIIBAA==')], true, 86_400);

        // When / Then
        static::assertSame(self::METADATA, $description->entityId());
    }

    /**
     * Section 6.1 step 1: metadata whose messages nothing verifies is not metadata to publish.
     */
    #[Test]
    public function itRefusesToDescribeAnIdentityProviderWithoutACertificate(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The metadata of an identity provider carries the certificate of a key at least (spec/saml.md section 6.1 step 1).');

        // When
        new IdentityProviderDescription(self::endpoints(), [], true, 86_400);
    }

    private static function endpoints(): IdentityProviderEndpoints
    {
        return new IdentityProviderEndpoints(self::METADATA, 'https://id.acme.example/saml/sso', 'https://id.acme.example/saml/slo');
    }
}
