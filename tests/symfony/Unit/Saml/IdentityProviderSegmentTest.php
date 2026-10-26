<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\IdentityProviderSegment;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * beffroi/saml, spec/saml.md S-65: the last segment of the URL of the metadata given to an upstream identity provider,
 * its entity ID in base64url without padding.
 */
final class IdentityProviderSegmentTest extends TestCase
{
    /**
     * S-65: the segment is the entity ID in the base64url of RFC 4648 §5, without padding, one segment of a path.
     */
    #[Test]
    public function theSegmentIsTheEntityIdInBase64Url(): void
    {
        // When / Then
        static::assertSame('aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8_aWQ9MQ', IdentityProviderSegment::of('https://idp.example/saml2/?id=1'));
    }

    /**
     * S-65: the entity ID is read back from the segment alone.
     */
    #[Test]
    public function theEntityIdIsReadBackFromTheSegment(): void
    {
        // When / Then
        static::assertSame('https://idp.example/saml2/?id=1', IdentityProviderSegment::entityIdOf('aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8_aWQ9MQ'));
    }

    /**
     * S-65: a segment that is not base64url, one that writes an entity ID otherwise than the one way, and one whose
     * value is no entity ID of M-6, name no provider.
     */
    #[Test]
    #[DataProvider('provideSegmentsOfNoProvider')]
    public function aSegmentThatIsNoEntityIdNamesNoProvider(string $segment): void
    {
        // When / Then
        static::assertNull(IdentityProviderSegment::entityIdOf($segment));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSegmentsOfNoProvider(): iterable
    {
        yield 'padded' => ['aHR0cHM6Ly9pZHAuZXhhbXBsZQ=='];
        yield 'the standard alphabet' => ['aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8/aWQ9MQ'];
        yield 'other trailing bits' => ['aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8_aWQ9MR'];
        yield 'not absolute' => [IdentityProviderSegment::of('idp.example')];
        yield 'empty' => [''];
    }
}
