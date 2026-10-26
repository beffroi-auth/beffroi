<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/saml.md S-50: the RelayState of a request to an upstream identity provider is a reference, never empty and
 * within the 80 bytes of SAML Bindings §3.4.3 and §3.5.3.
 */
final class UpstreamAuthnRequestTest extends TestCase
{
    /**
     * S-50, SAML Bindings §3.4.3: a RelayState of 80 bytes is one.
     */
    #[Test]
    public function aRelayStateOfEightyBytesIsOne(): void
    {
        // When
        $request = self::request(str_repeat('a', 80));

        // Then
        static::assertSame(str_repeat('a', 80), $request->relayState);
    }

    /**
     * S-50: an empty RelayState, and one longer than 80 bytes, are no reference, a programming error.
     */
    #[Test]
    #[DataProvider('provideRelayStatesThatAreNoReference')]
    public function aRelayStateThatIsNoReferenceIsRefused(string $relayState): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The RelayState of a request to an upstream identity provider is a reference of 1 to 80 bytes (spec/saml.md S-50).');

        // When
        self::request($relayState);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRelayStatesThatAreNoReference(): iterable
    {
        yield 'empty' => [''];
        yield '81 bytes' => [str_repeat('a', 81)];
        yield '80 characters of 2 bytes' => [str_repeat('é', 80)];
    }

    private static function request(string $relayState): UpstreamAuthnRequest
    {
        return new UpstreamAuthnRequest(
            IdentityProviderDocuments::SIGNED,
            new ServiceProviderEndpoints(
                'https://id.acme.example/saml/sp/metadata',
                'https://id.acme.example/saml/sp/metadata',
                'https://id.acme.example/saml/sp/acs',
            ),
            false,
            $relayState,
            Fixtures::now(),
        );
    }
}
