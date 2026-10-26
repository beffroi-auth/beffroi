<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Saml\Domain\Metadata\EndpointLocation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-11: where the identity provider sends a browser for a service provider is an https URL on a host name
 * or an IP address, and nothing a form, a redirection or a Content-Security-Policy would read otherwise.
 */
final class EndpointLocationTest extends TestCase
{
    /**
     * S-11, the security review of 20 October 2026 (findings B-3, C-2, C-3): a location in clear, one that is no web
     * address at all, and one whose authority is not a host and a port are refused, the reg-name of RFC 3986 §3.2.2
     * admitting the ';' and the ',' that split a policy.
     */
    #[Test]
    #[DataProvider('provideRefusedLocations')]
    public function aLocationThatIsNotHttpsOnAHostIsRefused(string $location): void
    {
        // When / Then
        static::assertFalse(EndpointLocation::isHttpsOnAHost($location));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedLocations(): iterable
    {
        yield 'plain http' => ['http://sp.example.org/saml/acs'];
        yield 'a script' => ['javascript:fetch(document.cookie)'];
        yield 'a document of its own' => ['data:text/html,<form>'];
        yield 'a host that carries a directive' => ['https://sp.example.org;sandbox/slo'];
        yield 'a host that carries a second policy' => ['https://sp.example.org,sandbox/slo'];
        yield 'a host that carries a space' => ['https://sp.example.org sandbox/slo'];
        yield 'a host that carries a quote' => ["https://sp.example.org'/slo"];
        yield 'a user before the host' => ['https://attacker@sp.example.org/acs'];
        yield 'a user and a password before the host' => ['https://user:secret@sp.example.org/acs'];
        yield 'no host' => ['https:///acs'];
        yield 'a port that is not a number' => ['https://sp.example.org:https/acs'];
        yield 'an https lookalike scheme' => ['https+evil://sp.example.org/acs'];
        yield 'a relative reference' => ['//sp.example.org/acs'];
        yield 'a script that names an https URL' => ['javascript:https://sp.example.org/acs'];
    }

    /**
     * S-11: an https URL on a name, an IPv4 address or an IPv6 literal, with or without a port, its scheme in any case
     * (RFC 3986 §3.1), is where a browser may be sent.
     */
    #[Test]
    #[DataProvider('provideAcceptedLocations')]
    public function anHttpsLocationOnAHostIsAccepted(string $location): void
    {
        // When / Then
        static::assertTrue(EndpointLocation::isHttpsOnAHost($location));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedLocations(): iterable
    {
        yield 'a name and a path' => ['https://sp.example.org/saml/acs'];
        yield 'a name and a port' => ['https://sp.example.org:8443/saml/acs'];
        yield 'a name alone' => ['https://sp.example.org'];
        yield 'a name and a query' => ['https://sp.example.org?acs'];
        yield 'an IPv4 address' => ['https://192.0.2.10/acs'];
        yield 'an IPv6 literal and a port' => ['https://[2001:db8::1]:8443/acs'];
        yield 'the scheme in capitals' => ['HTTPS://SP.EXAMPLE.ORG/saml/acs'];
    }
}
