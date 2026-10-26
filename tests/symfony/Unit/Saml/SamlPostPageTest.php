<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\SamlPostPage;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * beffroi/saml S-36: the origin of a URL a page of SAML names in its "form-action", the scheme, the host and the port
 * of CSP Level 3 §2.3.1, and nothing that would split the policy it is written into.
 */
final class SamlPostPageTest extends TestCase
{
    /**
     * CSP Level 3 §2.3.1: the scheme, the host and the port of a single logout service, its path left out.
     */
    #[Test]
    #[DataProvider('provideUrlsAndTheirOrigins')]
    public function theOriginOfAUrlIsItsSchemeItsHostAndItsPort(string $url, string $origin): void
    {
        // When / Then
        static::assertSame($origin, SamlPostPage::originOf($url));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUrlsAndTheirOrigins(): iterable
    {
        yield 'a name' => ['https://sp.example.org/saml/slo?x=1', 'https://sp.example.org'];
        yield 'a name and a port' => ['https://sp.example.org:8443/saml/slo', 'https://sp.example.org:8443'];
        yield 'an IPv6 literal' => ['https://[2001:db8::1]/saml/slo', 'https://[2001:db8::1]'];
    }

    /**
     * beffroi/saml S-36, the security review of 20 October 2026 (finding C-2): a URL whose origin is not a scheme, a
     * host and a port is refused rather than written into the header, where a ';' in its host would end the
     * directive and start one of its own, "sandbox" freezing the page. The reading of the metadata refuses such an
     * endpoint first (S-11): reaching this is a rule broken upstream, hence a LogicException.
     */
    #[Test]
    #[DataProvider('provideUrlsWithNoOrigin')]
    public function aUrlWithNoOriginIsRefused(string $url): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A page names an origin in its Content-Security-Policy as a scheme, a host and a port, and nothing else, which would be written into the header as it is (CSP Level 3 §2.3.1, beffroi/saml S-36).');

        // When
        SamlPostPage::originOf($url);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUrlsWithNoOrigin(): iterable
    {
        yield 'a host that carries a directive' => ['https://sp.example.org;sandbox/saml/slo'];
        yield 'a host that carries a second policy' => ['https://sp.example.org,sandbox/saml/slo'];
        yield 'a script' => ['javascript:fetch(document.cookie)'];
    }
}
