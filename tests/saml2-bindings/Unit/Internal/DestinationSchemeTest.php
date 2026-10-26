<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Internal\DestinationScheme;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.3 step 1, section 6.4 step 1, RFC 3986 §3.1: the scheme of a Destination, read at its first byte, http or
 * https in letters of either case, followed by a colon, and nothing trimmed or normalised to find it.
 */
final class DestinationSchemeTest extends TestCase
{
    /**
     * §9.2 row 33, section 6.3 step 1: a Destination of the scheme http or https is a web location, whatever the case
     * of its letters (RFC 3986 §3.1).
     */
    #[Test]
    #[DataProvider('provideWebDestinations')]
    public function itAcceptsTheSchemesHttpAndHttpsInEitherCase(string $destination): void
    {
        // When
        $isWeb = DestinationScheme::isWeb($destination);

        // Then
        static::assertTrue($isWeb);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWebDestinations(): iterable
    {
        yield 'http' => ['http://peer.example.com/saml'];
        yield 'https' => ['https://peer.example.com/saml'];
        yield 'HTTP' => ['HTTP://peer.example.com/saml'];
        yield 'HTTPS' => ['HTTPS://peer.example.com/saml'];
        yield 'HtTpS' => ['HtTpS://peer.example.com/saml'];
        yield 'a colon and nothing else' => ['https:'];
        yield 'a query and a port' => ['http://peer.example.com:8443/saml?tenant=acme'];
    }

    /**
     * §9.2 row 33, section 6.3 step 1: a Destination of another scheme, or whose scheme is not found at its first
     * byte, is not a web location.
     */
    #[Test]
    #[DataProvider('provideOtherDestinations')]
    public function itRefusesEveryOtherScheme(string $destination): void
    {
        // When
        $isWeb = DestinationScheme::isWeb($destination);

        // Then
        static::assertFalse($isWeb);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherDestinations(): iterable
    {
        yield 'javascript' => ['javascript:alert(1)//'];
        yield 'JAVASCRIPT' => ['JAVASCRIPT:alert(1)//'];
        yield 'data' => ['data:text/html,<script>alert(1)</script>'];
        yield 'ftp' => ['ftp://peer.example.com/saml'];
        yield 'file' => ['file:///etc/passwd'];
        yield 'blob' => ['blob:https://peer.example.com/1b2c'];
        yield 'vbscript' => ['vbscript:msgbox(1)'];
        yield 'a scheme after a scheme' => ['javascript:https://peer.example.com/saml'];
        yield 'a longer scheme that starts with https' => ['httpsx://peer.example.com/saml'];
        yield 'a longer scheme that starts with http' => ['httpx://peer.example.com/saml'];
        yield 'a shorter scheme' => ['htt://peer.example.com/saml'];
        yield 'https with no colon' => ['https.peer.example.com/saml'];
        yield 'http with no colon' => ['http//peer.example.com/saml'];
        yield 'a network path' => ['//peer.example.com/saml'];
        yield 'a path' => ['/saml'];
        yield 'empty' => [''];
        yield 'a space before' => [' https://peer.example.com/saml'];
        yield 'a tab before' => ["\thttps://peer.example.com/saml"];
        yield 'a NUL before' => ["\0https://peer.example.com/saml"];
        yield 'a line feed inside the scheme' => ["ht\ntp://peer.example.com/saml"];
        yield 'a line feed after the scheme' => ["https\n://peer.example.com/saml"];
        yield 'a letter before' => ['xhttps://peer.example.com/saml'];
    }
}
