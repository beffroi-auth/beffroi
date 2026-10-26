<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Encoding;

use Beffroi\Core\Domain\Encoding\Host;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class HostTest extends TestCase
{
    /**
     * RFC 3986 §3.2.2, RFC 1123 §2.1: a name for the DNS, an IPv4 address or an IPv6 literal between brackets.
     */
    #[Test]
    #[DataProvider('provideHosts')]
    public function aNameOrAnAddressIsAHost(string $host): void
    {
        // When / Then
        static::assertTrue(Host::isHost($host));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHosts(): iterable
    {
        yield 'a name' => ['rp.example'];
        yield 'a name in capitals' => ['RP.Example'];
        yield 'a name with a hyphen' => ['relying-party.example'];
        yield 'the A-label of a name outside ASCII (RFC 5890 §2.3.2.1)' => ['xn--bcher-kva.example'];
        yield 'an IPv4 address' => ['192.0.2.10'];
        yield 'an IPv6 literal' => ['[2001:db8::1]'];
        yield 'the IPv6 loopback' => ['[::1]'];
    }

    /**
     * RFC 3986 §3.2.2 admits these in a reg-name, and a Content-Security-Policy that names them is split or
     * misread: a ";" ends a directive, a "," a policy, whitespace a source (CSP Level 3 §2.2.1).
     */
    #[Test]
    #[DataProvider('provideWhatIsNoHost')]
    public function whatAPolicyWouldSplitIsNoHost(string $host): void
    {
        // When / Then
        static::assertFalse(Host::isHost($host));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoHost(): iterable
    {
        yield 'empty' => [''];
        yield 'a semicolon' => ['rp.example;sandbox'];
        yield 'a comma' => ['rp.example,sandbox'];
        yield 'a space' => ['rp.example sandbox'];
        yield 'a quote' => ["rp.example'"];
        yield 'a percent-encoded octet' => ['rp.example%3Bsandbox'];
        yield 'a name outside ASCII' => ['bücher.example'];
        yield 'a user before the name' => ['user@rp.example'];
        yield 'a port after the name' => ['rp.example:443'];
        yield 'an IPv6 literal without its brackets' => ['2001:db8::1'];
        yield 'a future IP literal (RFC 3986 §3.2.2)' => ['[v1.fe80::a+en1]'];
        yield 'a name then a line' => ["rp.example\nsandbox"];
    }
}
