<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

/**
 * Decision 0029, spec/saml.md S-44 and S-60: an e-mail domain an upstream provider answers for, a name of the DNS kept
 * in lower case, and the one reading of the domain of an address.
 */
final class EmailDomainTest extends TestCase
{
    /**
     * S-44, RFC 4343: a domain is read without regard to case and kept in lower case, so that two spellings are one.
     */
    #[Test]
    public function aDomainIsKeptInLowerCase(): void
    {
        // When / Then
        static::assertSame('acme.example', new EmailDomain('Acme.EXAMPLE')->value);
    }

    /**
     * S-44, RFC 1035 §2.3.4, RFC 1123 §2.1, RFC 5890 §2.3.2.1: a name of the DNS of two labels at least.
     */
    #[Test]
    #[DataProvider('provideDomains')]
    public function aNameOfTheDnsIsADomain(string $domain): void
    {
        // When / Then
        static::assertSame($domain, new EmailDomain($domain)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDomains(): iterable
    {
        yield 'two labels' => ['acme.example'];
        yield 'a subdomain' => ['eu.acme.example'];
        yield 'digits and hyphens' => ['a-1.2b.example'];
        yield 'an A-label' => ['xn--bcher-kva.example'];
        yield 'a label of 63 characters' => [str_repeat('a', 63) . '.example'];
        yield 'a name of 253 characters' => [self::longName(61)];
    }

    /**
     * S-44: what is no name of the DNS of two labels at least is refused.
     */
    #[Test]
    #[DataProvider('provideWhatIsNoDomain')]
    public function whatIsNoNameOfTheDnsIsRefused(string $domain): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            '"%s" is no e-mail domain: a name of the DNS of two labels at least, of letters, digits and hyphens, a name outside ASCII written as its A-label.',
            $domain,
        ));

        // When
        new EmailDomain($domain);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoDomain(): iterable
    {
        yield 'nothing' => [''];
        yield 'one label' => ['localhost'];
        yield 'an empty label' => ['acme..example'];
        yield 'a dot first' => ['.acme.example'];
        yield 'a dot last' => ['acme.example.'];
        yield 'a label of 64 characters' => [str_repeat('a', 64) . '.example'];
        yield 'a hyphen first in a label' => ['-acme.example'];
        yield 'a hyphen last in a label' => ['acme-.example'];
        yield 'an underscore' => ['ac_me.example'];
        yield 'a wildcard' => ['*.acme.example'];
        yield 'a name outside ASCII' => ['bücher.example'];
        // an A-label the IDNA does not read back: a domain no address could ever be of
        yield 'a broken A-label' => ['xn--a.example'];
        // UTS #46 §4.1: two hyphens at the third and fourth characters are an A-label's, or nothing
        yield 'two hyphens at the third and fourth characters' => ['ab--cd.example'];
        yield 'a name of 254 characters' => [self::longName(62)];
        yield 'an IPv4 address' => ['192.0.2.1'];
        yield 'an address' => ['alice@acme.example'];
        yield 'a port' => ['acme.example:443'];
        yield 'a space' => ['acme .example'];
        yield 'a line feed after it' => ["acme.example\n"];
    }

    /**
     * S-44, UTS #46: the domain of an address is written as a declared domain is, in lower case and as its A-label, the
     * part after the last "@" taken, so that it is compared with a declared domain as one.
     */
    #[Test]
    #[DataProvider('provideAddresses')]
    public function theDomainOfAnAddressIsWrittenAsADeclaredDomainIs(string $address, string $domain): void
    {
        // When / Then
        static::assertSame($domain, EmailDomain::ofAddress($address)->value);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAddresses(): iterable
    {
        yield 'in lower case already' => ['alice@acme.example', 'acme.example'];
        yield 'in capitals' => ['alice@Acme.EXAMPLE', 'acme.example'];
        yield 'a U-label' => ['alice@bücher.example', 'xn--bcher-kva.example'];
        yield 'a U-label in capitals' => ['alice@BÜCHER.example', 'xn--bcher-kva.example'];
        yield 'an A-label' => ['alice@xn--bcher-kva.example', 'xn--bcher-kva.example'];
        yield 'a sharp s, kept by the non-transitional processing' => ['alice@faß.example', 'xn--fa-hia.example'];
        yield 'the last "@"' => ['"alice@home"@acme.example', 'acme.example'];
        // the whole part after the "@": a subdomain is a domain of its own, and never its parent
        yield 'a subdomain' => ['alice@eu.acme.example', 'eu.acme.example'];
    }

    /**
     * S-44: an address without a domain after an "@" is refused, and never taken for an address of no federated
     * domain.
     */
    #[Test]
    #[DataProvider('provideAddressesWithoutADomain')]
    public function anAddressWithoutADomainIsRefused(string $address): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An address holds a domain after its "@".');

        // When
        EmailDomain::ofAddress($address);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddressesWithoutADomain(): iterable
    {
        yield 'no "@"' => ['alice.acme.example'];
        yield 'nothing after the "@"' => ['alice@'];
    }

    /**
     * S-44, UTS #46: a domain the IDNA cannot convert is refused, the address not named.
     */
    #[Test]
    #[DataProvider('provideDomainsTheIdnaRefuses')]
    public function aDomainTheIdnaCannotConvertIsRefused(string $address): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The domain of an address cannot be written as a name of the DNS by the IDNA of UTS #46.');

        // When
        EmailDomain::ofAddress($address);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDomainsTheIdnaRefuses(): iterable
    {
        yield 'an empty label' => ['alice@acme..example'];
        yield 'a broken A-label' => ['alice@xn--a.example'];
        yield 'an underscore' => ['alice@ac_me.example'];
        yield 'a wildcard' => ['alice@*.acme.example'];
    }

    /**
     * S-44: a domain the IDNA converts that is no name of the DNS of two labels at least is refused, the address not
     * named.
     */
    #[Test]
    #[DataProvider('provideDomainsTheRuleRefuses')]
    public function aDomainTheRuleRefusesOnceConvertedIsRefused(string $address): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The domain of an address is no name of the DNS of two labels at least.');

        // When
        EmailDomain::ofAddress($address);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDomainsTheRuleRefuses(): iterable
    {
        yield 'one label' => ['alice@localhost'];
        yield 'a final dot' => ['alice@acme.example.'];
    }

    /**
     * Three labels of 63 characters, then a last one of the length given.
     */
    private static function longName(int $last): string
    {
        return str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', $last);
    }
}
