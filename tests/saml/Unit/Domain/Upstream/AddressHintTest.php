<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Upstream\AddressHint;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/saml.md S-68, section 7: the address a person gave the login page, carried to a provider that reads one in a
 * parameter of its single sign-on service whose name is a token of the query and none of the parameters of the binding.
 */
final class AddressHintTest extends TestCase
{
    /**
     * S-68, RFC 3986 §2.3, section 7: a name of one to 64 unreserved characters is the parameter of the address.
     */
    #[Test]
    #[DataProvider('provideParameters')]
    public function aNameOfUnreservedCharactersIsTheParameter(string $parameter): void
    {
        // When / Then
        static::assertSame($parameter, new AddressHint($parameter, new EmailAddress('alice@acme.example'))->parameter);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideParameters(): iterable
    {
        yield 'the one of Entra' => ['login_hint'];
        yield 'one character' => ['u'];
        yield 'every unreserved character' => ['AZaz09-._~'];
        yield 'sixty-four characters' => [str_repeat('h', 64)];
        yield 'a name that holds one of the binding' => ['SAMLRequestHint'];
    }

    /**
     * S-68, RFC 3986 §2.3, section 7: a name that is not one to 64 unreserved characters is refused.
     */
    #[Test]
    #[DataProvider('provideNamesThatAreNoToken')]
    public function aNameThatIsNoTokenIsRefused(string $parameter): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The parameter of the address is one to 64 unreserved characters of RFC 3986 (spec/saml.md S-68).');

        // When
        AddressHint::assertParameter($parameter);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatAreNoToken(): iterable
    {
        yield 'empty' => [''];
        yield 'sixty-five characters' => [str_repeat('h', 65)];
        yield 'an at sign' => ['login@hint'];
        yield 'a space' => ['login hint'];
        yield 'an equals sign' => ['login=hint'];
        yield 'an ampersand' => ['login&hint'];
        yield 'a percent-escape' => ['login%5Fhint'];
        yield 'a plus sign' => ['login+hint'];
        yield 'a slash' => ['login/hint'];
        yield 'a question mark' => ['login?hint'];
        yield 'a number sign' => ['login#hint'];
        yield 'a bracket' => ['login_hint[]'];
        yield 'a character outside ASCII' => ['indice_é'];
        yield 'a line feed after it' => ["login_hint\n"];
        yield 'a space before it' => [' login_hint'];
    }

    /**
     * S-68, bindings.md B-1: a parameter of the binding is refused, whatever its case, which a provider that reads its
     * query without regard to case would take for the parameter of the binding.
     */
    #[Test]
    #[DataProvider('provideParametersOfTheBinding')]
    public function aParameterOfTheBindingIsRefused(string $parameter): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The parameter of the address "' . $parameter . '" is a parameter of the binding (spec/saml.md S-68).');

        // When
        new AddressHint($parameter, new EmailAddress('alice@acme.example'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideParametersOfTheBinding(): iterable
    {
        yield 'SAMLRequest' => ['SAMLRequest'];
        yield 'SAMLResponse' => ['SAMLResponse'];
        yield 'SAMLEncoding' => ['SAMLEncoding'];
        yield 'RelayState' => ['RelayState'];
        yield 'SigAlg' => ['SigAlg'];
        yield 'Signature' => ['Signature'];
        yield 'RelayState in lower case' => ['relaystate'];
        yield 'SAMLRequest in another case' => ['samlRequest'];
        yield 'Signature in capitals' => ['SIGNATURE'];
    }

    /**
     * S-68, RFC 3986 §2.1: the hint goes into the query of the URL, after a "?" when it holds none and after a "&"
     * when it holds one, before its fragment, the address percent-encoded outside the unreserved characters.
     */
    #[Test]
    #[DataProvider('provideUrls')]
    public function theHintIsAppendedToTheQuery(string $address, string $url, string $hinted): void
    {
        // Given
        $hint = new AddressHint('login_hint', new EmailAddress($address));

        // When / Then
        static::assertSame($hinted, $hint->appendedTo($url));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideUrls(): iterable
    {
        yield 'a URL without a query' => [
            'alice@acme.example',
            'https://idp.acme.example/saml2',
            'https://idp.acme.example/saml2?login_hint=alice%40acme.example',
        ];
        yield 'a URL with a query' => [
            'alice@acme.example',
            'https://idp.acme.example/saml2?SAMLRequest=fZ&RelayState=r&SigAlg=s&Signature=t',
            'https://idp.acme.example/saml2?SAMLRequest=fZ&RelayState=r&SigAlg=s&Signature=t&login_hint=alice%40acme.example',
        ];
        yield 'a URL with a fragment' => [
            'alice@acme.example',
            'https://idp.acme.example/saml2#sign-in',
            'https://idp.acme.example/saml2?login_hint=alice%40acme.example#sign-in',
        ];
        yield 'a URL with a question mark in its fragment' => [
            'alice@acme.example',
            'https://idp.acme.example/saml2#sign-in?now',
            'https://idp.acme.example/saml2?login_hint=alice%40acme.example#sign-in?now',
        ];
        yield 'a URL with a query and a fragment' => [
            'alice@acme.example',
            'https://idp.acme.example/saml2?tenant=acme#sign-in',
            'https://idp.acme.example/saml2?tenant=acme&login_hint=alice%40acme.example#sign-in',
        ];
        yield 'an address with a plus sign' => [
            'alice+saml@acme.example',
            'https://idp.acme.example/saml2',
            'https://idp.acme.example/saml2?login_hint=alice%2Bsaml%40acme.example',
        ];
        yield 'an address with characters a query reads' => [
            'a&b=c#d@acme.example',
            'https://idp.acme.example/saml2',
            'https://idp.acme.example/saml2?login_hint=a%26b%3Dc%23d%40acme.example',
        ];
        yield 'an address with a local part outside ASCII' => [
            'zoé@acme.example',
            'https://idp.acme.example/saml2',
            'https://idp.acme.example/saml2?login_hint=zo%C3%A9%40acme.example',
        ];
        yield 'an address with a tilde' => [
            'alice~saml@acme.example',
            'https://idp.acme.example/saml2',
            'https://idp.acme.example/saml2?login_hint=alice~saml%40acme.example',
        ];
    }
}
