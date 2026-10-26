<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Saml\Domain\Upstream\AuthnContextMethods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-57, RFC 8176 §2, SAML Authentication Context §3.4: a login of an upstream identity provider proves a
 * federated assertion, and the method its class of authentication names exactly, nothing a class does not say.
 */
final class AuthnContextMethodsTest extends TestCase
{
    /**
     * @param list<string> $methods
     */
    #[Test]
    #[DataProvider('provideClasses')]
    public function aClassProvesTheMethodItNamesExactly(string $class, array $methods): void
    {
        // When / Then
        static::assertSame($methods, self::references(AuthnContextMethods::of($class)));
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function provideClasses(): iterable
    {
        yield 'Password' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:Password', ['fed', 'pwd']];
        yield 'PasswordProtectedTransport' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', ['fed', 'pwd']];
        yield 'Smartcard' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard', ['fed', 'sc']];
        yield 'TimeSyncToken' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken', ['fed', 'otp']];
        yield 'unspecified' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', ['fed']];
        yield 'X509, which names no method of RFC 8176 exactly' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:X509', ['fed']];
        yield 'a class of another vocabulary' => ['http://schemas.microsoft.com/claims/multipleauthn', ['fed']];
        yield 'a class in another case' => ['urn:oasis:names:tc:SAML:2.0:ac:classes:password', ['fed']];
    }

    /**
     * S-57: every method a login of an upstream identity provider may prove, each once, what the provider announces of
     * that login.
     */
    #[Test]
    public function everyMethodALoginMayProveIsAnnouncedOnce(): void
    {
        // When / Then
        static::assertSame(['fed', 'pwd', 'sc', 'otp'], self::references(AuthnContextMethods::everyProvable()));
    }

    /**
     * @param list<AuthenticationMethod> $methods
     *
     * @return list<string>
     */
    private static function references(array $methods): array
    {
        return array_map(static fn (AuthenticationMethod $method): string => $method->value, $methods);
    }
}
