<?php

declare(strict_types=1);

namespace App\Tests\Image;

use App\Kernel;
use function dirname;
use function file_get_contents;
use function preg_match;
use function preg_match_all;
use function preg_replace;
use const PREG_SET_ORDER;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_replace;
use Symfony\Component\Routing\RouterInterface;

/**
 * Decision 0026
 */
final class AccessLogKeepsNoValueTest extends TestCase
{
    private const string SECRET = 'the-value-a-reader-of-the-log-would-hold';

    #[Test]
    #[DataProvider('provideTheRoutesThatCarryAValue')]
    public function theValueInThePathOfARouteIsNotLogged(string $path): void
    {
        // Given
        $uri = str_replace('{value}', self::SECRET, preg_replace('/\{(?!value\})[a-z_]+\}/', '0193a3f2-7b6c-7d4e-8f00-123456789abc', $path) ?? $path);

        // When
        $logged = self::logged($uri);

        // Then
        static::assertStringNotContainsString(self::SECRET, $logged);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTheRoutesThatCarryAValue(): iterable
    {
        $kernel = new Kernel('prod', false);
        $kernel->boot();
        try {
            $router = $kernel->getContainer()->get('router');
            static::assertInstanceOf(RouterInterface::class, $router);
            foreach ($router->getRouteCollection()->all() as $name => $route) {
                if (preg_match('/\{value\}/', $route->getPath()) === 1) {
                    yield $name => [$route->getPath()];
                }
            }
        } finally {
            $kernel->shutdown();
        }
    }

    /**
     * OIDC Core §3.1.2.1, RFC 9101 §5, OpenID Connect RP-Initiated Logout 1.0 §2
     */
    #[Test]
    #[DataProvider('provideParameters')]
    public function theValueOfAParameterIsNotLogged(string $parameter): void
    {
        // When
        $logged = self::logged('/authorize?client_id=a-client&' . $parameter . '=' . self::SECRET . '&state=s');

        // Then
        static::assertSame('/authorize?client_id=REDACTED&' . $parameter . '=REDACTED&state=REDACTED', $logged);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideParameters(): iterable
    {
        yield 'a login hint' => ['login_hint'];
        yield 'an ID token hint' => ['id_token_hint'];
        yield 'a request object' => ['request'];
        yield 'a user code' => ['user_code'];
    }

    /**
     * spec/scim.md P-20, RFC 7644 §7.5.2
     */
    #[Test]
    public function theFilterOfAQueryOfScimIsNotLogged(): void
    {
        // When
        $logged = self::logged('/scim/v2/Users?filter=userName%20eq%20%22' . self::SECRET . '%22&startIndex=1&count=100');

        // Then
        static::assertSame('/scim/v2/Users?filter=REDACTED&startIndex=REDACTED&count=REDACTED', $logged);
    }

    #[Test]
    public function aPathWithoutAValueIsLoggedAsItIs(): void
    {
        // When / Then
        static::assertSame(
            '/account/passkeys/0193a3f2-7b6c-7d4e-8f00-123456789abc/name',
            self::logged('/account/passkeys/0193a3f2-7b6c-7d4e-8f00-123456789abc/name'),
        );
    }

    /**
     * The URI as the filter of the access log of the Caddyfile writes it, its replacements applied in their order.
     */
    private static function logged(string $uri): string
    {
        $caddyfile = (string) file_get_contents(dirname(__DIR__, 2) . '/frankenphp/Caddyfile');
        preg_match('/^\(access_log\) \{\n(.*?)^\}$/ms', $caddyfile, $snippet);
        preg_match_all('/^\s*regexp "([^"]+)" "([^"]+)"$/m', $snippet[1] ?? '', $replacements, PREG_SET_ORDER);
        static::assertNotSame([], $replacements, 'The access log of the Caddyfile replaces nothing.');
        foreach ($replacements as [, $pattern, $replacement]) {
            $uri = preg_replace('~' . $pattern . '~', $replacement, $uri) ?? $uri;
        }

        return $uri;
    }
}
