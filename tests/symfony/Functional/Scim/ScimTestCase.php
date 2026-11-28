<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Scim;

use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use function preg_match;
use function sprintf;
use function str_replace;
use function str_starts_with;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouterInterface;

/**
 * A deployment whose environment switches SCIM (tests/symfony/config/config_test_scim.yml), off unless a test turns it
 * on before the kernel boots.
 */
abstract class ScimTestCase extends BrowserTestCase
{
    protected const string SWITCH = 'BEFFROI_TEST_SCIM';

    protected const string MEDIA_TYPE = 'application/scim+json';

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER[self::SWITCH], $_ENV[self::SWITCH]);
    }

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_scim',
        ];
    }

    /**
     * The routes of the module, each with a method it serves and a path it matches.
     *
     * @return iterable<string, array{string, string}>
     */
    protected static function scimRoutes(): iterable
    {
        foreach (self::service('router', RouterInterface::class)->getRouteCollection() as $name => $route) {
            if (! str_starts_with(self::string($name), 'beffroi_protocol_scim_') || $route->getDefault('_controller') === FailingController::class) {
                continue;
            }
            $methods = $route->getMethods();

            yield self::string($name) => [$methods === [] ? 'POST' : $methods[0], self::pathOf($route)];
        }
    }

    /**
     * RFC 7644 §3.12
     *
     * @return array<string, mixed>
     */
    protected static function scimError(Response $response, int $status): array
    {
        static::assertSame($status, $response->getStatusCode());
        static::assertSame(self::MEDIA_TYPE, $response->headers->get('Content-Type'));
        $error = self::json($response);
        static::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $error['schemas'] ?? null);
        static::assertSame((string) $status, $error['status'] ?? null);

        return $error;
    }

    private static function pathOf(Route $route): string
    {
        $path = $route->getPath();
        foreach ($route->compile()->getPathVariables() as $variable) {
            $value = '2819c223-7f76-453a-919d-413861904646';
            if (preg_match('#^(?:' . ($route->getRequirement(self::string($variable)) ?? '[^/]++') . ')$#', $value) !== 1) {
                static::fail(sprintf('The path of the route "%s" takes no identifier.', $route->getPath()));
            }
            $path = str_replace(sprintf('{%s}', self::string($variable)), $value, $path);
        }

        return $path;
    }
}
