<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\RouterIdentityProviderEndpoints;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-4 and section 6.1 step 3: the endpoints of the SAML identity provider of a tenant are
 * the routes of the bundle under the origin of its issuer, never under the request that asked for them.
 */
final class RouterIdentityProviderEndpointsTest extends TestCase
{
    /**
     * S-4, section 6.1 step 3: the request came in on another host, scheme and port than the issuer names; every URL
     * of the identity provider is still under the origin of the issuer, never under the Host of the request.
     */
    #[Test]
    public function theHostOfTheRequestIsIgnored(): void
    {
        // Given
        $endpoints = new RouterIdentityProviderEndpoints(self::router('', new RequestContext('', 'GET', 'attacker.example', 'http', 8080)));

        // When
        $located = $endpoints->locate(self::tenant('https://op.example:8443'));

        // Then
        static::assertSame(
            ['https://op.example:8443/saml/metadata', 'https://op.example:8443/saml/sso', 'https://op.example:8443/saml/slo'],
            [$located->metadata, $located->singleSignOn, $located->singleLogout],
        );
    }

    /**
     * S-4, section 6.1 step 3: the routes are not mounted under the path of the issuer, so the entity ID it announces
     * would name a URL where nothing is served; a configuration fault, refused rather than announced.
     */
    #[Test]
    public function routesMountedElsewhereThanTheIssuerAreRefused(): void
    {
        // Given
        $endpoints = new RouterIdentityProviderEndpoints(self::router('/auth'));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The SAML metadata is served at "https://op.example/auth/saml/metadata" but the issuer "https://op.example" puts the identity provider under "https://op.example/saml/metadata": mount the routes of the bundle under the path of the issuer.');

        // When
        $endpoints->locate(self::tenant('https://op.example'));
    }

    private static function router(string $prefix, ?RequestContext $context = null): UrlGenerator
    {
        $routes = new RouteCollection();
        $routes->add(IdentityProviderRoutes::METADATA, new Route($prefix . IdentityProviderRoutes::METADATA_PATH));
        $routes->add(IdentityProviderRoutes::SINGLE_SIGN_ON, new Route($prefix . IdentityProviderRoutes::SINGLE_SIGN_ON_PATH));
        $routes->add(IdentityProviderRoutes::SINGLE_LOGOUT, new Route($prefix . IdentityProviderRoutes::SINGLE_LOGOUT_PATH));

        return new UrlGenerator($routes, $context ?? new RequestContext());
    }

    private static function tenant(string $issuer): Tenant
    {
        return new Tenant(Uuid::v7(), 'default', new Issuer($issuer), 'Test', new DateTimeImmutable('2026-10-19T10:00:00+00:00'));
    }
}
