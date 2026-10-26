<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\RouterIdentityProviderEndpoints;
use Beffroi\Bundle\Saml\RouterServiceProviderEndpoints;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
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
 * beffroi/saml, spec/saml.md S-38, S-39 and section 6.9 step 3: the endpoints of the SAML service provider of a tenant
 * are the routes of the bundle under the origin of its issuer, never under the request that asked for them, and its
 * entity ID is its own.
 */
final class RouterServiceProviderEndpointsTest extends TestCase
{
    /**
     * S-39, section 6.9 step 3: the request came in on another host, scheme and port than the issuer names; the
     * metadata and the assertion consumer service are still under the origin of the issuer, and the entity ID is the
     * URL of the metadata.
     */
    #[Test]
    public function theHostOfTheRequestIsIgnored(): void
    {
        // Given
        $endpoints = self::endpoints('', null, new RequestContext('', 'GET', 'attacker.example', 'http', 8080));

        // When
        $located = $endpoints->locate(self::tenant('https://op.example:8443'));

        // Then
        static::assertSame(
            ['https://op.example:8443/saml/sp/metadata', 'https://op.example:8443/saml/sp/metadata', 'https://op.example:8443/saml/sp/acs'],
            [$located->entityId, $located->metadata, $located->assertionConsumerService],
        );
    }

    /**
     * S-38: the entity ID the deployment names is the one the service provider goes by.
     */
    #[Test]
    public function theEntityIdTheDeploymentNamesIsTheOneItGoesBy(): void
    {
        // Given
        $endpoints = self::endpoints('', 'urn:example:op:service-provider');

        // When
        $located = $endpoints->locate(self::tenant('https://op.example'));

        // Then
        static::assertSame('urn:example:op:service-provider', $located->entityId);
    }

    /**
     * S-38: an entity ID equal to the one of the identity provider, which an environment variable kept from the
     * compilation of the container, is refused at the first use of the service provider.
     */
    #[Test]
    public function theEntityIdOfTheIdentityProviderIsRefused(): void
    {
        // Given
        $endpoints = self::endpoints('', 'https://op.example/saml/metadata');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of the service provider of the tenant, "https://op.example/saml/metadata", is the one of its identity provider: each role is an entity of its own (spec/saml.md S-38).');

        // When
        $endpoints->locate(self::tenant('https://op.example'));
    }

    /**
     * S-38, M-6: an entity ID that is no URI of the model, which an environment variable kept from the compilation of
     * the container, is refused at the first use of the service provider rather than at the writer of its metadata.
     */
    #[Test]
    public function anEntityIdThatIsNoUriOfTheModelIsRefused(): void
    {
        // Given
        $endpoints = self::endpoints('', "https://op.example/saml\u{200B}sp");

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).');

        // When
        $endpoints->locate(self::tenant('https://op.example'));
    }

    /**
     * Section 6.9 step 3: the routes are not mounted under the path of the issuer, so the metadata would name a URL
     * where nothing is served; a configuration fault, refused rather than announced.
     */
    #[Test]
    public function routesMountedElsewhereThanTheIssuerAreRefused(): void
    {
        // Given
        $endpoints = self::endpoints('/auth');

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The SAML metadata of the service provider is served at "https://op.example/auth/saml/sp/metadata" but the issuer "https://op.example" puts it under "https://op.example/saml/sp/metadata": mount the routes of the bundle under the path of the issuer.');

        // When
        $endpoints->locate(self::tenant('https://op.example'));
    }

    /**
     * S-52, section 6.9 step 3: the route of the assertion consumer service mounted elsewhere than the issuer names it
     * would be announced where nothing answers; a configuration fault, refused rather than announced.
     */
    #[Test]
    public function anAssertionConsumerServiceMountedElsewhereThanTheIssuerIsRefused(): void
    {
        // Given
        $endpoints = self::endpoints('', acsPrefix: '/elsewhere');

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The assertion consumer service of the service provider is served at "https://op.example/elsewhere/saml/sp/acs" but the issuer "https://op.example" puts it under "https://op.example/saml/sp/acs": mount the routes of the bundle under the path of the issuer.');

        // When
        $endpoints->locate(self::tenant('https://op.example'));
    }

    private static function endpoints(
        string $prefix,
        ?string $entityId = null,
        ?RequestContext $context = null,
        ?string $acsPrefix = null,
    ): RouterServiceProviderEndpoints {
        $routes = new RouteCollection();
        $routes->add(ServiceProviderRoutes::METADATA, new Route($prefix . ServiceProviderRoutes::METADATA_PATH));
        $routes->add(
            ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE,
            new Route(($acsPrefix ?? $prefix) . ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE_PATH),
        );
        $identityProviderRoutes = new RouteCollection();
        $identityProviderRoutes->add(IdentityProviderRoutes::METADATA, new Route(IdentityProviderRoutes::METADATA_PATH));
        $identityProviderRoutes->add(IdentityProviderRoutes::SINGLE_SIGN_ON, new Route(IdentityProviderRoutes::SINGLE_SIGN_ON_PATH));
        $identityProviderRoutes->add(IdentityProviderRoutes::SINGLE_LOGOUT, new Route(IdentityProviderRoutes::SINGLE_LOGOUT_PATH));

        return new RouterServiceProviderEndpoints(
            new UrlGenerator($routes, $context ?? new RequestContext()),
            new RouterIdentityProviderEndpoints(new UrlGenerator($identityProviderRoutes, new RequestContext())),
            $entityId,
        );
    }

    private static function tenant(string $issuer): Tenant
    {
        return new Tenant(Uuid::v7(), 'default', new Issuer($issuer), 'Test', new DateTimeImmutable('2026-10-22T10:00:00+00:00'));
    }
}
