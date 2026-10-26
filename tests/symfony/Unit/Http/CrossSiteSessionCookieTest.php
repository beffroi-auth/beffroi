<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\CrossSiteSessionCookie;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\LogoutChainCookie;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * beffroi/saml, spec/saml.md S-28, "The plane": the answer to a request of the interaction plane that a browser sent from
 * another site, by a method other than GET or HEAD and without the session cookie, carries no session cookie, and every
 * other cookie it was given; any other request keeps the session cookie its answer was given.
 */
final class CrossSiteSessionCookieTest extends TestCase
{
    /**
     * The name the storage of these tests gives the session.
     */
    private const string SESSION = 'MOCKSESSID';

    /**
     * S-28, S-32: the session cookie is taken off by its name, the cookie of a chain of logout, "SameSite=None", which
     * an answer posted from the site of a service provider moves on, left as it was given.
     */
    #[Test]
    public function theSessionCookieAloneIsTakenOff(): void
    {
        // Given
        $request = self::request('POST', 'cross-site');

        // When
        $response = self::answered($request, IdentityProviderRoutes::SINGLE_LOGOUT);

        // Then
        static::assertSame([LogoutChainCookie::NAME], self::namesOf($response));
    }

    /**
     * S-28, "The plane": a request a cookie set "SameSite=Lax" accompanies, or that says it does not come from another
     * site, or that a browser sent with the session cookie, keeps the session cookie of its answer; so does a request
     * outside the interaction plane.
     */
    #[Test]
    #[DataProvider('provideRequestsThatKeepTheirSessionCookie')]
    public function anyOtherRequestKeepsTheSessionCookie(Request $request, string $route): void
    {
        // When
        $response = self::answered($request, $route);

        // Then
        static::assertSame([self::SESSION, LogoutChainCookie::NAME], self::namesOf($response));
    }

    /**
     * @return iterable<string, array{Request, string}>
     */
    public static function provideRequestsThatKeepTheirSessionCookie(): iterable
    {
        yield 'a GET from another site' => [self::request('GET', 'cross-site'), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a HEAD from another site' => [self::request('HEAD', 'cross-site'), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post from the same site' => [self::request('POST', 'same-site'), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post that does not say where it came from' => [self::request('POST', null), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post from another site with the session cookie' => [self::request('POST', 'cross-site', true), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post from another site to the protocol plane' => [self::request('POST', 'cross-site'), 'beffroi_protocol_token'];
        yield 'a post from another site to a route of the application' => [self::request('POST', 'cross-site'), 'app_home'];
    }

    /**
     * S-28: a request of any method but GET and HEAD, from another site, without the session cookie, is one the cookie
     * did not accompany.
     */
    #[Test]
    #[DataProvider('provideMethodsLaxKeepsTheCookieFrom')]
    public function aRequestFromAnotherSiteWithoutTheCookieIsOneTheCookieDidNotAccompany(string $method): void
    {
        // When / Then
        static::assertTrue(CrossSiteSessionCookie::withheldFrom(self::request($method, 'cross-site')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMethodsLaxKeepsTheCookieFrom(): iterable
    {
        yield 'POST' => ['POST'];
        yield 'PUT' => ['PUT'];
        yield 'DELETE' => ['DELETE'];
    }

    /**
     * A request to the provider, with a session whose cookie it carries when $withTheCookie.
     */
    private static function request(string $method, ?string $site, bool $withTheCookie = false): Request
    {
        $request = Request::create(
            'https://op.test/saml/slo',
            $method,
            [],
            $withTheCookie ? [self::SESSION => 'held'] : [],
            [],
            $site === null ? [] : ['HTTP_SEC_FETCH_SITE' => $site],
        );
        $request->setSession(new Session(new MockArraySessionStorage(self::SESSION)));

        return $request;
    }

    /**
     * The answer of $route to $request, given the cookie of a session and the cookie of a chain of logout, once the
     * listener ran.
     */
    private static function answered(Request $request, string $route): Response
    {
        $request->attributes->set('_route', $route);
        $response = new Response();
        $response->headers->setCookie(Cookie::create(self::SESSION, 'started', 0, '/', null, true, true, false, Cookie::SAMESITE_LAX));
        $response->headers->setCookie(Cookie::create(LogoutChainCookie::NAME, 'secret', 0, '/', null, true, true, false, Cookie::SAMESITE_NONE));
        new CrossSiteSessionCookie()->onKernelResponse(new ResponseEvent(
            static::createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            $response,
        ));

        return $response;
    }

    /**
     * @return list<string>
     */
    private static function namesOf(Response $response): array
    {
        $names = [];
        foreach ($response->headers->getCookies() as $cookie) {
            $names[] = $cookie->getName();
        }

        return $names;
    }
}
