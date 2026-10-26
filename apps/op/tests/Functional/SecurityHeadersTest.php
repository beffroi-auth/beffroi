<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use function base64_encode;
use Beffroi\Bundle\Http\BrowserPreferences;
use function hash;
use function implode;
use function parse_str;
use function parse_url;
use const PHP_URL_QUERY;
use function rtrim;
use function sprintf;
use function strtr;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Oidc\Domain\Authorization\FormPostResponse;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Nelmio\SecurityBundle\Test\SecurityHeadersAssertionsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * What this provider tells a browser to do with its answers (config/packages/nelmio_security.yaml,
 * config/packages/nelmio_cors.yaml, config/packages/framework.yaml).
 *
 * A scanner says what is true of a deployment today. What is here is what stays true of the next one: the
 * two planes do not carry the same cross-origin headers, the pages a relying party drives keep the opener
 * the protocol needs, and the endpoints a browser-based client calls are the only ones that answer CORS.
 */
final class SecurityHeadersTest extends BrowserTestCase
{
    use SecurityHeadersAssertionsTrait;

    /**
     * The origin of a client running in a page, which no walk of this suite registers: what is read below
     * is whether the endpoint answers a preflight at all, which it does before it knows the client.
     */
    private const string BROWSER_ORIGIN = 'https://client.example.com';

    /**
     * Whatever the plane, and whatever serves it: no sniffing of the content type (a JWK set read as a
     * script is a JWK set executed), no framing (RFC 9700 §4.15), and no referrer, an authorization request
     * carrying the client, the state and the scope in its query string.
     */
    #[Test]
    #[DataProvider('provideAnswersOfEveryPlane')]
    public function itSendsTheBaselineHeadersWhateverPlaneAnswers(string $path): void
    {
        // When
        $this->browser->request('GET', $path);

        // Then
        static::assertContentTypeOptions();
        static::assertFrameOptions('DENY');
        static::assertReferrerPolicy(['no-referrer']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAnswersOfEveryPlane(): iterable
    {
        yield 'the discovery document of the protocol plane' => ['/.well-known/openid-configuration'];
        yield 'a page of the interaction plane' => ['/login'];
        yield 'a script the bundle serves' => ['/passkey.js'];
    }

    /**
     * RFC 6797 §6.1: a year, every subdomain of the issuer, and the preload list.
     */
    #[Test]
    public function itAsksForHttpsForAYearIncludingTheSubdomainsOfTheIssuer(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertStrictTransportSecurity(maxAge: 31536000, includeSubDomains: true, preload: true);
    }

    /**
     * An answer of the protocol plane is JSON read by a program. CORP says who may embed it; COEP and COOP
     * describe a browsing context, which an answer that is not a document never has.
     */
    #[Test]
    public function itAnswersTheProtocolPlaneWithTheOneCrossOriginHeaderThatAppliesToIt(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertCrossOriginResourcePolicy('same-origin');
        static::assertFalse($this->browser->getResponse()->headers->has('Cross-Origin-Embedder-Policy'));
        static::assertFalse($this->browser->getResponse()->headers->has('Cross-Origin-Opener-Policy'));
    }

    /**
     * The one place in this configuration where a header is deliberately not written, and the protocol is
     * the reason: a client that opens the authorization request in a popup keeps the handle on it, and the
     * page it lands on keeps its opener. "same-origin" swaps the browsing context group on the way in and
     * severs both for good.
     *
     * Isolation is COOP and COEP together, so a group that cannot have the first is a group where the
     * second isolates nothing and only refuses things. Both are absent, and what answers is what a browser
     * does with neither.
     */
    #[Test]
    #[DataProvider('providePagesARelyingPartyDrives')]
    public function itLeavesTheOpenerOfThePagesARelyingPartyDrives(string $path): void
    {
        // When
        $this->browser->request('GET', $path);

        // Then
        $headers = $this->browser->getResponse()->headers;
        static::assertFalse($headers->has('Cross-Origin-Opener-Policy'), (string) $headers->get('Cross-Origin-Opener-Policy'));
        static::assertFalse($headers->has('Cross-Origin-Embedder-Policy'), (string) $headers->get('Cross-Origin-Embedder-Policy'));
        static::assertCrossOriginResourcePolicy('same-origin');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePagesARelyingPartyDrives(): iterable
    {
        yield 'the login an authorization request sends a browser to' => ['/login'];
        yield 'the authorization endpoint itself, answering a request it refuses' => ['/authorize'];
    }

    /**
     * Nobody opens a page of the account in a popup to carry a step of the protocol, so the three headers
     * hold together there and the document is cross-origin isolated: it owns its browsing context group,
     * nothing cross-origin sits in its process that did not ask to, and what a CPU speculates on in that
     * process is this provider's own. It is also what leaves a page opened from here no opener to navigate
     * back.
     */
    #[Test]
    public function itIsolatesThePagesOfTheAccount(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $this->browser->request('GET', '/account');

        // Then
        static::assertIsIsolated();
    }

    /**
     * CSP Level 3 §6.1: everything is refused and then one directive per kind of thing a page of this
     * deployment loads. Neither "unsafe-inline" nor "unsafe-eval" is one of them, the level 1 fallback that
     * would add the first being off.
     *
     * On a page of the interaction plane as well, which is the one place two policies meet: the bundle
     * gives every one of them the floor a deployment that configures nothing still needs, and that floor
     * gives way to this one (App\Http\DeploymentPolicyPrevails).
     */
    #[Test]
    #[DataProvider('provideAnswersTheDeploymentWritesThePolicyOf')]
    public function itRefusesEverythingItDoesNotName(string $path): void
    {
        // When
        $this->browser->request('GET', $path);

        // Then
        static::assertCspHeader(
            requiredDirectives: ['default-src', 'base-uri', 'script-src', 'style-src', 'form-action', 'frame-ancestors'],
            contains: ["default-src 'none'", "frame-ancestors 'none'", "script-src 'self'", "base-uri 'none'", "form-action 'self'"],
            notContains: ["'unsafe-inline'", "'unsafe-eval'"],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAnswersTheDeploymentWritesThePolicyOf(): iterable
    {
        yield 'the discovery document, which carries no policy of its own' => ['/.well-known/openid-configuration'];
        yield 'a page of the interaction plane, which carries the floor of its plane' => ['/login'];
        yield 'the authorization endpoint, answering a request it refuses' => ['/authorize'];
    }

    /**
     * The two pages whose policy is part of the protocol compute their own, and theirs is the one that is
     * sent: the page that posts the response of an authorization request to the redirect URI names the hash
     * of the one script that submits the form and the origin it posts to, and nothing else runs or loads
     * (OAuth 2.0 Form Post Response Mode §2, CSP Level 3 §6.6.2.2).
     */
    #[Test]
    public function itLeavesThePolicyOfAPageThatComputesItsOwn(): void
    {
        // When / Then
        static::assertStringStartsWith(
            "default-src 'none'; script-src 'sha256-",
            new FormPostResponse(
                new RedirectUri('https://client.example.com/callback'),
                ['code' => 'a-code', 'iss' => 'https://op.localhost'],
            )->contentSecurityPolicy(),
        );
    }

    /**
     * CSP Level 3 §6.1, §6.3.2: a page of the interaction plane that may send the browser to a client
     * names the origin of that client among the form targets of the policy this deployment writes
     * (Beffroi\Bundle\Http\FormTarget), a browser checking the directive over the whole redirect chain of
     * a submission and the last hop of that chain being the answer carried to the client.
     *
     * What is read here is the order of the two, which is what the page depends on: the policy of this
     * deployment is written on the answer, and the page that may answer a client completes the directive
     * it wrote. The pages themselves are walked by the suite of the bundle, on a kernel of their own.
     */
    #[Test]
    public function itNamesTheClientAPageMayAnswerAmongTheFormTargetsOfThePolicyItWrites(): void
    {
        // Given
        $request = Request::create('https://op.localhost/login?interaction=the-one-this-browser-began', server: ['HTTPS' => 'on']);
        new FormTarget()->mayEndAt($request, new RedirectUri('https://client.example.com/callback'));
        $response = new Response('a page of the interaction plane');

        // When
        self::service('event_dispatcher', EventDispatcherInterface::class)->dispatch(
            new ResponseEvent($this->browser->getKernel(), $request, HttpKernelInterface::MAIN_REQUEST, $response),
            KernelEvents::RESPONSE,
        );

        // Then
        static::assertStringContainsString(
            "form-action 'self' https://client.example.com;",
            (string) $response->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * Issue beffroi-auth/beffroi#584: the consent page extends the layout of this application, so it is
     * served the policy written here like every other page of the plane and not one of its own, which
     * would be a page served without the directives above. What it adds to that policy is read on the
     * page itself: the host serving the logo of the asking client in the "img-src", that client in the
     * "form-action", and nothing a client registers anywhere else.
     */
    #[Test]
    public function itServesTheConsentPageThePolicyOfThisDeploymentCompletedWithWhatThatPageAdds(): void
    {
        // Given
        $this->signIn(self::user());
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'consent-app',
            'redirect_uri' => 'https://consent.test/callback',
            'response_type' => 'code',
            'scope' => 'openid profile',
            'state' => 'state-of-the-client',
            'nonce' => 'nonce-of-the-client',
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'S256',
        ]);

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $this->interactionOfTheRedirection(),
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertCspHeader(
            requiredDirectives: ['default-src', 'base-uri', 'script-src', 'style-src', 'img-src', 'form-action', 'frame-ancestors'],
            contains: [
                "default-src 'none'",
                "img-src 'self' data: https://cdn.consent.test https://op.test",
                "form-action 'self' https://consent.test",
            ],
        );
    }

    /**
     * RFC 7636 §4.2 over the verifier of the walk above, which nothing ever presents: the authorization
     * endpoint refuses a request that carries no challenge (decision 0006) and the page under test is
     * reached before any token is asked for.
     */
    private static function codeChallenge(): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', true)), '+/', '-_'), '=');
    }

    /**
     * The interaction the authorization request began, read where the browser was sent (architecture
     * §4.3): the page of an interaction is reached with the identifier the redirection names and with no
     * other.
     */
    private function interactionOfTheRedirection(): string
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $query = [];
        parse_str((string) parse_url(self::string($response->headers->get('Location')), PHP_URL_QUERY), $query);
        $interaction = $query['interaction'] ?? null;
        static::assertIsString($interaction);

        return $interaction;
    }

    /**
     * A directive left out of the header falls back to the allow list of the specification and not to a
     * refusal, so the whole set is written and the two entries a passkey needs are what open, to this
     * origin and to no other (WebAuthn §5.9).
     */
    #[Test]
    public function itOpensTheCredentialApiToItsOwnOriginAndClosesTheRest(): void
    {
        // When
        $this->browser->request('GET', '/login');

        // Then
        $policy = $this->browser->getResponse()->headers->get('Permissions-Policy');
        static::assertIsString($policy);
        static::assertStringContainsString('publickey-credentials-get=(self)', $policy);
        static::assertStringContainsString('publickey-credentials-create=(self)', $policy);
        static::assertStringContainsString('camera=()', $policy);
        static::assertStringContainsString('payment=()', $policy);
    }

    /**
     * RFC 9700 §6.3: the endpoints a public client running in a page calls are the ones that answer a
     * preflight, and the answer names a star rather than the origin that asked, so that no cache in front
     * of this provider has to be told to vary on it. The credentials are never allowed, which is what makes
     * the star the right answer: a browser refuses the two together, and the session of this provider is
     * read on the pages of the interaction plane and on none of these.
     */
    #[Test]
    #[DataProvider('provideEndpointsABrowserBasedClientCalls')]
    public function itLetsABrowserReadTheAnswerOfTheEndpointsAClientInAPageCalls(string $path, string $method, string $headers, string $allowed): void
    {
        // When
        $this->preflight($path, $method, $headers);

        // Then
        $answer = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $answer->getStatusCode(), (string) $answer->getContent());
        static::assertSame('*', $answer->headers->get('Access-Control-Allow-Origin'));
        static::assertSame($allowed, $answer->headers->get('Access-Control-Allow-Methods'));
        static::assertFalse($answer->headers->has('Access-Control-Allow-Credentials'));
    }

    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function provideEndpointsABrowserBasedClientCalls(): iterable
    {
        yield 'the discovery document (OIDC Discovery section 4)' => ['/.well-known/openid-configuration', 'GET', '', 'GET'];
        yield 'the keys an ID token is verified with' => ['/jwks', 'GET', '', 'GET'];
        yield 'the token endpoint (RFC 6749 section 3.2)' => ['/token', 'POST', 'content-type, dpop', 'POST'];
        yield 'the claims of the person (OIDC Core section 5.3)' => ['/userinfo', 'GET', 'authorization, dpop', 'GET, POST'];
        yield 'the revocation of a token (RFC 7009 section 2)' => ['/revoke', 'POST', 'content-type, authorization', 'POST'];
        yield 'the pushed authorization request (RFC 9126 section 2)' => ['/par', 'POST', 'content-type, dpop', 'POST'];
    }

    /**
     * A browser arrives at the authorization endpoint by navigation, and a navigation is not subject to
     * CORS: a header on it would say nothing to anybody. The endpoints no browser reaches answer none
     * either, whatever a client holds.
     */
    #[Test]
    #[DataProvider('provideEndpointsNoBrowserReads')]
    public function itAnswersNoCorsWhereNoBrowserReadsTheAnswer(string $path, string $method): void
    {
        // When
        $this->preflight($path, $method, 'content-type');

        // Then
        static::assertFalse($this->browser->getResponse()->headers->has('Access-Control-Allow-Origin'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEndpointsNoBrowserReads(): iterable
    {
        yield 'the authorization endpoint, reached by a navigation' => ['/authorize', 'GET'];
        yield 'the introspection a resource server calls from its own process' => ['/introspect', 'POST'];
        yield 'the registration of a client' => ['/register', 'POST'];
        yield 'the device authorization request' => ['/device_authorization', 'POST'];
        yield 'the backchannel authentication request' => ['/backchannel_authentication', 'POST'];
    }

    /**
     * The one header of a provider that no bundle writes. The "__Host-" prefix is what makes the browser
     * check the three attributes rather than this provider hope for them, and "lax" is what a provider
     * cannot tighten: a browser arrives at the authorization endpoint by a cross-site navigation, and
     * "strict" would drop the cookie on it and ask whoever sent it to sign in again.
     *
     * What is read is the configuration the kernel booted with and not a Set-Cookie of a response, because
     * the session of this environment is held by the mock storage of symfony/http-foundation, which names
     * its own cookie whatever the configuration says (session.storage.factory.mock_file). The cookie the
     * test below reads is one this application writes itself.
     */
    #[Test]
    public function itCarriesTheSessionOfABrowserOnAHostPrefixedCookie(): void
    {
        // When
        $options = static::getContainer()->getParameter('session.storage.options');

        // Then
        static::assertIsArray($options);
        static::assertSame('__Host-beffroi_session', $options['name'] ?? null);
        static::assertTrue($options['cookie_secure'] ?? null);
        static::assertTrue($options['cookie_httponly'] ?? null);
        static::assertSame(Cookie::SAMESITE_LAX, $options['cookie_samesite'] ?? null);
        static::assertSame('/', $options['cookie_path'] ?? null);
        static::assertArrayNotHasKey('cookie_domain', $options);
    }

    /**
     * The preferences of the browser, which this application writes a slot of and names no cookie of its
     * own for (issue #573, App\Theme\ThemePreference): the same prefix and the same three attributes under
     * it, a preference being read from a browser like anything else.
     */
    #[Test]
    public function itKeepsThePreferencesOfABrowserOnAHostPrefixedCookieToo(): void
    {
        // When
        $this->browser->request('POST', '/theme', ['theme' => 'dark']);

        // Then
        $cookie = $this->cookieNamed(BrowserPreferences::COOKIE);
        static::assertTrue($cookie->isSecure());
        static::assertTrue($cookie->isHttpOnly());
        static::assertSame(Cookie::SAMESITE_LAX, $cookie->getSameSite());
        static::assertSame('/', $cookie->getPath());
        static::assertNull($cookie->getDomain());
    }

    /**
     * The request a browser sends before a call it is not allowed to make without asking (Fetch §3.2.3).
     *
     * @param string $headers the headers the call would carry, empty for a call that carries none of its
     *                        own: a header the endpoint does not allow is what the preflight refuses, and
     *                        asking for one nowhere near it would read as that refusal
     */
    private function preflight(string $path, string $method, string $headers): void
    {
        $this->browser->request('OPTIONS', $path, server: [
            'HTTP_ORIGIN' => self::BROWSER_ORIGIN,
            'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => $method,
        ] + ($headers === '' ? [] : ['HTTP_ACCESS_CONTROL_REQUEST_HEADERS' => $headers]));
    }

    private function cookieNamed(string $name): Cookie
    {
        $names = [];
        foreach ($this->browser->getResponse()->headers->getCookies() as $cookie) {
            if ($cookie->getName() === $name) {
                return $cookie;
            }
            $names[] = $cookie->getName();
        }

        static::fail(sprintf('The answer carries no "%s"; it set %s.', $name, $names === [] ? 'no cookie' : implode(', ', $names)));
    }
}
