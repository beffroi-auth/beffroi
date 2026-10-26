<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use function array_filter;
use function base64_decode;
use function base64_encode;
use Closure;
use DateTimeImmutable;
use function explode;
use function hash;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function parse_str;
use function parse_url;
use const PASSWORD_BCRYPT;
use function password_hash;
use const PHP_URL_QUERY;
use function rtrim;
use function sprintf;
use function str_starts_with;
use function strtolower;
use function strtr;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionFactoryInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A browser on the test kernel (architecture §7), with what a flow needs: a user with a password, or a
 * user signed in without the form, that is a session of the core the browser is bound to the way the
 * login of the firewall binds it; an interaction this browser began; a signing key; the PKCE pair of a
 * client.
 */
abstract class BrowserTestCase extends DatabaseTestCase
{
    use ClockSensitiveTrait;

    /**
     * RFC 7636 §4.1: 43 to 128 unreserved characters.
     */
    protected const string CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /**
     * Architecture §5.2: the Content-Security-Policy every response of the interaction plane carries
     * unless the page builds one of its own.
     */
    protected const string INTERACTION_POLICY = "frame-ancestors 'none'";

    protected KernelBrowser $browser;

    protected function setUp(): void
    {
        $this->browser = self::browser($this->configureContainer(), static::kernelOptions());
        // One kernel for the whole test, where a KernelBrowser reboots one per request by default. A login
        // is ten requests and a reboot pays for the re-instantiation of everything the next one touches:
        // the functional suite is 213 s this way against 339 s rebooting, same 1 271 tests (issue #510).
        // What it changes for a test: a service keeps what it holds from one request to the next, which is
        // what the provider does in production, and the recorded events span the test instead of the last
        // request, so a fixture that raises some calls forgetEvents() before its act.
        $this->browser->disableReboot();
        new Filesystem()->remove(self::keyStorage());
    }

    /**
     * What the kernel behind the browser is booted with; nothing by default, which is a kernel that is
     * not in debug, as every test runs on.
     *
     * @return array<string, mixed>
     */
    protected static function kernelOptions(): array
    {
        return [];
    }

    /**
     * What a test replaces in the container behind its browser, on every boot; nothing by default.
     *
     * @return (Closure(ContainerInterface): void)|null
     */
    protected function configureContainer(): ?Closure
    {
        return null;
    }

    protected function tearDown(): void
    {
        // Before the parent, which shuts the kernel down: keyStorage() asks the container where it
        // writes, and a container that is down would be booted again just to answer.
        new Filesystem()->remove(self::keyStorage());
        parent::tearDown();
    }

    /**
     * The rows keep seconds: what the kernel dates from now on is dated the second after what it dated
     * so far, a login after the interaction it answers, a fresh login after the session it refreshes.
     * The clock of the kernel is the global clock of the process (Symfony\Component\Clock\Clock), which
     * the reboot the browser does between two requests keeps: the mock set here is what the next
     * request reads, and the trait restores the real clock after the test.
     */
    /**
     * The page a form of these pages comes back to (issue #481): every one of them answers with a
     * redirection a browser re-issues as a GET, so what a test reads after submitting is the page that
     * redirection names, and what was refused is on it.
     */
    protected function afterTheForm(): Crawler
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));

        return $this->browser->followRedirect();
    }

    protected static function aSecondLater(): void
    {
        self::mockTime(Clock::get()->now()->modify('+1 second'));
    }

    /**
     * A user who can sign in on the form: the password hashed by the hasher of the core, or by bcrypt
     * when the test wants a hash the policy of the core will want to replace.
     */
    protected static function userWithPassword(string $username, string $password, PasswordAlgorithmInterface $algorithm = new Argon2id()): User
    {
        $user = self::user($username, $username . '-subject');
        $hash = match ($algorithm->name()) {
            Argon2id::NAME => self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->hash($password),
            Bcrypt::NAME => new PasswordHash(new Bcrypt(), password_hash($password, PASSWORD_BCRYPT, [
                'cost' => 4,
            ])),
            default => static::fail(sprintf('No fixture hashes with %s.', $algorithm->name())),
        };
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save(new PasswordCredential(Uuid::v7(), $user, $hash, self::now()));

        return $user;
    }

    /**
     * Signs the user in without the form: a session of the core, and a fresh HTTP session bound to it,
     * whose cookie the browser now carries. The session is established now, by the clock the kernel
     * reads, not at the fixed moment of the fixtures: the kernel judges whether it is still active.
     */
    protected function signIn(User $user, ?DateTimeImmutable $establishedAt = null): AuthenticationSession
    {
        // the browser reboots the kernel between two requests: the user is read again from the rows
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $session = self::session($managed, $establishedAt ?? self::currentSecond());
        $this->httpSession(static fn (SessionInterface $httpSession, BrowserSession $browser) => $browser->bind($httpSession, $session));

        return $session;
    }

    /**
     * An interaction of the native client, begun by this browser, created at the given moment.
     */
    protected function beginInteraction(DateTimeImmutable $createdAt, DateTimeImmutable $expiresAt): Interaction
    {
        $request = new AuthorizationRequest(
            self::client('native-app'),
            new RedirectUri('http://127.0.0.1/callback'),
            new Scopes([Scope::openid(), new Scope('profile')]),
            new CodeChallenge(self::codeChallenge(), new Sha256CodeChallengeMethod()),
            'state-of-the-client',
            'nonce-of-the-client',
        );
        $interaction = new Interaction(Secrets::draw(), self::tenant(), $request, null, $createdAt, $expiresAt);
        self::service('test.beffroi.interactions', InteractionRepositoryInterface::class)->save($interaction);
        $this->httpSession(static fn (SessionInterface $httpSession, BrowserSession $browser) => $browser->begin($httpSession, $interaction));

        return $interaction;
    }

    /**
     * A key the tenant signs with, so that the token endpoint can answer. Called again, it is a rotation:
     * the key that signed starts retiring, this one signs (architecture §3.3).
     */
    protected static function signingKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    /**
     * The key the tenant publishes for encryption (RFC 7517 §4.2), which is what a client encrypts a
     * request object to. Called again, it is a rotation, as it is for a signing key.
     */
    protected static function encryptionKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::ecdhEsA256Kw(), self::context());
    }

    /**
     * A key published before it signs: the first half of a rotation.
     */
    protected static function stagedKey(): TenantKey
    {
        return self::staging()->stage(self::tenant(), Algorithms::rs256(), self::context());
    }

    /**
     * Out of the JWK Set before its retirement date: what an operator does after a compromise.
     */
    protected static function retireKey(TenantKey $key): void
    {
        self::service('test.beffroi.key_retirement', KeyRetirement::class)->retireBeforeItsDate(self::tenant(), $key->kid, self::context());
    }

    protected static function takeOver(): KeyTakeOver
    {
        return self::service('test.beffroi.key_take_over', KeyTakeOver::class);
    }

    protected static function staging(): KeyStaging
    {
        return self::service('test.beffroi.key_staging', KeyStaging::class);
    }

    /**
     * The application server key the tenant hands to a browser that subscribes (RFC 8292 §2). Drawn like
     * every other key of the tenant, and not published in its JWK Set.
     */
    protected static function applicationServerKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::vapid(), self::context());
    }

    /**
     * The "kid" a compact JWS names in its protected header (RFC 7515 §4.1.4).
     */
    protected static function kidOf(string $compactJws): string
    {
        $header = json_decode(self::base64UrlDecode(explode('.', $compactJws)[0]), true, 2, JSON_THROW_ON_ERROR);
        static::assertIsArray($header);

        return self::string($header['kid'] ?? null);
    }

    /**
     * The whole code flow of one client on the session the browser holds: the authorization request, the
     * consent when the client requires one, then the code exchanged for tokens. A client holds a token of
     * the session from there on (Back-Channel Logout 1.0 §2.6).
     */
    protected function signInClient(string $clientId, string $redirectUri, ?string $secret): void
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
        ]));
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        if (str_starts_with($location, '/consent?')) {
            $interaction = self::redirectedInteraction($this->browser->getResponse());
            $this->browser->submit($this->browser->request('GET', '/consent', [
                'interaction' => $interaction,
            ])->selectButton('Allow')->form());
        }
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail(sprintf('The client "%s" got no code.', $clientId));
        $parameters = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => self::CODE_VERIFIER,
        ];
        // the three authentication methods of the test kernel: a public client names itself and nothing else
        $server = [];
        if ($secret === null) {
            $parameters['client_id'] = $clientId;
        } elseif ($clientId === 'legacy-app') {
            $parameters['client_id'] = $clientId;
            $parameters['client_secret'] = $secret;
        } else {
            $server = [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ];
        }
        $this->browser->request('POST', '/token', $parameters, server: $server);
        static::assertIsString(self::json($this->browser->getResponse())['access_token'] ?? null, self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * The claims of a compact JWS, unverified: the test reads what the endpoint wrote.
     *
     * @return array<string, mixed>
     */
    protected static function claimsOf(string $compactJws): array
    {
        $claims = json_decode(self::base64UrlDecode(explode('.', $compactJws)[1]), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($claims);
        $members = [];
        foreach ($claims as $name => $value) {
            $members[(string) $name] = $value;
        }

        return $members;
    }

    private static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        static::assertIsString($decoded);

        return $decoded;
    }

    /**
     * A valid authorization request of a client of the test kernel (OIDC Core §3.1.2.1), as query
     * parameters; what is given replaces the defaults, null removes a parameter.
     *
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    protected static function authorizationParameters(string $clientId = 'native-app', array $parameters = []): array
    {
        $defaults = [
            'client_id' => $clientId,
            'redirect_uri' => $clientId === 'native-app' ? 'http://127.0.0.1/callback' : 'https://demo.test/login/check',
            'response_type' => 'code',
            'scope' => 'openid profile',
            'state' => 'state-of-the-client',
            'nonce' => 'nonce-of-the-client',
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'S256',
        ];
        $merged = [];
        foreach ($parameters + $defaults as $name => $value) {
            if ($value !== null) {
                $merged[$name] = $value;
            }
        }

        return $merged;
    }

    protected static function codeChallenge(): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '+/', '-_'), '=');
    }

    /**
     * The query parameters of the Location header of a redirection.
     *
     * @return array<string, string>
     */
    protected static function redirectedQuery(Response $response): array
    {
        $location = $response->headers->get('Location') ?? static::fail('The response is not a redirection.');
        $query = parse_url($location, PHP_URL_QUERY);
        static::assertIsString($query, sprintf('The location "%s" carries no query.', $location));
        parse_str($query, $parameters);
        $strings = [];
        foreach ($parameters as $name => $value) {
            static::assertIsString($value);
            $strings[(string) $name] = $value;
        }

        return $strings;
    }

    /**
     * The interaction identifier the Location header of a redirection to a page carries.
     */
    protected static function redirectedInteraction(Response $response): string
    {
        return self::redirectedQuery($response)['interaction'] ?? static::fail('The redirection names no interaction.');
    }

    /**
     * @return array<string, mixed>
     */
    protected static function json(Response $response): array
    {
        $content = $response->getContent();
        static::assertIsString($content);
        $decoded = json_decode($content, true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($decoded);
        $members = [];
        foreach ($decoded as $name => $value) {
            $members[(string) $name] = $value;
        }

        return $members;
    }

    protected static function string(mixed $value): string
    {
        static::assertIsString($value);

        return $value;
    }

    /**
     * Architecture §5.2: what every response of the interaction plane carries.
     *
     * @param string $contentSecurityPolicy what this page carries over the policy of the plane, which the
     *                                      two pages whose policy is part of a step of the protocol name
     *                                      in full (FormPostResponse, FrontChannelLogoutPage)
     */
    protected static function assertInteractionHeaders(Response $response, string $contentSecurityPolicy = self::INTERACTION_POLICY): void
    {
        static::assertSame('DENY', $response->headers->get('X-Frame-Options'));
        static::assertSame($contentSecurityPolicy, $response->headers->get('Content-Security-Policy'));
        static::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * The session ended on the rows, the way a logout, an administrator or another tab ends it: read
     * again through the repository, because the browser reboots the kernel between two requests and the
     * object the test holds is not the one the next request reads.
     */
    protected function endSession(AuthenticationSession $session, SessionEnd $by = SessionEnd::User): void
    {
        $sessions = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class);
        $stored = $sessions->find($session->id) ?? static::fail('The session is gone.');
        $stored->end($by, self::currentSecond());
        $sessions->save($stored);
    }

    /**
     * The HTTP session the browser holds, read from the storage of the kernel: what the firewall and the
     * bundle wrote in it.
     */
    protected function readHttpSession(): SessionInterface
    {
        $httpSession = self::service('session.factory', SessionFactoryInterface::class)->createSession();
        $cookie = $this->sessionCookie($httpSession->getName()) ?? static::fail('The browser holds no session cookie.');
        $httpSession->setId($cookie->getValue());
        $httpSession->start();

        return $httpSession;
    }

    /**
     * The real now, with the precision of a datetime column.
     */
    protected static function currentSecond(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . time());
    }

    /**
     * The session cookie the browser will send: the one the kernel set, which carries a domain, over the
     * one a test wrote without one before any request, once a login migrated the session behind it.
     */
    /**
     * What a browser sends when a page of another site posts a form here: "Sec-Fetch-Site: cross-site", and none of the
     * cookies of this provider that "SameSite=Lax" or "Strict" keeps from a cross-site post (RFC 6265bis, "SameSite"
     * cookies), the ones that say "SameSite=None" going with it. The cookies held back are given back afterwards, as the
     * browser still holds them.
     *
     * @param string $body the body as the other site encoded it, which the provider reads as it came
     * @param array<string, string|null> $server what replaces the headers of a cross-site post, null removing one
     */
    protected function postedFromAnotherSite(string $uri, string $body, array $server = []): void
    {
        $jar = $this->browser->getCookieJar();
        $heldBack = [];
        foreach ($jar->all() as $cookie) {
            if (strtolower((string) $cookie->getSameSite()) !== 'none') {
                $heldBack[] = $cookie;
                $jar->expire($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
            }
        }
        $this->postedFromAnotherSiteWithTheCookie($uri, $body, $server);
        foreach ($heldBack as $cookie) {
            $jar->set($cookie);
        }
    }

    /**
     * The same post from a browser that sends the cookies of this provider with it all the same, a browser that does
     * not apply "SameSite" or a cookie that does not say "Lax".
     *
     * @param string $body the body as the other site encoded it, which the provider reads as it came
     * @param array<string, string|null> $server what replaces the headers of a cross-site post, null removing one
     */
    protected function postedFromAnotherSiteWithTheCookie(string $uri, string $body, array $server = []): void
    {
        parse_str($body, $fields);
        $this->browser->request(
            'POST',
            $uri,
            $fields,
            [],
            array_filter(
                $server
                + [
                    'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
                    'HTTP_SEC_FETCH_SITE' => 'cross-site',
                ],
                static fn (?string $value): bool => $value !== null,
            ),
            $body,
        );
    }

    /**
     * The page of CrossSitePost submitted from the origin of the provider, with the cookies of the browser.
     */
    protected function postedAgain(): void
    {
        $this->browser->submit(
            $this->browser->getCrawler()->filter('form')->form(),
            [],
            [
                'HTTP_SEC_FETCH_SITE' => 'same-origin',
            ],
        );
    }

    private function sessionCookie(string $name): ?Cookie
    {
        $found = null;
        foreach ($this->browser->getCookieJar()->all() as $cookie) {
            if ($cookie->getName() === $name && ($found === null || $cookie->getDomain() !== '')) {
                $found = $cookie;
            }
        }

        return $found;
    }

    /**
     * Writes an HTTP session the browser will present on its next request, through the same session
     * factory and storage the kernel uses.
     *
     * @param callable(SessionInterface, BrowserSession): void $write
     */
    protected function httpSession(callable $write): void
    {
        $httpSession = self::service('session.factory', SessionFactoryInterface::class)->createSession();
        $cookie = $this->sessionCookie($httpSession->getName());
        if ($cookie !== null) {
            $httpSession->setId($cookie->getValue());
        }
        $httpSession->start();
        $write($httpSession, self::service('test.beffroi.browser_session', BrowserSession::class));
        $httpSession->save();
        // the cookie the kernel set carries a domain, and a cookie with a domain wins over one without
        $this->browser->getCookieJar()->set(
            new Cookie($httpSession->getName(), $httpSession->getId(), null, $cookie?->getPath() ?? '/', $cookie?->getDomain() ?? ''),
        );
    }

    /**
     * The events of a class that reached the event bus since the test began, or since the last
     * forgetEvents(). One kernel serves the whole test, so this is not the last request alone.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    protected static function events(string $class): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                $events[] = $event;
            }
        }

        return $events;
    }

    /**
     * Forgets what the fixture of a test raised, so that events() answers for its act alone. Under
     * "// Given", as its last statement.
     */
    protected static function forgetEvents(): void
    {
        self::service(RecordingEventHandler::class, RecordingEventHandler::class)->forget();
    }
}
