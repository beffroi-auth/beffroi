<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use function array_filter;
use function array_values;
use function base64_decode;
use function base64_encode;
use Closure;
use DateTimeImmutable;
use function explode;
use function hash;
use function hash_pbkdf2;
use App\Http\BrowserSession;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
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
use SensitiveParameter;
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
use Symfony\Component\DomCrawler\Form;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionFactoryInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Transport\InMemory\InMemoryTransport;
use Symfony\Component\Uid\Uuid;

abstract class BrowserTestCase extends DatabaseTestCase
{
    use ClockSensitiveTrait;

    /**
     * RFC 7636 §4.1
     */
    protected const string CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /**
     * Architecture §5.2
     */
    protected const string INTERACTION_POLICY = "frame-ancestors 'none'";

    protected KernelBrowser $browser;

    protected function setUp(): void
    {
        $this->browser = self::browser($this->configureContainer(), static::kernelOptions());
        // One kernel for the whole test, a reboot per request being much slower: services keep their state
        // between requests, as in production, and the recorded events span the whole test.
        $this->browser->disableReboot();
        new Filesystem()->remove([self::keyStorage(), self::metadataStorage()]);
    }

    /**
     * @return array<string, mixed>
     */
    protected static function kernelOptions(): array
    {
        return [];
    }

    /**
     * @return (Closure(ContainerInterface): void)|null
     */
    protected function configureContainer(): ?Closure
    {
        return null;
    }

    protected function tearDown(): void
    {
        // Before the parent shuts the kernel down, or reading the storage paths from the container boots it again.
        new Filesystem()->remove([self::keyStorage(), self::metadataStorage()]);
        parent::tearDown();
    }

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

    protected static function userWithPassword(string $username, string $password, PasswordAlgorithmInterface $algorithm = new Argon2id()): User
    {
        $user = self::user($username, $username . '-subject');
        $hash = match ($algorithm->name()) {
            Argon2id::NAME => self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->hash($password),
            Bcrypt::NAME => new PasswordHash(new Bcrypt(), password_hash($password, PASSWORD_BCRYPT, [
                'cost' => 4,
            ])),
            Pbkdf2Sha256::NAME => self::pbkdf2($algorithm, 'sha256', $password),
            Pbkdf2Sha512::NAME => self::pbkdf2($algorithm, 'sha512', $password),
            default => static::fail(sprintf('No fixture hashes with %s.', $algorithm->name())),
        };
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save(new PasswordCredential(Uuid::v7(), $user, $hash, self::now()));

        return $user;
    }

    /**
     * RFC 8018 §5.2
     *
     * As Keycloak stores one: the derived key and the salt in base64, the iterations beside them.
     *
     * @param non-falsy-string $digest
     */
    private static function pbkdf2(PasswordAlgorithmInterface $algorithm, string $digest, #[SensitiveParameter] string $password): PasswordHash
    {
        $salt = 'sixteen octets!!';

        return new PasswordHash($algorithm, base64_encode(hash_pbkdf2($digest, $password, $salt, 1000, 64, true)), [
            'salt' => base64_encode($salt),
            'iterations' => 1000,
        ]);
    }

    protected function signIn(User $user, ?DateTimeImmutable $establishedAt = null): AuthenticationSession
    {
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $session = self::session($managed, $establishedAt ?? self::currentSecond());
        $this->httpSession(static fn (SessionInterface $httpSession, BrowserSession $browser) => $browser->bind($httpSession, $session));

        return $session;
    }

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
     * Called again, it is a rotation: the key that signed starts retiring, this one signs (architecture §3.3).
     */
    protected static function signingKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    /**
     * The key the tenant publishes for encryption (RFC 7517 §4.2); called again, it is a rotation.
     */
    protected static function encryptionKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::ecdhEsA256Kw(), self::context());
    }

    protected static function stagedKey(): TenantKey
    {
        return self::staging()->stage(self::tenant(), Algorithms::rs256(), self::context());
    }

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
     * RFC 8292 §2
     */
    protected static function applicationServerKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::vapid(), self::context());
    }

    /**
     * RFC 7515 §4.1.4
     */
    protected static function kidOf(string $compactJws): string
    {
        $header = json_decode(self::base64UrlDecode(explode('.', $compactJws)[0]), true, 2, JSON_THROW_ON_ERROR);
        static::assertIsArray($header);

        return self::string($header['kid'] ?? null);
    }

    /**
     * The whole code flow of one client on the session the browser holds, consent included.
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
     * OIDC Core §3.1.2.1
     *
     * @param array<string, string|null> $parameters replace the defaults, null removing a parameter
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
     * Architecture §5.2
     */
    protected static function assertInteractionHeaders(Response $response, string $contentSecurityPolicy = self::INTERACTION_POLICY): void
    {
        static::assertSame('DENY', $response->headers->get('X-Frame-Options'));
        static::assertSame($contentSecurityPolicy, $response->headers->get('Content-Security-Policy'));
        static::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    protected function endSession(AuthenticationSession $session, SessionEnd $by = SessionEnd::User): void
    {
        $sessions = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class);
        $stored = $sessions->find($session->id) ?? static::fail('The session is gone.');
        $stored->end($by, self::currentSecond());
        $sessions->save($stored);
    }

    protected function readHttpSession(): SessionInterface
    {
        $httpSession = self::service('session.factory', SessionFactoryInterface::class)->createSession();
        $cookie = $this->sessionCookie($httpSession->getName()) ?? static::fail('The browser holds no session cookie.');
        $httpSession->setId($cookie->getValue());
        $httpSession->start();

        return $httpSession;
    }

    protected static function currentSecond(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . time());
    }

    /**
     * Posts as a browser does from another site: "Sec-Fetch-Site: cross-site", without the cookies that
     * "SameSite=Lax" or "Strict" keeps from it (RFC 6265bis), which the jar holds again afterwards.
     *
     * @param array<string, string|null> $server replaces the headers of a cross-site post, null removing one
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
     * @param array<string, string|null> $server replaces the headers of a cross-site post, null removing one
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

    protected function postedWithoutOriginOrReferer(Form $form): void
    {
        $this->browser->getHistory()->clear();
        $this->browser->submit(
            $form,
            [],
            [
                'HTTP_ORIGIN' => 'null',
            ],
        );
    }

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
     * Writes the HTTP session the browser presents on its next request.
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
        // The cookie the kernel set carries a domain, and a cookie with a domain wins over one without.
        $this->browser->getCookieJar()->set(
            new Cookie($httpSession->getName(), $httpSession->getId(), null, $cookie?->getPath() ?? '/', $cookie?->getDomain() ?? ''),
        );
    }

    /**
     * The events of that class since the test began, or since the last forgetEvents().
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
     * @return list<Envelope> what waits on the notifications lane, oldest first
     */
    protected static function queued(): array
    {
        return array_values(self::service('test.beffroi.notification_queue', InMemoryTransport::class)->all());
    }

    protected static function forgetEvents(): void
    {
        self::service(RecordingEventHandler::class, RecordingEventHandler::class)->forget();
    }
}
