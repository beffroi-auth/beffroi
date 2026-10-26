<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7592: what decision 0009 promises every dynamic client. The registration hands it a
 * "registration_access_token" and a "registration_client_uri", and at that URI it reads itself, replaces
 * itself and deletes itself, with that token and with nothing else.
 */
final class ClientConfigurationTest extends BrowserTestCase
{
    private const string INITIAL_ACCESS_TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * What the registration answered: the client, its secret, its registration access token and the URI it
     * reads itself at.
     *
     * @var array<string, mixed>
     */
    private array $registered = [];

    protected function setUp(): void
    {
        parent::setUp();
        // one token worth two registrations: this client, and the one whose URI its token must not read
        $this->issue();
        $this->registered = $this->register();
    }

    /**
     * RFC 7591 §3.2.1: the two members that make RFC 7592 usable at all, handed out once.
     */
    #[Test]
    public function theRegistrationHandsOutTheTokenAndTheUriOfTheClient(): void
    {
        // Then
        static::assertIsString($this->registered['registration_access_token']);
        static::assertSame(
            'https://op.test/register/' . self::string($this->registered['client_id']),
            $this->registered['registration_client_uri'],
        );
    }

    /**
     * RFC 7592 §2.1: the registration as the provider holds it.
     */
    #[Test]
    public function aClientReadsWhatItRegistered(): void
    {
        // When
        $this->send('GET');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $read = self::json($response);
        static::assertSame($this->registered['client_id'], $read['client_id']);
        static::assertSame([self::REDIRECT_URI], $read['redirect_uris']);
    }

    /**
     * The secret was answered once, at the registration, and what the row keeps of it is a hash nobody
     * reads back.
     */
    #[Test]
    public function aClientThatReadsItselfIsAnsweredNoSecret(): void
    {
        // When
        $this->send('GET');

        // Then
        static::assertArrayNotHasKey('client_secret', self::json($this->browser->getResponse()));
    }

    /**
     * RFC 7592 §2.3: the provider must refuse a token that belongs to another client, and decision 0006
     * makes that refusal the one a token nobody issued gets.
     */
    #[Test]
    #[DataProvider('provideUnauthorizedRequests')]
    public function aRequestThatReadsNoClientIsRefusedTheSameWay(string $method, bool $ofAnotherClient, bool $withoutAToken): void
    {
        // Given
        $token = $withoutAToken ? null : self::string($this->registered['registration_access_token']);
        $uri = $ofAnotherClient ? $this->anotherClient() : self::string($this->registered['registration_client_uri']);

        // When
        $this->browser->request($method, $uri, server: $this->headers($token));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('invalid_token', self::json($response)['error']);
        static::assertStringStartsWith('Bearer error="invalid_token"', self::string($response->headers->get('WWW-Authenticate')));
    }

    /**
     * @return iterable<string, array{string, bool, bool}>
     */
    public static function provideUnauthorizedRequests(): iterable
    {
        yield 'a read with no token at all' => ['GET', false, true];

        yield 'a read with the token of another client' => ['GET', true, false];

        yield 'a replacement with no token at all' => ['PUT', false, true];

        yield 'a replacement with the token of another client' => ['PUT', true, false];

        yield 'a deletion with no token at all' => ['DELETE', false, true];

        yield 'a deletion with the token of another client' => ['DELETE', true, false];
    }

    /**
     * RFC 7592 §2.2: an update is whole and never a patch.
     */
    #[Test]
    public function aMemberLeftOutOfAReplacementIsAMemberTheClientNoLongerRegisters(): void
    {
        // Given
        $clientId = self::string($this->registered['client_id']);

        // When
        $this->send('PUT', [
            'client_id' => $clientId,
            'client_secret' => self::string($this->registered['client_secret']),
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => 'openid profile',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertArrayNotHasKey('client_name', self::json($response));
        self::reload();
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId);
        static::assertSame($clientId, $client?->registration->presentation->name);
    }

    /**
     * RFC 7592 §2.2: the request names the client it is for, and it carries nothing the provider assigned.
     */
    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideRefusedReplacements')]
    public function aReplacementThatReachesWhatItMayNotIsRefused(array $members, string $named): void
    {
        // When
        $this->send(
            'PUT',
            $members
            + [
                'client_id' => $this->registered['client_id'],
                'redirect_uris' => [self::REDIRECT_URI],
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), self::string($response->getContent()));
        $refusal = self::json($response);
        static::assertSame('invalid_client_metadata', $refusal['error']);
        static::assertStringContainsString($named, self::string($refusal['error_description']));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideRefusedReplacements(): iterable
    {
        yield 'a request that names another client' => [
            [
                'client_id' => 'a-client-of-somebody-else',
            ],
            'names itself',
        ];

        yield 'a request that carries the date the identifier was drawn on' => [
            [
                'client_id_issued_at' => 1_790_000_000,
            ],
            'client_id_issued_at',
        ];

        yield 'a request that carries the URI it reads itself at' => [
            [
                'registration_client_uri' => 'https://op.test/register/somewhere-else',
            ],
            'registration_client_uri',
        ];

        yield 'a request that carries a scope the tenant hands out no token for' => [
            [
                'scope' => 'openid billing.read',
            ],
            'billing.read',
        ];

        yield 'a request that moves the front-channel logout URI to a host that carries a directive of a policy' => [
            [
                'frontchannel_logout_uri' => 'https://registered.test;sandbox/frontchannel-logout',
            ],
            'must name a host of letters, digits, hyphens and dots, or an IP address',
        ];
    }

    /**
     * RFC 7592 §2.2: the request names the client it is for, and a request that names none names another.
     */
    #[Test]
    public function aReplacementThatNamesNoClientIsRefused(): void
    {
        // When
        $this->send('PUT', [
            'redirect_uris' => [self::REDIRECT_URI],
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('names itself', self::string(self::json($response)['error_description']));
    }

    /**
     * RFC 7591 §3.1: a body that is no JSON object carries no metadata at all, and a caller that reads no
     * client is told that first, rather than what it sent.
     */
    #[Test]
    public function aBodyThatIsNoJsonObjectIsRefusedAfterTheTokenIsRead(): void
    {
        // When
        $this->browser->request(
            'PUT',
            self::string($this->registered['registration_client_uri']),
            server: $this->headers(
                self::string($this->registered['registration_access_token']),
            ),
            content: 'not a JSON object',
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame(
            'The body of a registration request is a JSON object (RFC 7591 section 3.1).',
            self::json($response)['error_description'],
        );
    }

    /**
     * RFC 7592 §2.2: a client may echo back the secret it holds, and no other.
     */
    #[Test]
    public function aSecretThatIsNotTheClientOwnIsRefused(): void
    {
        // When
        $this->send('PUT', [
            'client_id' => $this->registered['client_id'],
            'client_secret' => 'a-secret-of-somebody-else-of-at-least-32-characters',
            'redirect_uris' => [self::REDIRECT_URI],
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('is not the secret it holds', self::string(self::json($response)['error_description']));
    }

    /**
     * RFC 7592 §2.3: a 204 and nothing to answer.
     */
    #[Test]
    public function aClientThatDeletesItselfIsGone(): void
    {
        // Given
        $clientId = self::string($this->registered['client_id']);

        // When
        $this->send('DELETE');

        // Then
        static::assertSame(Response::HTTP_NO_CONTENT, $this->browser->getResponse()->getStatusCode());
        self::reload();
        static::assertNull(
            self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId),
        );
    }

    /**
     * The token that deleted the client reads nothing afterwards.
     */
    #[Test]
    public function theTokenOfADeletedClientReadsNothing(): void
    {
        // Given
        $this->send('DELETE');

        // When
        $this->send('GET');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 7592 §2.3: the registration access token is a credential of one client for one URI. It is not an
     * access token of this provider and it opens no endpoint of it.
     */
    #[Test]
    #[DataProvider('provideEndpointsItOpensNothingAt')]
    public function theRegistrationAccessTokenOpensNoEndpointOfTheProvider(string $method, string $path): void
    {
        // Given
        $token = self::string($this->registered['registration_access_token']);

        // When
        $this->browser->request($method, $path, server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertContains($response->getStatusCode(), [Response::HTTP_UNAUTHORIZED, Response::HTTP_BAD_REQUEST], self::string($response->getContent()));
        static::assertStringNotContainsString('"sub"', self::string($response->getContent()));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEndpointsItOpensNothingAt(): iterable
    {
        yield 'the UserInfo endpoint' => ['GET', '/userinfo'];

        yield 'the token endpoint' => ['POST', '/token'];

        yield 'the introspection endpoint' => ['POST', '/introspect'];
    }

    /**
     * RFC 7592 §2: the operations of this endpoint are switched through the HTTP method, and an operation
     * the provider does not switch on is answered with the error code that says so. The three it serves are
     * three routes on one path, so the router answers that for a fourth without anything written for it.
     */
    #[Test]
    public function aMethodTheEndpointDoesNotSwitchOnIsAnsweredAsSuch(): void
    {
        // When
        $this->browser->request(
            'PATCH',
            self::string($this->registered['registration_client_uri']),
            server: $this->headers(
                self::string($this->registered['registration_access_token']),
            ),
        );

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * A client of the same tenant, registered with a token of its own, whose URI this client's token does
     * not read.
     */
    private function anotherClient(): string
    {
        return self::string($this->register()['registration_client_uri']);
    }

    private function issue(): void
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::INITIAL_ACCESS_TOKEN),
                'The team that integrates',
                2,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
    }

    /**
     * @return array<string, mixed>
     */
    private function register(): array
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::INITIAL_ACCESS_TOKEN,
            ],
            content: json_encode([
                'client_name' => 'A client that registered itself',
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => 'openid profile',
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    /**
     * @param array<string, mixed>|null $members
     */
    private function send(string $method, ?array $members = null): void
    {
        $this->browser->request(
            $method,
            self::string($this->registered['registration_client_uri']),
            server: $this->headers(self::string($this->registered['registration_access_token'])),
            content: $members === null ? null : json_encode($members, JSON_THROW_ON_ERROR),
        );
    }

    /**
     * @return array<string, string>
     */
    private function headers(?string $token): array
    {
        $headers = [
            'CONTENT_TYPE' => 'application/json',
        ];
        if ($token !== null) {
            $headers['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        }

        return $headers;
    }
}
