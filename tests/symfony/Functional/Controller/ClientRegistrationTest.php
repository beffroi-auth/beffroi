<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function array_map;
use function base64_encode;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
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
 * RFC 7591, decision 0009: the registration endpoint in the mode built first, a client authorised by an
 * initial access token the tenant issued. A client that registers this way is a client: it signs in end
 * to end and is refused everything a declared one is refused.
 */
final class ClientRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * RFC 7591 §3.2.1: the identifier the provider drew, the date it drew it on, and the metadata it
     * registered.
     */
    #[Test]
    public function aClientThatPresentsATokenOfTheTenantIsRegistered(): void
    {
        // Given
        $this->issue();

        // When
        $this->register();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));
        $registered = self::json($response);
        static::assertIsString($registered['client_id']);
        static::assertGreaterThanOrEqual(self::currentSecond()->getTimestamp() - 1, $registered['client_id_issued_at']);
        static::assertSame([self::REDIRECT_URI], $registered['redirect_uris']);
    }

    /**
     * RFC 7591 §3.2.1: the provider assigns a secret when, and only when, the method the client
     * registered proves one.
     */
    #[Test]
    public function aClientWhoseMethodProvesASecretIsHandedOne(): void
    {
        // Given
        $this->issue();

        // When
        $this->register();

        // Then
        $registered = self::json($this->browser->getResponse());
        static::assertIsString($registered['client_secret']);
        static::assertSame(0, $registered['client_secret_expires_at']);
    }

    #[Test]
    public function aPublicClientIsHandedNoSecret(): void
    {
        // Given
        $this->issue();

        // When
        $this->register([
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'none',
        ]);

        // Then
        $registered = self::json($this->browser->getResponse());
        static::assertArrayNotHasKey('client_secret', $registered);
    }

    /**
     * RFC 7591 §2: a client that registers nothing beyond its redirection URI takes the defaults of the
     * specification, and the row it was written to is read back through the reader every registration
     * goes through.
     */
    #[Test]
    public function theRegisteredClientIsResolvedLikeAnyOther(): void
    {
        // Given
        $this->issue();
        $this->register([
            'redirect_uris' => [self::REDIRECT_URI],
        ]);
        $clientId = self::string(self::json($this->browser->getResponse())['client_id']);

        // When
        self::reload();
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId);

        // Then
        static::assertSame(['authorization_code'], array_map(
            static fn (GrantTypeName $grantType): string => $grantType->value,
            $client?->registration->grantTypes ?? [],
        ));
    }

    /**
     * OIDC Core §3.1: the code flow for a client that existed nowhere a moment earlier, with no restart
     * and no cache to clear.
     */
    #[Test]
    public function aClientThatRegisteredItselfSignsAUserInEndToEnd(): void
    {
        // Given
        self::signingKey();
        $this->issue();
        $this->register([
            'redirect_uris' => [self::REDIRECT_URI],
            'scope' => 'openid profile',
        ]);
        $registered = self::json($this->browser->getResponse());
        $clientId = self::string($registered['client_id']);
        $secret = self::string($registered['client_secret']);
        $code = $this->codeAllowedByAlice($clientId);

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['id_token']);
    }

    /**
     * Decision 0006: whoever does not hold a token of this tenant learns nothing about the one they
     * presented, so the five refusals are one refusal.
     */
    #[Test]
    #[DataProvider('provideUnauthorizedRequests')]
    public function aRequestThatAuthorisesNothingIsRefusedTheSameWay(?string $header, bool $spend, bool $expire, bool $revoke): void
    {
        // Given
        $this->issue(expired: $expire, spent: $spend, revoked: $revoke);

        // When
        $this->post([
            'redirect_uris' => [self::REDIRECT_URI],
        ], $header);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_token', self::json($response)['error']);
        static::assertStringStartsWith('Bearer error="invalid_token"', self::string($response->headers->get('WWW-Authenticate')));
    }

    /**
     * @return iterable<string, array{string|null, bool, bool, bool}>
     */
    public static function provideUnauthorizedRequests(): iterable
    {
        yield 'no Authorization header at all' => [null, false, false, false];

        yield 'a value nobody was handed' => ['Bearer a-value-nobody-was-handed', false, false, false];

        yield 'a token already worth nothing' => ['Bearer ' . self::TOKEN, true, false, false];

        yield 'a token that expired' => ['Bearer ' . self::TOKEN, false, true, false];

        yield 'a token the tenant took back' => ['Bearer ' . self::TOKEN, false, false, true];
    }

    /**
     * RFC 7591 §1.2: a token worth one registration registers one.
     */
    #[Test]
    public function aTokenWorthOneRegistrationServesOne(): void
    {
        // Given
        $this->issue();
        $this->register();

        // When
        $this->register();

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 7591 §3.2.2: a member that does not hold is a 400 naming the error the refusal answers for.
     */
    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideRefusedRegistrations')]
    public function aRegistrationTheTenantDoesNotOfferIsRefused(array $members, string $error, string $named): void
    {
        // Given
        $this->issue();

        // When
        $this->register($members);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        $refusal = self::json($response);
        static::assertSame($error, $refusal['error']);
        static::assertStringContainsString($named, self::string($refusal['error_description']));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function provideRefusedRegistrations(): iterable
    {
        yield 'a scope the tenant hands out no token for' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'scope' => 'openid billing.read',
            ],
            'invalid_client_metadata',
            'billing.read',
        ];

        yield 'a grant the provider does not serve' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'grant_types' => ['password'],
            ],
            'invalid_client_metadata',
            'grant_types',
        ];

        yield 'an authentication method the provider is not wired with' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_query',
            ],
            'invalid_client_metadata',
            'token_endpoint_auth_method',
        ];

        yield 'a shape of access token the provider does not write' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'access_token_format' => 'saml',
            ],
            'invalid_client_metadata',
            'access_token_format',
        ];

        yield 'the PKCE exemption of decision 0017, which nothing a client sends grants' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'requires_pkce' => false,
            ],
            'invalid_client_metadata',
            'requires_pkce',
        ];

        yield 'the consent exemption of architecture section 7' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'requires_consent' => false,
            ],
            'invalid_client_metadata',
            'requires_consent',
        ];

        yield 'signed request objects required, and read unsigned (RFC 9101 section 10.5)' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'require_signed_request_object' => true,
                'request_object_signing_alg' => 'none',
            ],
            'invalid_client_metadata',
            'registers no request_object_signing_alg under which an unsigned one is read',
        ];

        yield 'a page of the client served in plain HTTP (OIDC Registration section 2)' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'logo_uri' => 'http://registered.test/logo.png',
            ],
            'invalid_client_metadata',
            'http://registered.test/logo.png',
        ];

        yield 'a redirection URI with a fragment' => [
            [
                'redirect_uris' => ['https://registered.test/callback#here'],
            ],
            'invalid_redirect_uri',
            'must not carry a fragment',
        ];

        yield 'a redirection URI whose host carries a directive of a policy (RFC 3986 section 3.2.2)' => [
            [
                'redirect_uris' => ['https://registered.test;sandbox/callback'],
            ],
            'invalid_redirect_uri',
            'must name a host of letters, digits, hyphens and dots, or an IP address',
        ];

        yield 'a post-logout redirection URI whose host carries a second policy' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'post_logout_redirect_uris' => ['https://registered.test,sandbox/'],
            ],
            'invalid_redirect_uri',
            'must name a host of letters, digits, hyphens and dots, or an IP address',
        ];

        yield 'a front-channel logout URI whose host carries a directive of a policy' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'frontchannel_logout_uri' => 'https://registered.test;sandbox/frontchannel-logout',
            ],
            'invalid_client_metadata',
            'must name a host of letters, digits, hyphens and dots, or an IP address',
        ];

        yield 'a logo served from a name outside ASCII' => [
            [
                'redirect_uris' => [self::REDIRECT_URI],
                'logo_uri' => 'https://bücher.example/logo.png',
            ],
            'invalid_client_metadata',
            'must name a host of letters, digits, hyphens and dots, or an IP address',
        ];
    }

    /**
     * RFC 7591 §3.1: the body is a JSON object whose members are the metadata; anything else carries no
     * metadata at all.
     */
    #[Test]
    public function aBodyThatIsNoJsonObjectCarriesNoMetadata(): void
    {
        // Given
        $this->issue();

        // When
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
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
     * Decision 0009: a client that registered itself gets nothing a declared client does not get, and is
     * refused what a declared client is refused. The same request is made of both, and the two answers
     * are the same answer.
     */
    #[Test]
    public function aRegisteredClientIsRefusedWhatADeclaredClientIsRefused(): void
    {
        // Given
        $this->issue();
        $this->register();
        $clientId = self::string(self::json($this->browser->getResponse())['client_id']);
        $this->signIn(self::user('alice'));

        // When
        $registered = $this->askForAScopeNobodyRegistered($clientId, self::REDIRECT_URI);
        $declared = $this->askForAScopeNobodyRegistered('native-app', 'http://127.0.0.1/callback');

        // Then
        static::assertSame($declared, $registered);
        static::assertSame('invalid_scope', $registered['error'] ?? null);
    }

    /**
     * The tenant of the tests announces where a client registers, because its policy registers clients.
     */
    #[Test]
    public function theDocumentAnnouncesWhereAClientRegisters(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame('https://op.test/register', self::json($this->browser->getResponse())['registration_endpoint']);
    }

    private function issue(bool $expired = false, bool $spent = false, bool $revoked = false): InitialAccessToken
    {
        $issuedAt = $expired ? self::currentSecond()->modify('-2 days') : self::currentSecond();
        $token = new InitialAccessToken(
            Uuid::v7(),
            self::tenant(),
            DrawnSecret::digestOf(self::TOKEN),
            'The team that integrates',
            1,
            $issuedAt,
            $issuedAt->modify('+1 day'),
        );
        if ($spent) {
            $token->spend();
        }
        if ($revoked) {
            $token->revoke(self::currentSecond());
        }
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)->save($token);
        self::reload();

        return $token;
    }

    /**
     * @param array<string, mixed>|null $members
     */
    private function register(?array $members = null): void
    {
        $this->post(
            $members ?? [
                'redirect_uris' => [self::REDIRECT_URI],
            ],
            'Bearer ' . self::TOKEN,
        );
    }

    /**
     * @param array<string, mixed> $members
     */
    private function post(array $members, ?string $authorization): void
    {
        $server = [
            'CONTENT_TYPE' => 'application/json',
        ];
        if ($authorization !== null) {
            $server['HTTP_AUTHORIZATION'] = $authorization;
        }
        $this->browser->request('POST', '/register', server: $server, content: json_encode($members, JSON_THROW_ON_ERROR));
    }

    /**
     * RFC 6749 §3.3: a scope the client did not register is not its to ask for, and what comes back is a
     * redirection carrying the refusal.
     *
     * @return array<string, string>
     */
    private function askForAScopeNobodyRegistered(string $clientId, string $redirectUri): array
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
            'scope' => 'openid address',
        ]));
        $query = self::redirectedQuery($this->browser->getResponse());
        unset($query['iss']);

        return $query;
    }

    private function codeAllowedByAlice(string $clientId): string
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => self::REDIRECT_URI,
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }
}
