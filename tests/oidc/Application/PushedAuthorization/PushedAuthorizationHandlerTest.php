<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\PushedAuthorization;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use function array_filter;
use function array_merge;
use function base64_encode;
use DateInterval;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\JweDecrypterInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRecordRepository;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnsupportedResponseTypeException;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use Beffroi\Oidc\Tests\Fixture\RequestObjects;
use Beffroi\Oidc\Tests\Fixture\ServedModes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function urlencode;

final class PushedAuthorizationHandlerTest extends TestCase
{
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    private Tenant $tenant;

    private RequestContext $context;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private InMemoryPushedAuthorizationRecordRepository $requests;

    private MockClock $clock;

    /**
     * The key the tenant publishes for encryption, which a client encrypts its pushed request object to.
     */
    private TenantKey $encryption;

    private JweDecrypterInterface $decrypter;

    private PushedAuthorizationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->hasher = new FakePasswordHasher();
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET)));
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'post-client'));
        $this->clients->save(Clients::public($this->tenant));
        $this->requests = new InMemoryPushedAuthorizationRecordRepository();
        $this->clock = new MockClock('2026-09-22T12:00:00+00:00');
        $keys = new Jwts($this->tenant);
        $this->encryption = $keys->activate(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());
        $this->decrypter = new JwtLibraryJweDecrypter($keys->keys, Algorithms::encryption());
        $this->handler = $this->handler($this->requests);
    }

    /**
     * RFC 9126 §2.2: a reference of the registered URN, and the seconds it lives.
     */
    #[Test]
    public function itAnswersAReferenceAndItsLifetime(): void
    {
        // When
        $response = $this->push();

        // Then
        static::assertStringStartsWith(RequestUri::URN_PREFIX, $response->requestUri->value);
        static::assertSame(60, $response->expiresIn);
    }

    /**
     * RFC 9126 §2.2: the record waits under the hash of the reference, bound to the client that pushed
     * it, unused until the browser brings the reference back.
     */
    #[Test]
    public function itKeepsTheRequestUnderTheHashOfItsReference(): void
    {
        // When
        $response = $this->push();

        // Then
        $request = $this->storedRequest($response);
        static::assertSame('oidc-demo', $request->clientId);
        static::assertSame($this->tenant, $request->tenant);
        static::assertFalse($request->isUsed());
    }

    /**
     * RFC 9126 §4: what the authorization endpoint will read is what the client wrote, kept as it wrote
     * it, with the name of the authenticated client beside it.
     */
    #[Test]
    public function itKeepsTheParametersTheClientWrote(): void
    {
        // When
        $response = $this->push([
            'scope' => 'openid profile',
            'state' => 'af0ifjsldkj',
            'nonce' => 'n-0S6_WzA2Mj',
        ]);

        // Then
        static::assertSame(
            [
                'response_type' => 'code',
                'scope' => 'openid profile',
                'redirect_uri' => 'https://demo.localhost/login/check',
                'code_challenge' => self::CHALLENGE,
                'code_challenge_method' => 'S256',
                'state' => 'af0ifjsldkj',
                'nonce' => 'n-0S6_WzA2Mj',
                'client_id' => 'oidc-demo',
            ],
            $this->storedRequest($response)->parameters,
        );
    }

    /**
     * RFC 9101 §6.1 and RFC 9126 §3: a pushed request may itself be a request object, which FAPI 2.0
     * Message Signing asks of one. It is verified here, once, and what the record keeps is the request
     * it carried, so that the authorization endpoint reads parameters like any other.
     */
    #[Test]
    public function itReadsARequestObjectAPushedRequestCarries(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, clientId: 'jar-client'));
        $object = RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid profile',
            'code_challenge' => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ]));

        // When
        $response = $this->pushWith(self::basic('jar-client', Clients::SECRET), [
            'request' => $object,
            'redirect_uri' => null,
            'scope' => null,
            'response_type' => null,
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]);

        // Then
        static::assertSame(
            [
                'client_id' => 'jar-client',
                'response_type' => 'code',
                'redirect_uri' => 'https://jar.example/callback',
                'scope' => 'openid profile',
                'code_challenge' => self::CHALLENGE,
                'code_challenge_method' => 'S256',
            ],
            $this->storedRequest($response)->parameters,
        );
    }

    /**
     * Issue #189, RFC 9101 §6.1: the object a client pushes may be encrypted to a key the tenant
     * publishes. The endpoint opens it with that key and keeps the request it carried, which is what the
     * authorization endpoint does with the same object.
     */
    #[Test]
    public function itOpensARequestObjectAClientEncryptedToTheProvider(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, clientId: 'jar-client'));
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
                'response_type' => 'code',
                'redirect_uri' => 'https://jar.example/callback',
                'scope' => 'openid profile',
                'code_challenge' => self::CHALLENGE,
                'code_challenge_method' => 'S256',
            ])),
            [
                'cty' => 'JWT',
            ],
        );

        // When
        $response = $this->pushWith(self::basic('jar-client', Clients::SECRET), [
            'request' => $object,
            'redirect_uri' => null,
            'scope' => null,
            'response_type' => null,
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]);

        // Then
        static::assertSame(
            [
                'client_id' => 'jar-client',
                'response_type' => 'code',
                'redirect_uri' => 'https://jar.example/callback',
                'scope' => 'openid profile',
                'code_challenge' => self::CHALLENGE,
                'code_challenge_method' => 'S256',
            ],
            $this->storedRequest($response)->parameters,
        );
    }

    /**
     * RFC 9101 §10.5, FAPI 2.0 Message Signing §5.3.1: a client whose requests are only read from a
     * request object it signed cannot push one as form parameters.
     */
    #[Test]
    public function aClientHeldToSignedObjectsIsRefusedARequestOfFormParameters(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requiresSignedRequestObject: true));

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client only starts an authorization request with a request object it signed (RFC 9101 section 10.5, require_signed_request_object).');

        // When
        $this->pushWith(self::basic('jar-client', Clients::SECRET), [
            'redirect_uri' => 'https://jar.example/callback',
        ]);
    }

    /**
     * RFC 9101 §10.5, RFC 9126 §4: the record of a request such a client pushed in an object it signed
     * says so, which is what the authorization endpoint reads the requirement from when the reference
     * comes back.
     */
    #[Test]
    public function theRecordOfARequestPushedInASignedObjectSaysSo(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requiresSignedRequestObject: true));
        $object = RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid profile',
            'code_challenge' => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ]));

        // When
        $response = $this->pushWith(self::basic('jar-client', Clients::SECRET), [
            'request' => $object,
            'redirect_uri' => null,
            'scope' => null,
            'response_type' => null,
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]);

        // Then
        static::assertTrue($this->storedRequest($response)->carriedBySignedObject);
    }

    /**
     * RFC 9101 §10.5: a request object of such a client that uses "alg": "none" is refused, the
     * registration of that client reading no object unsigned.
     */
    #[Test]
    public function anUnsignedObjectOfAClientHeldToSignedObjectsIsRefused(): void
    {
        // Given
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requiresSignedRequestObject: true));
        $object = RequestObjects::unsigned(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid profile',
            'code_challenge' => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ]));

        // Then
        $this->expectException(InvalidRequestObjectException::class);
        $this->expectExceptionMessageIs('invalid_request_object: The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).');

        // When
        $this->pushWith(self::basic('jar-client', Clients::SECRET), [
            'request' => $object,
            'redirect_uri' => null,
            'scope' => null,
            'response_type' => null,
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]);
    }

    /**
     * RFC 9126 §2.1: a "request_uri" is not one of the parameters a pushed request carries, the
     * reference being what the endpoint answers and not what it reads.
     */
    #[Test]
    public function aRequestObjectByReferenceIsNotPushed(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('not one of those a pushed authorization request carries');

        // When
        $this->push([
            'request_uri' => 'https://jar.example/request.jwt',
        ]);
    }

    /**
     * A credential authenticates the request that carries it and nothing else: the record that outlives
     * that request keeps none of it, and keeps the name of the client all the same.
     */
    #[Test]
    public function itKeepsNothingOfWhatAuthenticatedTheClient(): void
    {
        // When
        $response = $this->pushWith(null, [
            'client_id' => 'post-client',
            'client_secret' => Clients::SECRET,
        ]);

        // Then
        $parameters = $this->storedRequest($response)->parameters;
        static::assertArrayNotHasKey('client_secret', $parameters);
        static::assertSame('post-client', $parameters['client_id'] ?? null);
    }

    /**
     * RFC 9126 §2.1: the record names the authenticated client whether or not the body did; a client
     * authenticating through the Authorization header names itself nowhere else.
     */
    #[Test]
    public function theClientOfTheRecordIsTheAuthenticatedOneEvenWhenTheBodyNamesNone(): void
    {
        // When
        $response = $this->push();

        // Then
        static::assertSame('oidc-demo', $this->storedRequest($response)->clientId);
    }

    /**
     * RFC 9126 §2.1: "request_uri authorization request parameter is one exception, and it MUST NOT be
     * provided".
     */
    #[Test]
    public function itRefusesARequestUriAtTheEndpoint(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The request_uri parameter is not one of those a pushed authorization request carries (RFC 9126 section 2.1).');

        // When
        $this->push([
            'request_uri' => RequestUri::of(Secrets::draw())->value,
        ]);
    }

    /**
     * RFC 9126 §2: the endpoint authenticates the client exactly as the token endpoint does.
     */
    #[Test]
    public function itRefusesAClientThatDoesNotAuthenticate(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);

        // When
        $this->pushWith(self::basic('oidc-demo', 'not-the-secret'));
    }

    /**
     * RFC 9126 §2.1: the request is read here by the parser the authorization endpoint reads with, the
     * redirect URI included, so that what is refused there is refused here.
     *
     * @param array<string, string|null> $overrides
     * @param class-string<OAuth2Exception> $exception
     */
    #[Test]
    #[DataProvider('provideRequestsTheAuthorizationEndpointRefuses')]
    public function itRefusesWhatTheAuthorizationEndpointWouldRefuse(array $overrides, string $exception, string $message): void
    {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        $this->push($overrides);
    }

    /**
     * @return iterable<string, array{array<string, string|null>, class-string<OAuth2Exception>, string}>
     */
    public static function provideRequestsTheAuthorizationEndpointRefuses(): iterable
    {
        yield 'a redirect URI the client did not register' => [
            [
                'redirect_uri' => 'https://attacker.example/callback',
            ],
            InvalidRequestException::class,
            'The redirect_uri parameter is not registered for this client.',
        ];

        yield 'no redirect URI at all' => [
            [
                'redirect_uri' => null,
            ],
            InvalidRequestException::class,
            'The redirect_uri parameter is missing.',
        ];

        yield 'no scope' => [
            [
                'scope' => null,
            ],
            InvalidRequestException::class,
            'The scope parameter is missing.',
        ];

        yield 'a scope the client is not allowed' => [
            [
                'scope' => 'openid banking',
            ],
            InvalidScopeException::class,
            'The requested scope is not allowed for this client.',
        ];

        yield 'a PKCE method the provider refuses' => [
            [
                'code_challenge_method' => 'plain',
            ],
            InvalidRequestException::class,
            'The code_challenge_method parameter must be S256',
        ];

        yield 'a response type the provider does not serve' => [
            [
                'response_type' => 'token',
            ],
            UnsupportedResponseTypeException::class,
            'Only the code response type is supported.',
        ];
    }

    /**
     * Nothing is kept of a request that is refused: the whole request is read before a reference exists.
     */
    #[Test]
    public function aRefusedRequestIsNeverStored(): void
    {
        // Given
        $requests = $this->createMock(PushedAuthorizationRecordRepositoryInterface::class);
        $requests->expects(static::never())->method('save');
        $this->handler = $this->handler($requests);

        // When
        try {
            $this->push([
                'redirect_uri' => 'https://attacker.example/callback',
            ]);
        } catch (OAuth2Exception) {
        }
    }

    /**
     * RFC 9126 §2: a public client pushes its request too, naming itself and proving nothing, which is
     * how it authenticates at the token endpoint.
     */
    #[Test]
    public function aPublicClientPushesItsRequestToo(): void
    {
        // When
        $response = $this->pushWith(null, [
            'client_id' => 'spa',
            'redirect_uri' => 'https://spa.example/callback',
        ]);

        // Then
        static::assertSame('spa', $this->storedRequest($response)->clientId);
    }

    /**
     * RFC 9126 §2.2: the lifetime is the deployment's, and the answer says the one the record has.
     */
    #[Test]
    public function theLifetimeIsTheOneTheDeploymentWired(): void
    {
        // Given
        $this->handler = $this->handler($this->requests, new DateInterval('PT30S'));

        // When
        $response = $this->push();

        // Then
        static::assertSame(30, $response->expiresIn);
    }

    /**
     * RFC 9449 §10.1: a request pushed with a proof reserves its code for the key of the proof, without
     * the client having to name it a second time.
     */
    #[Test]
    public function aRequestPushedWithAProofReservesItsCodeForThatKey(): void
    {
        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo', Clients::SECRET),
            self::parameters([]),
            $this->context,
            null,
            $this->proof(),
        );

        // Then
        static::assertSame(Proofs::thumbprintOf(Proofs::key())->thumbprint, $this->storedRequest($response)->parameters['dpop_jkt']);
    }

    /**
     * A request that names one key and is pushed with a proof of another names two keys, and choosing
     * one of them would be the provider deciding what the client meant.
     */
    #[Test]
    public function aRequestNamingAKeyAndProvingAnotherIsRefused(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The dpop_jkt of the pushed request names another key than the proof that carried it (RFC 9449 section 10.1).');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo', Clients::SECRET),
            self::parameters([
                'dpop_jkt' => Proofs::thumbprintOf(Proofs::otherKey())->thumbprint,
            ]),
            $this->context,
            null,
            $this->proof(),
        );
    }

    /**
     * A client that names the key itself is taken at its word, and the code is reserved all the same.
     */
    #[Test]
    public function aRequestMayNameTheKeyItself(): void
    {
        // When
        $response = $this->push([
            'dpop_jkt' => Proofs::thumbprintOf(Proofs::key())->thumbprint,
        ]);

        // Then
        static::assertSame(Proofs::thumbprintOf(Proofs::key())->thumbprint, $this->storedRequest($response)->parameters['dpop_jkt']);
    }

    /**
     * A proof for the pushed endpoint of the tenant, made now.
     */
    private function proof(): string
    {
        return Proofs::proof('POST', Endpoints::of($this->tenant)->pushedAuthorizationRequest, $this->context->receivedAt);
    }

    /**
     * The record the endpoint kept for the reference it answered with.
     */
    private function storedRequest(PushedAuthorizationResponse $response): PushedAuthorizationRecord
    {
        return (
            $this->requests->findByRequestUriHash(
                $response->requestUri->hash(),
            ) ?? static::fail('The endpoint kept no request for the reference it answered with.')
        );
    }

    private function handler(PushedAuthorizationRecordRepositoryInterface $requests, ?DateInterval $lifetime = null): PushedAuthorizationHandler
    {
        return new PushedAuthorizationHandler(
            new ClientAuthenticator(
                $this->clients,
                Methods::all($this->hasher),
                Methods::requestParser(),
                $this->clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            Proofs::verifier(),
            new Endpoints(),
            new AuthorizationRequestParser($this->clients, ServedModes::queryAndFormPost(), AuthorizationDetailTypes::served(), ChallengeMethods::s256()),
            RequestObjects::resolver($this->clients, $this->clock, decrypter: $this->decrypter),
            $requests,
            Secrets::drawer(),
            $this->clock,
            $lifetime ?? new DateInterval('PT60S'),
        );
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function push(array $overrides = []): PushedAuthorizationResponse
    {
        return $this->pushWith(self::basic('oidc-demo', Clients::SECRET), $overrides);
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function pushWith(?string $authorizationHeader, array $overrides = []): PushedAuthorizationResponse
    {
        return $this->handler->handle($this->tenant, $authorizationHeader, self::parameters($overrides), $this->context);
    }

    /**
     * @param array<string, string|null> $overrides
     *
     * @return array<string, string>
     */
    private static function parameters(array $overrides): array
    {
        $parameters = array_merge([
            'response_type' => 'code',
            'scope' => 'openid',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'code_challenge' => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ], $overrides);

        return array_filter($parameters, static fn (mixed $value): bool => $value !== null);
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($secret));
    }
}
