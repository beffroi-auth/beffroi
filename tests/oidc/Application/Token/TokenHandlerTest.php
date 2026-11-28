<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use function base64_encode;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Beffroi\Oidc\Application\Token\GrantInterface;
use Beffroi\Oidc\Application\Token\RefreshTokenDue;
use Beffroi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Beffroi\Oidc\Application\Token\RefreshTokenGrant;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Application\Token\TokenHandler;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\RefreshTokenRotated;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Exception\AuthorizationPendingException;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Beffroi\Oidc\Exception\UnsupportedGrantTypeException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeBackchannelGrant;
use Beffroi\Oidc\Tests\Fixture\FakeClientActingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeClientAuthenticatingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\FakeExchangingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeGrant;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Core\JWK;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class TokenHandlerTest extends TestCase
{
    private const string AUTH_REQUEST_ID = 'the-auth-req-id';

    private Tenant $tenant;

    private Client $basicClient;

    private Client $postClient;

    private Client $publicClient;

    private Client $boundClient;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private InMemoryAuthorizationCodeRepository $codes;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private InMemoryBackchannelAuthenticationRecordRepository $backchannelRecords;

    private TokenIssuer $issuer;

    private AuthorizationCodeGrant $codeGrant;

    private TokenHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $alice = Fixtures::user($this->tenant);
        $this->hasher = new FakePasswordHasher();
        $this->basicClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretBasic(), 'basic-client');
        $this->postClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'post-client');
        $this->publicClient = Clients::public($this->tenant, 'public-client');
        $this->boundClient = Clients::boundToItsCertificate($this->tenant);
        $this->clients = new InMemoryClientRepository();
        foreach ([$this->basicClient, $this->postClient, $this->publicClient, $this->boundClient] as $client) {
            $this->clients->save($client);
        }
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($alice, $this->clock->now()->modify('-1 hour'));
        $this->context = Fixtures::context($this->clock->now());
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->backchannelRecords = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer(new FakeAccessTokenIssuer(), new FakeIdTokenIssuer(), $this->refreshTokens, Secrets::drawer(), $this->events);
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save($this->session);
        $this->codeGrant = new AuthorizationCodeGrant(
            $this->codes,
            new RefreshTokenRevocation($this->refreshTokens, $this->refreshTokens),
            new InMemoryAccessTokenRepository(),
            $sessions,
            $this->issuer,
            new SymfonyUuidGenerator(),
            $this->clock,
            $this->events,
            new RefreshTokenDue(Grants::served()),
            new RequestedAuthorizationDetails(AuthorizationDetailTypes::served()),
        );
        $refreshGrant = new RefreshTokenGrant(
            $this->refreshTokens,
            $this->refreshTokens,
            $this->codes,
            new RefreshTokenRevocation($this->refreshTokens, $this->refreshTokens),
            $sessions,
            $this->issuer,
            new RequestedAuthorizationDetails(AuthorizationDetailTypes::served()),
            $this->clock,
            $this->events,
        );
        $this->handler = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([$this->codeGrant, $refreshGrant]));
    }

    /**
     * RFC 6749 §4.1.3, §5.1
     */
    #[Test]
    public function itExchangesACodeForTokens(): void
    {
        // Given
        $this->codes->save(Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now(), ['openid', 'profile']));

        // When
        $response = $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $this->codeExchange(), $this->context);

        // Then
        $parameters = $response->parameters();
        static::assertSame('at:basic-client:alice-subject:' . $this->clock->now()->getTimestamp(), $parameters['access_token']);
        static::assertSame('Bearer', $parameters['token_type']);
        static::assertSame(600, $parameters['expires_in']);
        static::assertSame('id:basic-client:alice-subject:n-0S6_WzA2Mj:' . $this->clock->now()->getTimestamp(), $parameters['id_token']);
        static::assertSame('openid profile', $parameters['scope']);
        static::assertArrayHasKey('refresh_token', $parameters);
    }

    #[Test]
    public function anExchangeConsumesTheCodeAndRecordsTheRefreshToken(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now(), ['openid', 'profile']);
        $this->codes->save($code);

        // When
        $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $this->codeExchange(), $this->context);

        // Then
        static::assertTrue($code->isUsed());
        static::assertCount(1, $this->refreshTokens->all());
        static::assertCount(1, $this->events->of(TokensIssued::class));
    }

    /**
     * RFC 6749 §6
     */
    #[Test]
    public function itRefreshesTokens(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->postClient, $this->session, $this->clock->now());
        $this->codes->save($code);
        $token = Tokens::refreshToken(
            'the-token',
            $this->postClient,
            $this->session,
            $this->clock->now(),
            Tokens::family($this->clock->now(), $this->tenant, grantId: $code->grantId),
            ['openid', 'profile'],
        );
        $this->refreshTokens->save($token);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            null,
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'the-token',
                'client_id' => 'post-client',
                'client_secret' => Clients::SECRET,
            ],
            $this->context,
        );

        // Then
        $parameters = $response->parameters();
        static::assertSame('id:post-client:alice-subject:-:' . $this->clock->now()->getTimestamp(), $parameters['id_token']);
        // RFC 6749 §6, FAPI 2.0 Security Profile §5.3.2.1-9: a client that authenticates keeps its refresh token.
        static::assertArrayNotHasKey('refresh_token', $parameters);
        static::assertFalse($token->isRotated());
        static::assertCount(0, $this->events->of(RefreshTokenRotated::class));
    }

    /**
     * RFC 6749 §3.2.1
     */
    #[Test]
    public function itAuthenticatesTheClientBeforeReadingTheGrant(): void
    {
        // Given
        $this->codes->save(Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now()));

        // When
        try {
            $this->handler->handle(
                $this->tenant,
                self::basic('basic-client', 'wrong-secret'),
                [
                    'code' => 'the-code',
                ],
                $this->context,
            );
            static::fail('The client should have been refused.');
        } catch (InvalidClientException $exception) {
            // Then
            static::assertSame(401, $exception->statusCode);
            static::assertSame('Basic realm="https://id.acme.example"', $exception->challenge);
        }
    }

    #[Test]
    public function aRefusedClientConsumesNothingAndTheFailureIsAnnounced(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now());
        $this->codes->save($code);

        // When
        try {
            $this->handler->handle(
                $this->tenant,
                self::basic('basic-client', 'wrong-secret'),
                [
                    'code' => 'the-code',
                ],
                $this->context,
            );
        } catch (InvalidClientException) {
        }

        // Then
        static::assertFalse($code->isUsed());
        static::assertCount(1, $this->events->of(ClientAuthenticationFailed::class));
        static::assertCount(1, $this->events->events);
    }

    /**
     * RFC 6749 §4.1.3, §6
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideRequestsWithoutGrantType')]
    public function itRequiresAGrantType(array $parameters): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('grant_type');

        // When
        $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $parameters, $this->context);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideRequestsWithoutGrantType(): iterable
    {
        yield 'absent' => [[]];
        yield 'empty' => [[
            'grant_type' => '',
        ]];
        yield 'repeated' => [[
            'grant_type' => ['authorization_code'],
        ]];
    }

    /**
     * RFC 6749 §5.2, Decision 0006
     */
    #[Test]
    #[DataProvider('provideGrantTypesNotServed')]
    public function itRefusesAGrantTypeTheProviderDoesNotServe(string $grantType): void
    {
        // Then
        $this->expectException(UnsupportedGrantTypeException::class);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('basic-client', Clients::SECRET),
            [
                'grant_type' => $grantType,
            ],
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideGrantTypesNotServed(): iterable
    {
        yield 'password' => ['password'];
        yield 'client_credentials' => ['client_credentials'];
        yield 'implicit' => ['implicit'];
        yield 'device_code' => ['urn:ietf:params:oauth:grant-type:device_code'];
        yield 'authorization_code in another case' => ['Authorization_Code'];
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function itRefusesAGrantTypeTheHandlerWasNotGiven(): void
    {
        // Given
        $codeOnly = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([$this->codeGrant]));

        // Then
        $this->expectException(UnsupportedGrantTypeException::class);

        // When
        $codeOnly->handle(
            $this->tenant,
            null,
            [
                'grant_type' => 'refresh_token',
                'client_id' => 'public-client',
            ],
            $this->context,
        );
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function itRefusesAGrantTheClientIsNotRegisteredFor(): void
    {
        // Given
        $this->refreshTokens->save(Tokens::refreshToken('the-token', $this->publicClient, $this->session, $this->clock->now()));

        // When
        try {
            $this->handler->handle($this->tenant, null, $this->publicRefresh(), $this->context);
            static::fail('The public client is not registered for refresh_token.');
        } catch (UnauthorizedClientException $exception) {
            // Then
            static::assertSame(400, $exception->statusCode);
            static::assertFalse($exception->redirectable);
        }
    }

    #[Test]
    public function aGrantTheClientIsNotRegisteredForRotatesNothing(): void
    {
        // Given
        $token = Tokens::refreshToken('the-token', $this->publicClient, $this->session, $this->clock->now());
        $this->refreshTokens->save($token);

        // When
        try {
            $this->handler->handle($this->tenant, null, $this->publicRefresh(), $this->context);
        } catch (UnauthorizedClientException) {
        }

        // Then
        static::assertFalse($token->isRotated());
    }

    /**
     * RFC 6749 §4.5
     */
    #[Test]
    public function itServesAGrantItKnowsNothingAbout(): void
    {
        // Given
        $client = Clients::confidential(
            $this->tenant,
            $this->hasher->hash(Clients::SECRET),
            Methods::clientSecretBasic($this->hasher),
            'invented-client',
            grantTypes: [Grants::invented()],
        );
        $this->clients->save($client);
        $handler = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([new FakeGrant(Grants::invented())]));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The fake grant grants nothing.');

        // When
        $handler->handle(
            $this->tenant,
            self::basic('invented-client', Clients::SECRET),
            [
                'grant_type' => 'urn:example:params:oauth:grant-type:invented',
            ],
            $this->context,
        );
    }

    /**
     * RFC 6749 §2.1, §5.2
     */
    #[Test]
    #[DataProvider('provideGrantsThatRequireClientAuthentication')]
    public function aPublicClientIsRefusedAGrantThatRequiresClientAuthentication(GrantInterface $grant): void
    {
        // Given
        $this->clients->save(Clients::public($this->tenant, 'public-service', grantTypes: [$grant->grantType()]));
        $handler = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([$grant]));

        // Then
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessageIs('invalid_client: This grant type requires client authentication, and the client authenticated as a public client (RFC 6749 section 2.1).');

        // When
        $handler->handle(
            $this->tenant,
            null,
            [
                'grant_type' => $grant->grantType()->value,
                'client_id' => 'public-service',
            ],
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{GrantInterface}>
     */
    public static function provideGrantsThatRequireClientAuthentication(): iterable
    {
        yield 'a grant a client uses for itself (RFC 6749 §4.4)' => [new FakeClientActingGrant(Grants::clientCredentials())];
        yield 'a grant that exchanges a token (RFC 8693 §2.1)' => [new FakeExchangingGrant(Grants::tokenExchange())];
        yield 'a grant that declares nothing else (RFC 7523 §2.1)' => [new FakeClientAuthenticatingGrant(Grants::jwtBearer())];
        yield 'a grant that asks the user through a backchannel (CIBA Core §10.1)' => [new FakeBackchannelGrant(Grants::ciba())];
    }

    /**
     * RFC 9449 §5, §7.1
     */
    #[Test]
    public function aRequestThatProvesAKeyBindsTheTokensToIt(): void
    {
        // Given
        $this->codes->save(Tokens::code(
            'the-code',
            $this->publicClient,
            $this->session,
            $this->clock->now(),
            ['openid'],
            dpopKey: Proofs::thumbprintOf(Proofs::key()),
        ));

        // When
        $response = $this->handler->handle($this->tenant, null, $this->singlePageExchange('public-client'), $this->context, null, $this->proof());

        // Then
        static::assertSame('DPoP', $response->parameters()['token_type']);
        static::assertEquals(Proofs::thumbprintOf(Proofs::key()), $this->issuedConfirmation());
    }

    /**
     * RFC 9449 §5
     */
    #[Test]
    public function aRequestThatProvesNothingGetsABearerToken(): void
    {
        // Given
        $this->codes->save(Tokens::code('the-code', $this->publicClient, $this->session, $this->clock->now(), ['openid']));

        // When
        $response = $this->handler->handle($this->tenant, null, $this->singlePageExchange('public-client'), $this->context);

        // Then
        static::assertSame('Bearer', $response->parameters()['token_type']);
        static::assertNull($this->issuedConfirmation());
    }

    /**
     * RFC 9449 §10.1
     */
    #[Test]
    public function aCodeReservedForAKeyIsNotExchangedByAnother(): void
    {
        // Given
        $this->codes->save(Tokens::code(
            'the-code',
            $this->publicClient,
            $this->session,
            $this->clock->now(),
            ['openid'],
            dpopKey: Proofs::thumbprintOf(Proofs::otherKey()),
        ));

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The authorization code is invalid.');

        // When
        $this->handler->handle($this->tenant, null, $this->singlePageExchange('public-client'), $this->context, null, $this->proof());
    }

    /**
     * RFC 9449 §5.2
     */
    #[Test]
    public function aClientThatAlwaysUsesDpopIsRefusedATokenRequestThatCarriesNoProof(): void
    {
        // Given
        $client = Clients::boundToADpopKey($this->tenant);
        $this->clients->save($client);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), ['openid']));

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The tokens of this client are bound to a key it proves with DPoP, and this request carries no DPoP proof (RFC 9449 section 5.2).');

        // When
        $this->handler->handle($this->tenant, null, $this->singlePageExchange('dpop-bound-client'), $this->context);
    }

    /**
     * RFC 9449 §5.2
     */
    #[Test]
    public function aClientThatAlwaysUsesDpopGetsItsTokensBoundToTheKeyItProved(): void
    {
        // Given
        $client = Clients::boundToADpopKey($this->tenant);
        $this->clients->save($client);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), ['openid']));

        // When
        $response = $this->handler->handle($this->tenant, null, $this->singlePageExchange('dpop-bound-client'), $this->context, null, $this->proof());

        // Then
        static::assertSame('DPoP', $response->parameters()['token_type']);
        static::assertEquals(Proofs::thumbprintOf(Proofs::key()), $this->issuedConfirmation());
    }

    /**
     * FAPI 2.0 Security Profile §5.3.2.1
     */
    #[Test]
    public function aClientThatRequiresSenderConstrainedTokensIsRefusedATokenRequestThatProvesNothing(): void
    {
        // Given
        $client = Clients::requiringSenderConstrainedTokens($this->tenant);
        $this->clients->save($client);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), ['openid']));

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The tokens of this client are bound to what the request proves it holds, and this request proves neither a certificate nor a key (FAPI 2.0 Security Profile section 5.3.2.1).');

        // When
        $this->handler->handle($this->tenant, null, $this->singlePageExchange('sender-constrained-client'), $this->context);
    }

    #[Test]
    public function aRequestThatProvesACertificateAndAKeyIsRefused(): void
    {
        // Given
        $client = Clients::withCertificateIdentity($this->tenant, new SubjectDistinguishedName('c=FR,o=Beffroi Test,cn=beffroi mtls client'));
        $this->clients->save($client);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), ['openid']));

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIs('invalid_dpop_proof: The tokens of a request are bound to one thing, and this request proves a certificate and a key (RFC 9449 section 5).');

        // When
        $this->handler->handle(
            $this->tenant,
            null,
            [
                'grant_type' => 'authorization_code',
                'code' => 'the-code',
                'redirect_uri' => 'https://mtls.example/callback',
                'client_id' => 'mtls-client',
                'code_verifier' => Tokens::CODE_VERIFIER,
            ],
            $this->context,
            Certificates::client(),
            $this->proof(),
        );
    }

    /**
     * FAPI 1.0 Advanced Final §5.2.2, RFC 8705 §3.4
     */
    #[Test]
    public function aClientRegisteredForCertificateBoundTokensGetsThemBoundToTheCertificateItPresented(): void
    {
        // Given
        $this->backchannelRecords->save($this->approvedBackchannelRequest());

        // When
        $this->backchannelHandler()->handle($this->tenant, null, $this->cibaExchange(), $this->context, Certificates::client());

        // Then
        static::assertEquals(CertificateConfirmation::ofCertificate(Certificates::client()), $this->issuedConfirmation());
    }

    /**
     * FAPI 1.0 Advanced Final §5.2.2
     */
    #[Test]
    #[DataProvider('provideRequestsThatProveNoCertificate')]
    public function aTokenRequestThatProvesNoCertificateIsRefusedRatherThanToldToComeBackLater(bool $provesAKey): void
    {
        // Given
        $this->backchannelRecords->save($this->unansweredBackchannelRequest());

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The tokens of this client are bound to the certificate it presents, and this request proves none (RFC 8705 section 3.4).');

        // When
        $this->backchannelHandler()->handle(
            $this->tenant,
            null,
            $this->cibaExchange(),
            $this->context,
            null,
            $provesAKey ? $this->proof() : null,
        );
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideRequestsThatProveNoCertificate(): iterable
    {
        yield 'nothing at all' => [false];
        yield 'a key instead' => [true];
    }

    /**
     * CIBA Core §11
     */
    #[Test]
    public function aRequestThatProvesItsCertificateIsToldToComeBackLaterWhileNobodyHasAnswered(): void
    {
        // Given
        $this->backchannelRecords->save($this->unansweredBackchannelRequest());

        // Then
        $this->expectException(AuthorizationPendingException::class);

        // When
        $this->backchannelHandler()->handle($this->tenant, null, $this->cibaExchange(), $this->context, Certificates::client());
    }

    private function authenticator(): ClientAuthenticator
    {
        return new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher),
            Methods::requestParser(),
            $this->clock,
            $this->events,
            new FakeClientLoadBudget(),
        );
    }

    /**
     * @return array<string, string>
     */
    private function codeExchange(): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'client_id' => 'basic-client',
            'code_verifier' => Tokens::CODE_VERIFIER,
        ];
    }

    /**
     * @return array<string, string>
     */
    private function publicRefresh(): array
    {
        return [
            'grant_type' => 'refresh_token',
            'refresh_token' => 'the-token',
            'client_id' => 'public-client',
        ];
    }

    /**
     * @return array<string, string>
     */
    private function singlePageExchange(string $clientId): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://spa.example/callback',
            'client_id' => $clientId,
            'code_verifier' => Tokens::CODE_VERIFIER,
        ];
    }

    private function backchannelHandler(): TokenHandler
    {
        return new TokenHandler(
            $this->authenticator(),
            Proofs::verifier(),
            new Endpoints(),
            new ServedGrants([new BackchannelAuthenticationGrant(
                $this->backchannelRecords,
                $this->issuer,
                new RefreshTokenDue(Grants::servedWithCiba()),
                new SymfonyUuidGenerator(),
                $this->clock,
            )]),
        );
    }

    /**
     * CIBA Core §7
     */
    private function unansweredBackchannelRequest(): BackchannelAuthenticationRecord
    {
        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf(self::AUTH_REQUEST_ID),
            Uuid::v7(),
            $this->boundClient,
            $this->session->user,
            new Scopes([new Scope('openid')]),
            null,
            null,
            [],
            null,
            null,
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
    }

    /**
     * CIBA Core §10.1
     */
    private function approvedBackchannelRequest(): BackchannelAuthenticationRecord
    {
        $record = $this->unansweredBackchannelRequest();
        $record->approve(
            $this->session,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $this->clock->now(),
        );

        return $record;
    }

    /**
     * CIBA Core §10.1, OIDC Core §9
     *
     * @return array<string, string>
     */
    private function cibaExchange(): array
    {
        return [
            'grant_type' => 'urn:openid:params:grant-type:ciba',
            'auth_req_id' => self::AUTH_REQUEST_ID,
            ...ClientAssertions::parameters(ClientAssertions::signedWithKey(
                ClientAssertions::claims('bound-terminal', $this->tenant->issuer->value, $this->clock->now()),
            )),
        ];
    }

    private function proof(?JWK $key = null): string
    {
        return Proofs::proof('POST', Endpoints::of($this->tenant)->token, $this->clock->now(), null, [], [], $key);
    }

    private function issuedConfirmation(): ?ConfirmationInterface
    {
        $issued = $this->events->of(TokensIssued::class);

        return $issued === [] ? static::fail('No token was issued.') : $issued[0]->confirmation;
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
