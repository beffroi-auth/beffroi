<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Revocation;

use function array_map;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Grants;
use function base64_encode;
use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\UnopenedRows;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Grant\RecordedGrants;
use Beffroi\Oidc\Application\Revocation\RevocationHandler;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\TokenRevoked;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\UnsupportedTokenTypeException;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Clock\MockClock;

final class RevocationHandlerTest extends TestCase
{
    private Tenant $tenant;

    private AuthenticationSession $session;

    private Client $client;

    private Client $other;

    private Client $public;

    private MockClock $clock;

    private RequestContext $context;

    private Jwts $jwts;

    private InMemoryAccessTokenRepository $accessTokens;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryUserRepository $users;

    private RecordingEventDispatcher $events;

    private UnopenedRows $rows;

    private RevocationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-17T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $user = Fixtures::user($this->tenant);
        $this->session = Fixtures::session($user, $this->clock->now()->modify('-1 hour'));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->sessions->save($this->session);
        $this->users = new InMemoryUserRepository();
        $this->users->save($user);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $hasher = new FakePasswordHasher();
        $this->client = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET));
        $this->other = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'other');
        $this->public = Clients::public($this->tenant);
        $clients = new InMemoryClientRepository();
        foreach ([$this->client, $this->other, $this->public] as $client) {
            $clients->save($client);
        }
        $this->jwts = new Jwts($this->tenant);
        $this->accessTokens = new InMemoryAccessTokenRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->rows = new UnopenedRows();
        $this->handler = $this->handler($clients, $hasher, $this->accessTokens);
    }

    /**
     * RFC 7009 §2.1, decision 0066
     */
    #[Test]
    public function theRevocationNamesTheClientThatAskedForItAsItsAuthor(): void
    {
        // Given
        $token = $this->accessToken($this->client);

        // When
        $this->handler->handle($this->tenant, self::basic('oidc-demo'), ['token' => $token], $this->context);

        // Then
        static::assertEquals([new AClient($this->client->registration->clientId)], array_map(
            static fn (TokenRevoked $revoked): AuthorInterface => $revoked->author(),
            $this->events->of(TokenRevoked::class),
        ));
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function itRevokesAnAccessTokenOfTheCaller(): void
    {
        // Given
        $token = $this->accessToken($this->client);
        $record = $this->accessTokens->find($token) ?? static::fail('The token was kept.');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
                'token_type_hint' => 'access_token',
            ],
            $this->context,
        );

        // Then
        static::assertNull($this->accessTokens->find($token));
        $events = $this->events->of(TokenRevoked::class);
        static::assertCount(1, $events);
        static::assertSame(TokenRevoked::ACCESS_TOKEN, $events[0]->tokenType);
        static::assertSame($record->tokenHash, $events[0]->tokenHash);
        static::assertSame($this->client->registration->clientId, $events[0]->revokedBy);
        static::assertTrue($events[0]->subject()?->equals($this->session->user->subject));
        static::assertSame([], $events[0]->revokedAccessTokenHashes);
        static::assertEquals($this->clock->now(), $events[0]->occurredAt);
        static::assertSame($this->context, $events[0]->context);
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function itRevokesARefreshTokenAndTheAccessTokensOfItsGrant(): void
    {
        // Given
        $family = Tokens::family($this->clock->now()->modify('-2 days'), $this->client->tenant);
        $rotated = Tokens::refreshToken('rotated', $this->client, $this->session, $this->clock->now()->modify('-1 day'), $family);
        $rotated->rotate($this->clock->now()->modify('-1 hour'));
        $current = Tokens::refreshToken('current', $this->client, $this->session, $this->clock->now()->modify('-1 hour'), $family);
        $this->refreshTokens->save($rotated);
        $this->refreshTokens->save($current);
        $ofTheGrant = Tokens::storedAccessToken('of-the-grant', $this->client, $this->session, $this->clock->now(), $family->grantId);
        $ofAnotherGrant = Tokens::storedAccessToken('of-another-grant', $this->client, $this->session, $this->clock->now());
        $this->accessTokens->save($ofTheGrant);
        $this->accessTokens->save($ofAnotherGrant);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'current',
                'token_type_hint' => 'refresh_token',
            ],
            $this->context,
        );

        // Then
        static::assertTrue($current->isRevoked());
        static::assertEquals($this->clock->now(), $current->revokedAt);
        static::assertFalse($rotated->isRevoked(), 'the family is not revoked; a reuse of the rotated token is still told apart');
        static::assertSame([$ofAnotherGrant], $this->accessTokens->all());
        $events = $this->events->of(TokenRevoked::class);
        static::assertCount(1, $events);
        static::assertSame(TokenRevoked::REFRESH_TOKEN, $events[0]->tokenType);
        static::assertSame($current->tokenHash, $events[0]->tokenHash);
        static::assertSame([$ofTheGrant->tokenHash], $events[0]->revokedAccessTokenHashes);
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function anAccessTokenIsAnnouncedRevokedWhileItsSessionCannotBeOpened(): void
    {
        // Given
        $token = Secrets::draw();
        $this->accessTokens->save(Tokens::storedAccessToken($token, $this->client, $this->rows->unopenedSession($this->session), $this->clock->now()));
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
        );

        // Then
        $events = $this->events->of(TokenRevoked::class);
        static::assertCount(1, $events);
        static::assertSame(TokenRevoked::ACCESS_TOKEN, $events[0]->tokenType);
        static::assertTrue($events[0]->subject()?->equals($this->session->user->subject));
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function aRefreshTokenIsAnnouncedRevokedWhileItsSessionCannotBeOpened(): void
    {
        // Given
        $this->refreshTokens->save(Tokens::refreshToken(
            'current',
            $this->client,
            $this->rows->unopenedSession($this->session),
            $this->clock->now()->modify('-1 hour'),
        ));
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'current',
            ],
            $this->context,
        );

        // Then
        $events = $this->events->of(TokenRevoked::class);
        static::assertCount(1, $events);
        static::assertSame(TokenRevoked::REFRESH_TOKEN, $events[0]->tokenType);
        static::assertTrue($events[0]->subject()?->equals($this->session->user->subject));
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function aPublicClientRevokesItsOwnToken(): void
    {
        // Given
        $token = $this->accessToken($this->public);

        // When
        $this->handler->handle(
            $this->tenant,
            null,
            [
                'client_id' => 'spa',
                'token' => $token,
            ],
            $this->context,
        );

        // Then
        static::assertNull($this->accessTokens->find($token));
    }

    /**
     * RFC 7009 §2.2
     *
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideTokensNotRevoked')]
    public function itDoesNothingForATokenItCannotRevokeForTheCaller(callable $token): void
    {
        // Given
        $value = $token($this);
        $accessTokensBefore = $this->accessTokens->all();

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $value,
            ],
            $this->context,
        );

        // Then
        static::assertSame($accessTokensBefore, $this->accessTokens->all());
        static::assertSame([], $this->events->of(TokenRevoked::class));
        foreach ($this->refreshTokens->all() as $refreshToken) {
            static::assertFalse($refreshToken->isRevoked());
        }
    }

    /**
     * @return iterable<string, array{callable(self): string}>
     */
    public static function provideTokensNotRevoked(): iterable
    {
        yield 'unknown' => [
            static fn (): string => 'unknown',
        ];
        yield 'a JWT that is not one of the provider' => [
            static fn (): string => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLm90aGVyLmV4YW1wbGUifQ.c2ln',
        ];
        yield 'an expired JWT of the provider' => [
            static fn (self $test): string => $test->jwt($test->code($test->client), $test->clock->now()->modify('-1 hour')),
        ];
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function anAccessTokenOfAnotherClientIsLeftAlone(): void
    {
        // Given
        $token = $this->accessToken($this->other);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
        );

        // Then
        static::assertNotNull($this->accessTokens->find($token));
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    #[Test]
    public function aRefreshTokenOfAnotherClientIsLeftAlone(): void
    {
        // Given
        $token = Tokens::refreshToken('theirs', $this->other, $this->session, $this->clock->now());
        $this->refreshTokens->save($token);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'theirs',
            ],
            $this->context,
        );

        // Then
        static::assertFalse($token->isRevoked());
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    #[Test]
    public function aRefreshTokenAlreadyRevokedIsLeftAsItWas(): void
    {
        // Given
        $token = Tokens::refreshToken('revoked', $this->client, $this->session, $this->clock->now()->modify('-1 day'));
        $token->revoke($this->clock->now()->modify('-1 hour'));
        $this->refreshTokens->save($token);
        $this->accessTokens->save(Tokens::storedAccessToken('of-the-grant', $this->client, $this->session, $this->clock->now(), $token->family->grantId));

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'revoked',
            ],
            $this->context,
        );

        // Then
        static::assertEquals($this->clock->now()->modify('-1 hour'), $token->revokedAt);
        static::assertCount(1, $this->accessTokens->all());
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    /**
     * RFC 7009 §2.2.1
     */
    #[Test]
    public function itRefusesToRevokeAJwtOfTheProvider(): void
    {
        // Given
        $token = $this->jwt($this->code($this->client), $this->clock->now());

        // Then
        $this->expectException(UnsupportedTokenTypeException::class);
        $this->expectExceptionMessageIs('unsupported_token_type: A self-contained access token cannot be revoked; it expires on its own (RFC 7009 section 2.2.1).');

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
        );
    }

    /**
     * RFC 7009 §2.2
     *
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideJwtsTheProviderNoLongerHonours')]
    public function itAnswersAJwtTheProviderNoLongerHonoursAsAnInvalidToken(callable $token): void
    {
        // Given
        $value = $token($this);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $value,
            ],
            $this->context,
        );

        // Then
        static::assertSame([], $this->events->of(TokenRevoked::class));
    }

    /**
     * @return iterable<string, array{callable(self): string}>
     */
    public static function provideJwtsTheProviderNoLongerHonours(): iterable
    {
        yield 'of a session that ended' => [static function (self $test): string {
            $token = $test->jwt($test->code($test->client), $test->clock->now());
            $test->session->end(SessionEnd::User, $test->clock->now());

            return $token;
        }];
        yield 'of a grant that was revoked' => [static function (self $test): string {
            $code = $test->code($test->client);
            $token = $test->jwt($code, $test->clock->now());
            $code->revoke($test->clock->now());

            return $token;
        }];
        yield 'of a person no longer served' => [static function (self $test): string {
            $token = $test->jwt($test->code($test->client), $test->clock->now());
            $test->session->user->disable($test->clock->now());

            return $token;
        }];
    }

    /**
     * RFC 7009 §2.2.1
     */
    #[Test]
    public function itRefusesToRevokeWhatTheStoreCannotTakeBack(): void
    {
        // Given
        $store = static::createStub(AccessTokenRepositoryInterface::class);
        $store
            ->method('find')
            ->willReturn(StoredUserAccessToken::fromAuthorization(
                str_repeat('a', 64),
                UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                    'the-code',
                    $this->client,
                    $this->session,
                    $this->clock->now(),
                )),
                $this->clock->now(),
                $this->clock->now()->modify('+10 minutes'),
            ));
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $handler = $this->handler($clients, new FakePasswordHasher(), $store);

        // Then
        $this->expectException(UnsupportedTokenTypeException::class);
        $this->expectExceptionMessageIs('unsupported_token_type: This provider does not take access tokens back; they expire on their own (RFC 7009 section 2.2.1).');

        // When
        $handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'whatever',
            ],
            $this->context,
        );
    }

    /**
     * RFC 7009 §2.1, RFC 6749 §2.3
     */
    #[Test]
    public function itRefusesACallerThatDoesNotAuthenticate(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo', 'wrong'),
            [
                'token' => 'whatever',
            ],
            $this->context,
        );
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function itRequiresTheToken(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The token parameter is missing.');

        // When
        $this->handler->handle($this->tenant, self::basic('oidc-demo'), [], $this->context);
    }

    private function handler(InMemoryClientRepository $clients, FakePasswordHasher $hasher, AccessTokenRepositoryInterface $accessTokens): RevocationHandler
    {
        $verifier = AccessTokenShapes::verifier(
            new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
            $clients,
            $accessTokens,
            Subjects::publicKind(),
        );

        return new RevocationHandler(
            new ClientAuthenticator(
                $clients,
                Methods::all($hasher),
                Methods::requestParser(),
                $this->clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            new Endpoints(),
            $verifier,
            new AccessTokenInspector($verifier, $this->sessions, new RecordedGrants([$this->grants]), Subjects::personOfAToken($this->users)),
            $accessTokens,
            $this->refreshTokens,
            $this->sessions,
            $this->events,
        );
    }

    private function accessToken(Client $client): string
    {
        return Tokens::accessToken(
            new OpaqueAccessTokenIssuer($this->accessTokens, Secrets::drawer()),
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code('the-code', $client, $this->session, $this->clock->now())),
            $this->clock->now(),
        )->value;
    }

    private function code(Client $client): AuthorizationCode
    {
        $code = Tokens::code('the-code', $client, $this->session, $this->clock->now());
        $this->grants->save($code);

        return $code;
    }

    private function jwt(AuthorizationCode $code, DateTimeImmutable $issuedAt): string
    {
        return Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
            ),
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            $issuedAt,
        )->value;
    }

    private static function basic(string $clientId, string $secret = Clients::SECRET): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
