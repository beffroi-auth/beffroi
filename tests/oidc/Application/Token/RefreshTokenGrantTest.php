<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\UnopenedRows;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Token\RefreshTokenGrant;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\RefreshTokenOutlivedItsSession;
use Beffroi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Beffroi\Oidc\Domain\Event\RefreshTokenRotated;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Domain\Token\IssuedRefreshToken;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidAuthorizationDetailsException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Port\RefreshTokenRotationInterface;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class RefreshTokenGrantTest extends TestCase
{
    private const string INVALID_GRANT = 'invalid_grant: The refresh token is invalid.';

    /**
     * RFC 7638 §3.1
     */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    private Tenant $tenant;

    private User $alice;

    private Client $client;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private InMemoryAuthorizationCodeRepository $grants;

    private FakeAccessTokenIssuer $accessTokenIssuer;

    private FakeIdTokenIssuer $idTokens;

    private RecordingEventDispatcher $events;

    private UnopenedRows $rows;

    private InMemoryAuthenticationSessionRepository $sessions;

    private TokenIssuer $issuer;

    private RefreshTokenGrant $grant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        // A public client: the refresh token of a confidential client is not rotated (RFC 9700 §4.14.2,
        // FAPI 2.0 Security Profile §5.3.2.1-9).
        $this->client = Clients::public($this->tenant);
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->sessions->save($this->session);
        $this->context = Fixtures::context($this->clock->now());
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->accessTokenIssuer = new FakeAccessTokenIssuer();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->events = new RecordingEventDispatcher();
        $this->rows = new UnopenedRows();
        $this->issuer = new TokenIssuer($this->accessTokenIssuer, $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events);
        $this->grant = $this->grantWith($this->refreshTokens);
    }

    #[Test]
    public function itHandlesTheRefreshTokenGrantType(): void
    {
        // When / Then
        static::assertTrue($this->grant->grantType()->equals(Grants::refreshToken()));
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.14
     */
    #[Test]
    public function itRotatesTheTokenPresented(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->clock->sleep(3600);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertTrue($token->isRotated());
        static::assertEquals($this->clock->now(), $token->rotatedAt);
        static::assertFalse($token->isRevoked());
    }

    /**
     * RFC 9700 §4.14
     */
    #[Test]
    public function itIssuesASuccessorInTheSameFamilyWithASlidingExpiry(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->clock->sleep(3600);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $successor = ($issued->refreshToken ?? static::fail('A refresh always issues a successor.'))->token;
        static::assertNotSame($token, $successor);
        static::assertNotSame($token->tokenHash, $successor->tokenHash);
        static::assertSame($token->family, $successor->family);
        static::assertSame($token->scopes, $successor->scopes);
        static::assertSame($this->client, $successor->client);
        static::assertSame($this->session, $successor->session);
        static::assertEquals($this->clock->now(), $successor->issuedAt);
        static::assertEquals($this->clock->now()->modify('+30 days'), $successor->expiresAt);
        static::assertEquals($token->authentication->authenticatedAt, $successor->authentication->authenticatedAt);
        static::assertFalse($successor->isRotated());
    }

    #[Test]
    public function theRotationAndTheSuccessorAreSaved(): void
    {
        // Given
        $token = $this->token('the-token');

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame([$token, $issued->refreshToken?->token], $this->refreshTokens->all());
        static::assertSame(2, $this->refreshTokens->saves, 'the token in setUp, the successor');
    }

    /**
     * RFC 6749 §6, OIDC Core §12.2
     */
    #[Test]
    public function itIssuesTheTokensForTheScopesAndTheAuthenticationOfTheToken(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->clock->sleep(3600);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(UserAuthorizationInterface::class, $authorization);
        static::assertTrue($authorization->grantType->equals(Grants::refreshToken()));
        static::assertSame($token->scopes, $authorization->scopes);
        static::assertNull($authorization->nonce);
        static::assertEquals($token->authentication->authenticatedAt, $authorization->authentication->authenticatedAt);
        static::assertSame('id:spa:alice-subject:-:' . $this->clock->now()->getTimestamp(), $issued->idToken);
        static::assertSame('openid profile', $issued->toResponse()->parameters()['scope']);
    }

    #[Test]
    public function theRotationIsAnnouncedWithBothTokensAndTheRequestContext(): void
    {
        // Given
        $token = $this->token('the-token');

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $successor = ($issued->refreshToken ?? static::fail('A refresh always issues a successor.'))->token;
        static::assertCount(2, $this->events->events);
        $rotations = $this->events->of(RefreshTokenRotated::class);
        static::assertCount(1, $rotations);
        static::assertSame($token->tokenHash, $rotations[0]->previousTokenHash);
        static::assertSame($successor->tokenHash, $rotations[0]->nextTokenHash);
        static::assertEquals($this->clock->now(), $rotations[0]->occurredAt);
        static::assertSame($this->tenant, $rotations[0]->tenant);
        static::assertSame($this->context, $rotations[0]->context);
        static::assertSame($successor->tokenHash, $this->events->of(TokensIssued::class)[0]->refreshTokenHash);
    }

    /**
     * RFC 6749 §6
     */
    #[Test]
    public function itNarrowsTheScopeOfTheResponse(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile', 'email']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'email profile email'), $this->context);

        // Then
        static::assertEquals([new Scope('email'), new Scope('profile')], $issued->authorization->scopes->all);
        static::assertSame($token->scopes, $issued->authorization->grantedScopes);
        static::assertSame('email profile', $issued->toResponse()->parameters()['scope']);
    }

    /**
     * RFC 6749 §6
     */
    #[Test]
    public function theSuccessorKeepsTheScopesGranted(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile', 'email']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'email profile email'), $this->context);

        // Then
        static::assertSame($token->scopes, ($issued->refreshToken ?? static::fail('A refresh always issues a successor.'))->token->scopes);
    }

    /**
     * OIDC Core §12.2
     */
    #[Test]
    public function noIdTokenIsIssuedBelowOpenid(): void
    {
        // Given
        $this->token('the-token', ['openid', 'profile', 'email']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'email profile'), $this->context);

        // Then
        static::assertNull($issued->idToken);
        static::assertSame([], $this->idTokens->issued);
    }

    #[Test]
    public function aScopeNarrowedOnceCanBeAskedForAgain(): void
    {
        // Given
        $this->token('the-token', ['openid', 'profile', 'email']);
        $narrowed = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(scope: 'email profile'),
            $this->context,
        )->refreshToken ?? static::fail('A refresh always issues a successor.');

        // When
        $again = $this->grant->grant(new AuthenticatedClient($this->client), $this->request($narrowed->value, 'openid'), $this->context);

        // Then
        static::assertNotNull($again->idToken);
    }

    /**
     * RFC 6749 §6
     */
    #[Test]
    public function itRefusesAScopeOutsideTheGrant(): void
    {
        // Given
        $this->token('the-token', ['openid', 'profile']);

        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIsOrContains('exceeds');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: 'openid email'), $this->context);
    }

    /**
     * OIDC Core §3.1.3.7
     */
    #[Test]
    public function aTokenIsNotRotatedWhileTheKeysOfItsClientCannotBeRead(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->idTokens->unreadableKeys = new ClientKeysUnavailableException('The keys of the client cannot be read.');

        // When
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        } catch (ClientKeysUnavailableException) {
        }

        // Then
        static::assertFalse($token->isRotated());
        static::assertSame([$token], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aTokenIsNotRotatedWhileTheKmsDoesNotAnswer(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->accessTokenIssuer->kmsOutage = new KmsUnavailableException('The KMS did not answer.');

        // When
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertFalse($token->isRotated());
        static::assertSame([$token], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenLeftAsItWasIsRefreshedOnceTheKmsAnswers(): void
    {
        // Given
        $this->token('the-token', ['openid', 'profile']);
        $this->accessTokenIssuer->kmsOutage = new KmsUnavailableException('The KMS did not answer.');
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        } catch (KmsUnavailableException) {
        }
        $this->accessTokenIssuer->kmsOutage = null;

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame([], $this->events->of(RefreshTokenReuseDetected::class));
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aTokenIsNotRotatedWhileItsSessionCannotBeOpened(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);
        $this->rows->unopen($this->session);
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // When
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertFalse($token->isRotated());
        static::assertSame([$token], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aTokenIsNotRotatedWhileItsPersonCannotBeOpened(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile'], session: $this->sessionOfAnUnopenedPerson());
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // When
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertFalse($token->isRotated());
        static::assertSame([$token], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenLeftAsItWasIsRefreshedOnceItsPersonOpens(): void
    {
        // Given
        $this->token('the-token', ['openid', 'profile'], session: $this->sessionOfAnUnopenedPerson());
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        } catch (KmsUnavailableException) {
        }
        $this->rows->outage = null;

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame([], $this->events->of(RefreshTokenReuseDetected::class));
    }

    #[Test]
    public function aScopeOutsideTheGrantRotatesNothing(): void
    {
        // Given
        $token = $this->token('the-token', ['openid', 'profile']);

        // When
        $this->failToGrant($this->request(scope: 'openid email'));

        // Then
        static::assertFalse($token->isRotated());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    #[DataProvider('provideMalformedScopes')]
    public function itRefusesAMalformedScope(string $scope): void
    {
        // Given
        $this->token('the-token');

        // When
        try {
            $this->grant->grant(new AuthenticatedClient($this->client), $this->request(scope: $scope), $this->context);
            static::fail('The scope should have been refused.');
        } catch (InvalidScopeException $exception) {
            // Then
            static::assertStringContainsString('RFC 6749 section 3.3', $exception->errorDescription);
            static::assertInstanceOf(InvalidArgumentException::class, $exception->getPrevious());
        }
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    #[DataProvider('provideMalformedScopes')]
    public function aMalformedScopeRotatesNothing(string $scope): void
    {
        // Given
        $token = $this->token('the-token');

        // When
        $this->failToGrant($this->request(scope: $scope));

        // Then
        static::assertFalse($token->isRotated());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedScopes(): iterable
    {
        yield 'two spaces' => ['openid  profile'];
        yield 'double quote' => ['open"id'];
        yield 'leading space' => [' openid'];
    }

    #[Test]
    public function itRequiresTheRefreshToken(): void
    {
        // Given
        $this->token('the-token');

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The refresh_token parameter is missing.');

        // When
        $this->grant->grant(
            new AuthenticatedClient($this->client),
            RequestParameters::of([
                'grant_type' => 'refresh_token',
            ]),
            $this->context,
        );
    }

    /**
     * RFC 6749 §5.2
     *
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideTokensThatAreNoGrant')]
    public function itRefusesAnUnknownOrForeignOrRevokedToken(callable $token): void
    {
        // Given
        $value = $token($this);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request($value), $this->context);
    }

    /**
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideTokensThatAreNoGrant')]
    public function aTokenThatIsNoGrantTriggersNothing(callable $token): void
    {
        // Given
        $value = $token($this);
        $savesBefore = $this->refreshTokens->saves;

        // When
        $this->failToGrant($this->request($value));

        // Then
        static::assertSame([], $this->events->events);
        static::assertSame($savesBefore, $this->refreshTokens->saves);
    }

    /**
     * @return iterable<string, array{callable(self): string}>
     */
    public static function provideTokensThatAreNoGrant(): iterable
    {
        yield 'unknown' => [
            static fn (self $test): string => 'unknown',
        ];
        yield 'issued to another client, rotated' => [static function (self $test): string {
            $foreign = $test->token('foreign', client: Clients::confidential($test->tenant, new FakePasswordHasher()->hash(Clients::SECRET)));
            $foreign->rotate($test->clock->now());
            $test->refreshTokens->save($foreign);

            return 'foreign';
        }];
        yield 'revoked' => [static function (self $test): string {
            $revoked = $test->token('revoked');
            $revoked->revoke($test->clock->now());
            $test->refreshTokens->save($revoked);

            return 'revoked';
        }];
        yield 'of a grant revoked since it was issued' => [static function (self $test): string {
            $test->grantOf($test->token('of-a-revoked-grant'))->revoke($test->clock->now());

            return 'of-a-revoked-grant';
        }];
        yield 'of a grant no store holds' => [static function (self $test): string {
            $test->refreshTokens->save(Tokens::refreshToken('of-no-grant', $test->client, $test->session, $test->clock->now()));

            return 'of-no-grant';
        }];
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function itRefusesARotatedTokenPresentedAgain(): void
    {
        // Given
        $this->token('first');
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('first'), $this->context);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('first'), $this->context);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aRotatedTokenPresentedAgainRevokesTheWholeFamily(): void
    {
        // Given
        $first = $this->token('first', ['openid', 'profile']);
        $other = $this->token('other', family: Tokens::family($this->clock->now(), $this->client->tenant, 'other-code'));
        [$second, $third] = $this->twoRotationsOf('first');

        // When
        $this->failToGrant($this->request('first'));

        // Then
        foreach ([$first, $second->token, $third->token] as $token) {
            static::assertTrue($token->isRevoked());
            static::assertEquals($this->clock->now(), $token->revokedAt);
        }
        static::assertFalse($other->isRevoked());
        static::assertSame(7, $this->refreshTokens->saves, 'two fixtures, two successors, three revocations');
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenAnotherRequestRotatedFirstIsRefused(): void
    {
        // Given
        $this->token('the-token');

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grantWith(self::rotationLostToAnotherRequest())->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenAnotherRequestRotatedFirstRevokesItsFamilyWithTheSuccessorWritten(): void
    {
        // Given
        $token = $this->token('the-token');

        // When
        $this->failToGrant($this->request(), $this->grantWith(self::rotationLostToAnotherRequest()));

        // Then
        static::assertSame(
            [true, true],
            array_map(static fn (RefreshToken $member): bool => $member->isRevoked(), $this->refreshTokens->findByFamily($token->family->id)),
        );
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenAnotherRequestRotatedFirstIsAnnouncedAsAReuse(): void
    {
        // Given
        $token = $this->token('the-token');

        // When
        $this->failToGrant($this->request(), $this->grantWith(self::rotationLostToAnotherRequest()));

        // Then
        $detections = $this->events->of(RefreshTokenReuseDetected::class);
        static::assertCount(1, $detections);
        static::assertSame($token->tokenHash, $detections[0]->presentedTokenHash);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function theSuccessorIsInTheStoreBeforeTheRotationIsClaimed(): void
    {
        // Given
        $token = $this->token('the-token');
        $familyAtTheClaim = [];
        $rotations = static::createStub(RefreshTokenRotationInterface::class);
        $rotations
            ->method('rotate')
            ->willReturnCallback(function (RefreshToken $presented, DateTimeImmutable $now) use (&$familyAtTheClaim): bool {
                $familyAtTheClaim = $this->refreshTokens->findByFamily($presented->family->id);

                return $this->refreshTokens->rotate($presented, $now);
            });

        // When
        $issued = $this->grantWith($rotations)->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame([$token, $issued->refreshToken?->token], $familyAtTheClaim);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aReuseIsAnnouncedWithWhatWasRevoked(): void
    {
        // Given
        $first = $this->token('first', ['openid', 'profile']);
        [$second, $third] = $this->twoRotationsOf('first');

        // When
        $this->failToGrant($this->request('first'));

        // Then
        $detections = $this->events->of(RefreshTokenReuseDetected::class);
        static::assertCount(1, $detections);
        static::assertSame($first->tokenHash, $detections[0]->presentedTokenHash);
        static::assertSame([$first->tokenHash, $second->token->tokenHash, $third->token->tokenHash], $detections[0]->revokedTokenHashes);
        static::assertEquals($this->clock->now(), $detections[0]->occurredAt);
        static::assertSame($this->tenant, $detections[0]->tenant);
        static::assertSame($this->context, $detections[0]->context);
        static::assertCount(2, $this->events->of(TokensIssued::class));
    }

    #[Test]
    public function aRevokedFamilyIsNotDetectedAgain(): void
    {
        // Given
        $this->token('first', ['openid', 'profile']);
        [$second, $third] = $this->twoRotationsOf('first');
        $this->failToGrant($this->request('first'));

        // When
        $this->failToGrant($this->request($third->value));
        $this->failToGrant($this->request($second->value));

        // Then
        static::assertCount(1, $this->events->of(RefreshTokenReuseDetected::class));
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aReuseIsRefusedAsSuchWhileItsSessionCannotBeOpened(): void
    {
        // Given
        $this->rotatedOnAnotherWorker('first', $this->rows->unopenedSession($this->session));
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('first'), $this->context);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aReuseIsAnnouncedWithWhatWasRevokedWhileItsSessionCannotBeOpened(): void
    {
        // Given
        $session = $this->rows->unopenedSession($this->session);
        $first = $this->rotatedOnAnotherWorker('first', $session);
        $successor = $this->token('successor', family: $first->family, session: $session);
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // When
        $this->failToGrant($this->request('first'));

        // Then
        $detections = $this->events->of(RefreshTokenReuseDetected::class);
        static::assertCount(1, $detections);
        static::assertEquals($this->alice->subject, $detections[0]->subject);
        static::assertSame([$first->tokenHash, $successor->tokenHash], $detections[0]->revokedTokenHashes);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function aRefreshOnTheLastSecondSlidesTheExpiry(): void
    {
        // Given
        $this->token('sliding');
        $this->clock->sleep((30 * 86400) - 1);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request('sliding'), $this->context);

        // Then
        $successor = $issued->refreshToken ?? static::fail('A refresh always issues a successor.');
        static::assertEquals($this->clock->now()->modify('+30 days'), $successor->token->expiresAt);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itRefusesATokenPastItsSlidingExpiry(): void
    {
        // Given
        $this->token('sliding');
        $this->clock->sleep(30 * 86400);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('sliding'), $this->context);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itRefusesATokenWhoseFamilyExpired(): void
    {
        // Given
        $this->token('absolute', family: Tokens::family($this->clock->now()->modify('-89 days'), $this->client->tenant, 'old-code'));
        $this->clock->sleep(30 * 86400);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('absolute'), $this->context);
    }

    #[Test]
    public function anExpiredTokenIsNoReuse(): void
    {
        // Given
        $this->token('sliding');
        $this->clock->sleep(30 * 86400);

        // When
        $this->failToGrant($this->request('sliding'));

        // Then
        static::assertSame([], $this->events->of(RefreshTokenReuseDetected::class));
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function itRefusesATokenWhoseSessionHasEnded(): void
    {
        // Given
        $ended = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->token('ended', session: $ended);
        $ended->end(SessionEnd::User, $this->clock->now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('ended'), $this->context);
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function aTokenWhoseSessionHasEndedIsAnnounced(): void
    {
        // Given
        $ended = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->token('ended', session: $ended);
        $endedAt = $this->clock->now()->modify('-1 minute');
        $ended->end(SessionEnd::User, $endedAt);

        // When
        $this->failToGrant($this->request('ended'));

        // Then
        static::assertEquals(
            [new RefreshTokenOutlivedItsSession(
                $this->clock->now(),
                $this->tenant,
                $this->client->registration->clientId,
                $this->alice->subject,
                $ended->id,
                $endedAt,
                $this->context,
            )],
            $this->events->events,
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function itRefusesATokenOfAPersonDisabledSince(): void
    {
        // Given
        $this->token('the-token');
        $this->alice->disable($this->clock->now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('the-token'), $this->context);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aTokenOfADisabledPersonRotatesNothing(): void
    {
        // Given
        $token = $this->token('the-token');
        $this->alice->disable($this->clock->now());

        // When
        $this->failToGrant($this->request('the-token'));

        // Then
        static::assertSame([false, []], [$token->isRotated(), $this->events->events]);
    }

    #[Test]
    public function itHonoursATokenWhoseSessionExpired(): void
    {
        // Given
        $this->token('expired', session: Fixtures::session($this->alice, $this->clock->now()->modify('-2 days')));

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request('expired'), $this->context);

        // Then
        static::assertNotNull($issued->idToken);
    }

    /**
     * RFC 8707 §2.2
     */
    #[Test]
    public function aRefreshAddressesTheAccessTokenToTheResourcesOfTheGrant(): void
    {
        // Given
        $this->token('the-token', resources: ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]));

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $issued->authorization->audience()->values);
    }

    /**
     * RFC 8707 §2.2
     */
    #[Test]
    public function aRefreshNarrowsTheResourcesOfTheGrant(): void
    {
        // Given
        $this->token('the-token', resources: ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]));

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(resource: Clients::CONTACTS),
            $this->context,
        );

        // Then
        static::assertSame([Clients::CONTACTS], $issued->authorization->audience()->values);
    }

    /**
     * RFC 8707 §2.2
     */
    #[Test]
    public function itRefusesAResourceTheGrantDoesNotCarry(): void
    {
        // Given
        $this->token('the-token', resources: ResourceIndicators::of([Clients::CALENDAR]));

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: The requested resource is not among the resources of this authorization (RFC 8707 section 2.2).');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(resource: Clients::CONTACTS), $this->context);
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aRefreshCarriesTheDetailsOfTheGrant(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details();
        $this->token('the-token', authorizationDetails: $details);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertTrue(self::userAuthorization($issued)->authorizationDetails?->equals($details));
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aRefreshNarrowsTheDetailsOfTheGrant(): void
    {
        // Given
        $granted = new AuthorizationDetails([
            AuthorizationDetailTypes::detail('acct-4711'),
            AuthorizationDetailTypes::detail('acct-0815'),
        ]);
        $this->token('the-token', authorizationDetails: $granted);

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(authorizationDetails: AuthorizationDetailTypes::parameter('acct-0815')),
            $this->context,
        );

        // Then
        static::assertTrue(self::userAuthorization($issued)->authorizationDetails?->equals(AuthorizationDetailTypes::details('acct-0815')));
        static::assertTrue(self::userAuthorization($issued)->grantedAuthorizationDetails?->equals($granted));
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function itRefusesADetailTheGrantDoesNotCarry(): void
    {
        // Given
        $this->token('the-token', authorizationDetails: AuthorizationDetailTypes::details('acct-4711'));

        // Then
        $this->expectException(InvalidAuthorizationDetailsException::class);
        $this->expectExceptionMessageIs('invalid_authorization_details: The requested authorization detail is not among the details of this authorization (RFC 9396 section 7).');

        // When
        $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(authorizationDetails: AuthorizationDetailTypes::parameter('acct-0815')),
            $this->context,
        );
    }

    /**
     * @param list<string> $scopes
     */
    private function token(
        string $value,
        array $scopes = ['openid'],
        ?Client $client = null,
        ?RefreshTokenFamily $family = null,
        ?AuthenticationSession $session = null,
        ?ResourceIndicators $resources = null,
        ?AuthorizationDetails $authorizationDetails = null,
        ?ConfirmationInterface $confirmation = null,
    ): RefreshToken {
        $token = Tokens::refreshToken(
            $value,
            $client ?? $this->client,
            $session ?? $this->session,
            $this->clock->now(),
            $family,
            $scopes,
            confirmation: $confirmation,
            resources: $resources,
            authorizationDetails: $authorizationDetails,
        );
        $this->refreshTokens->save($token);
        $this->grantOf($token);

        return $token;
    }

    private function grantOf(RefreshToken $token): AuthorizationCode
    {
        $grant = $this->grants->findByGrantId($token->family->grantId) ?? Tokens::code(
            $token->family->id->toRfc4122(),
            $token->client,
            $token->session,
            $token->family->startedAt,
            grantId: $token->family->grantId,
        );
        $this->grants->save($grant);

        return $grant;
    }

    private function rotatedOnAnotherWorker(string $value, AuthenticationSession $session): RefreshToken
    {
        $token = $this->token($value, session: $session);
        $token->rotate($this->clock->now());
        $this->refreshTokens->save($token);

        return $token;
    }

    private function sessionOfAnUnopenedPerson(): AuthenticationSession
    {
        return Fixtures::session($this->rows->unopened($this->alice, ['id', 'tenant']), $this->clock->now()->modify('-1 hour'));
    }

    /**
     * RFC 9449 §5
     */
    #[Test]
    public function aBoundTokenIsRefreshedByARequestThatProvesItsKey(): void
    {
        // Given
        $key = new KeyConfirmation(self::THUMBPRINT);
        $this->token('the-token', confirmation: $key);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client, $key), $this->request(), $this->context);

        // Then
        static::assertEquals($key, $issued->authorization->confirmation);
    }

    #[Test]
    #[DataProvider('provideOtherProofs')]
    public function aBoundTokenIsNotRefreshedByARequestThatProvesAnythingElse(?string $thumbprint): void
    {
        // Given
        $this->token('the-token', confirmation: new KeyConfirmation(self::THUMBPRINT));
        $proven = $thumbprint === null ? null : new KeyConfirmation($thumbprint);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client, $proven), $this->request(), $this->context);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideOtherProofs(): iterable
    {
        yield 'another key' => ['5bPRpDFfR6QNNOFrxJLPHlbCcFEHFwWVtOJQCg8h2hM'];
        yield 'no proof at all' => [null];
    }

    /**
     * @param string|list<string>|null $resource RFC 8707 §2.2
     */
    private function request(
        string $refreshToken = 'the-token',
        ?string $scope = null,
        string|array|null $resource = null,
        ?string $authorizationDetails = null,
    ): RequestParameters {
        $parameters = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];
        if ($scope !== null) {
            $parameters['scope'] = $scope;
        }
        if ($resource !== null) {
            $parameters['resource'] = $resource;
        }
        if ($authorizationDetails !== null) {
            $parameters['authorization_details'] = $authorizationDetails;
        }

        return RequestParameters::of($parameters);
    }

    private function failToGrant(RequestParameters $request, ?RefreshTokenGrant $grant = null): void
    {
        try {
            ($grant ?? $this->grant)->grant(new AuthenticatedClient($this->client), $request, $this->context);
            static::fail('The grant should have failed.');
        } catch (OAuth2Exception) {
        }
    }

    private function grantWith(RefreshTokenRotationInterface $rotations): RefreshTokenGrant
    {
        return new RefreshTokenGrant(
            $this->refreshTokens,
            $rotations,
            $this->grants,
            new RefreshTokenRevocation($this->refreshTokens, $this->refreshTokens),
            $this->sessions,
            $this->issuer,
            new RequestedAuthorizationDetails(AuthorizationDetailTypes::served()),
            $this->clock,
            $this->events,
        );
    }

    /**
     * What a request sees when another one rotated or revoked the token between its read and its claim.
     */
    private static function rotationLostToAnotherRequest(): RefreshTokenRotationInterface
    {
        $rotations = static::createStub(RefreshTokenRotationInterface::class);
        $rotations->method('rotate')->willReturn(false);

        return $rotations;
    }

    /**
     * @return array{IssuedRefreshToken, IssuedRefreshToken}
     */
    private function twoRotationsOf(string $value): array
    {
        $this->clock->sleep(60);
        $second = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request($value),
            $this->context,
        )->refreshToken ?? static::fail('A refresh always issues a successor.');
        $this->clock->sleep(60);
        $third = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request($second->value),
            $this->context,
        )->refreshToken ?? static::fail('A refresh always issues a successor.');
        $this->clock->sleep(60);

        return [$second, $third];
    }

    private static function userAuthorization(IssuedTokens $issued): UserAuthorizationInterface
    {
        $authorization = $issued->authorization;
        static::assertInstanceOf(UserAuthorizationInterface::class, $authorization);

        return $authorization;
    }
}
