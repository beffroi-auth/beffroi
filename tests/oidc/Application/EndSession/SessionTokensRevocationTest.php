<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §4.9, Decision 0006
 */
final class SessionTokensRevocationTest extends TestCase
{
    private User $alice;

    private Client $client;

    private AuthenticationSession $session;

    private DateTimeImmutable $endedAt;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private InMemoryAccessTokenRepository $accessTokens;

    private RecordingEventDispatcher $events;

    private RequestContext $context;

    private SessionTokensRevocation $revocation;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user(Fixtures::tenant());
        $this->client = Clients::confidential($this->alice->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->session = Fixtures::session($this->alice);
        $this->endedAt = Fixtures::now()->modify('+5 days');
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->accessTokens = new InMemoryAccessTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->context = Fixtures::context($this->endedAt);
        $this->revocation = new SessionTokensRevocation(new RefreshTokenRevocation($this->refreshTokens), $this->accessTokens, $this->events);
    }

    #[Test]
    public function theRefreshTokensOfTheSessionAreRevokedAtItsEnd(): void
    {
        // Given
        $family = Tokens::family(Fixtures::now(), $this->client->tenant);
        $rotated = $this->refreshToken('rotated', $this->session, $family);
        $rotated->rotate(Fixtures::now()->modify('+1 day'));
        $current = $this->refreshToken('current', $this->session, $family, '+2 days');

        // When
        $this->endTheSession();

        // Then
        static::assertEquals([$this->endedAt, $this->endedAt], [$rotated->revokedAt, $current->revokedAt]);
    }

    #[Test]
    public function theRefreshTokensOfAnotherSessionAreNotRevoked(): void
    {
        // Given
        $elsewhere = $this->refreshToken('elsewhere', Fixtures::session($this->alice));

        // When
        $this->endTheSession();

        // Then
        static::assertFalse($elsewhere->isRevoked());
    }

    /**
     * RFC 6750 §3.1
     */
    #[Test]
    public function theStoredAccessTokensOfTheSessionAreRemoved(): void
    {
        // Given
        $this->accessTokens->save(Tokens::storedAccessToken('here', $this->client, $this->session, Fixtures::now()));
        $elsewhere = Tokens::storedAccessToken('elsewhere', $this->client, Fixtures::session($this->alice), Fixtures::now());
        $this->accessTokens->save($elsewhere);

        // When
        $this->endTheSession();

        // Then
        static::assertSame([$elsewhere], $this->accessTokens->all());
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function eachClientThatLostATokenIsAnActThatCountsWhatItLost(): void
    {
        // Given
        $other = Clients::public($this->alice->tenant, 'other-app');
        $this->refreshToken('first', $this->session);
        $this->refreshToken('second', $this->session, issuedOffset: '+1 hour');
        $this->accessTokens->save(Tokens::storedAccessToken('opaque', $this->client, $this->session, Fixtures::now()));
        $this->accessTokens->save(Tokens::storedAccessToken('of-the-other', $other, $this->session, Fixtures::now()));

        // When
        $this->endTheSession();

        // Then
        static::assertSame(
            [['oidc-demo', 2, 1], ['other-app', 0, 1]],
            array_map(
                static fn (SessionTokensRevoked $act): array => [$act->clientId, $act->refreshTokens, $act->accessTokens],
                $this->events->of(SessionTokensRevoked::class),
            ),
        );
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function theActNamesThePersonTheSessionAndTheMomentAndPlaceOfItsEnd(): void
    {
        // Given
        $this->refreshToken('current', $this->session);

        // When
        $this->endTheSession();

        // Then
        $act = $this->events->of(SessionTokensRevoked::class)[0] ?? static::fail('The end of the session raised no act.');
        static::assertEquals(
            [$this->alice->tenant, $this->alice->subject, $this->session->id, $this->endedAt, $this->context, null],
            [$act->tenant, $act->subject(), $act->sessionId, $act->occurredAt, $act->context, $act->author()],
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theActOfASessionAnAdministratorEndedNamesThem(): void
    {
        // Given
        $this->refreshToken('current', $this->session);
        $administrator = new Subject('administrator-subject');

        // When
        $this->revocation->sessionEnded(
            $this->session->id,
            $this->endedAt,
            $this->alice->tenant,
            $this->alice->subject,
            $this->context,
            $administrator,
        );

        // Then
        static::assertSame([$administrator], array_map(
            static fn (SessionTokensRevoked $act): ?Subject => $act->author(),
            $this->events->of(SessionTokensRevoked::class),
        ));
    }

    #[Test]
    public function aSessionThatHeldNoTokenRaisesNoAct(): void
    {
        // Given
        $this->refreshToken('elsewhere', Fixtures::session($this->alice));

        // When
        $this->endTheSession();

        // Then
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aTokenRevokedBeforeTheEndIsNotCounted(): void
    {
        // Given
        $revoked = $this->refreshToken('revoked', $this->session);
        $revoked->revoke(Fixtures::now()->modify('+1 day'));
        $this->refreshToken('current', $this->session);

        // When
        $this->endTheSession();

        // Then
        static::assertSame([1], array_map(
            static fn (SessionTokensRevoked $act): int => $act->refreshTokens,
            $this->events->of(SessionTokensRevoked::class),
        ));
    }

    #[Test]
    public function aSuccessorSavedAfterTheEndIsCountedAloneWhenItIsRevoked(): void
    {
        // Given
        $family = Tokens::family(Fixtures::now(), $this->client->tenant);
        $this->refreshToken('rotated', $this->session, $family);
        $this->endTheSession();
        $this->refreshToken('successor', $this->session, $family, '+1 hour');

        // When
        $this->endTheSession();

        // Then
        static::assertSame([1, 1], array_map(
            static fn (SessionTokensRevoked $act): int => $act->refreshTokens,
            $this->events->of(SessionTokensRevoked::class),
        ));
    }

    private function endTheSession(): void
    {
        $this->revocation->sessionEnded($this->session->id, $this->endedAt, $this->alice->tenant, $this->alice->subject, $this->context);
    }

    private function refreshToken(
        string $value,
        AuthenticationSession $session,
        ?RefreshTokenFamily $family = null,
        string $issuedOffset = '+0 seconds',
    ): RefreshToken {
        $token = Tokens::refreshToken($value, $this->client, $session, Fixtures::now()->modify($issuedOffset), $family);
        $this->refreshTokens->save($token);

        return $token;
    }
}
