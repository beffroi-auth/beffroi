<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use function array_map;
use function count;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
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
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Symfony\Component\Uid\Uuid;
use PHPUnit\Framework\Attributes\DataProvider;
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

    private WritesAsTheyCome $writes;

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
        $this->writes = new WritesAsTheyCome();
        $this->revocation = $this->revocationRecordedBy($this->events);
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

    #[Test]
    public function bothRevocationsAreWrittenInOneUnit(): void
    {
        // Given
        $this->refreshToken('current', $this->session);
        $writes = $this->writes;
        $accessTokens = new class($writes) implements CanRevokeAccessTokensBySessionInterface {
            public ?bool $removedInTheUnit = null;

            public function __construct(
                private readonly WritesAsTheyCome $writes,
            ) {
            }

            public function revokeBySession(Uuid $session): array
            {
                $this->removedInTheUnit = $this->writes->open;

                return [];
            }
        };
        $revocation = new SessionTokensRevocation(
            $this->refreshTokens,
            new RefreshTokenRevocation($this->refreshTokens, $this->refreshTokens),
            $accessTokens,
            $this->writes,
            $this->events,
        );

        // When
        $revocation->sessionEnded($this->session->id, $this->endedAt, $this->alice->tenant, $this->alice->subject, $this->context);

        // Then
        static::assertSame([1, true], [$this->writes->units, $accessTokens->removedInTheUnit]);
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
        $this->accessToken('opaque', $this->client);
        $this->accessToken('of-the-other', $other);

        // When
        $this->endTheSession();

        // Then
        static::assertSame([['oidc-demo', 2, 1], ['other-app', 0, 1]], $this->counted());
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
        $this->endTheSessionAsAnAdministrator($administrator);

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

    /**
     * Decision 0022
     */
    #[Test]
    #[DataProvider('provideRefreshTokensDeadAtTheEnd')]
    public function aRefreshTokenThatHadStoppedServingBeforeTheEndIsNotCounted(string $issued, ?string $rotated, ?string $revoked): void
    {
        // Given
        $token = Tokens::refreshToken('dead', $this->client, $this->session, $this->endedAt->modify($issued));
        if ($rotated !== null) {
            $token->rotate($this->endedAt->modify($rotated));
        }
        if ($revoked !== null) {
            $token->revoke($this->endedAt->modify($revoked));
        }
        $this->refreshTokens->save($token);

        // When
        $this->endTheSession();

        // Then
        static::assertSame([], $this->counted());
    }

    /**
     * @return iterable<string, array{string, ?string, ?string}>
     */
    public static function provideRefreshTokensDeadAtTheEnd(): iterable
    {
        yield 'rotated before the end' => ['-2 days', '-1 day', null];
        yield 'expired before the end' => ['-31 days', null, null];
        yield 'revoked before the end' => ['-2 days', null, '-1 day'];
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function anOpaqueAccessTokenExpiredBeforeTheEndIsNotCounted(): void
    {
        // Given
        $this->accessTokens->save(Tokens::storedAccessToken('expired', $this->client, $this->session, $this->endedAt->modify('-1 hour')));

        // When
        $this->endTheSession();

        // Then
        static::assertSame([], $this->counted());
    }

    #[Test]
    public function aRefreshTokenRotatedAfterTheEndWasServingAtItAndIsCounted(): void
    {
        // Given
        $token = $this->refreshToken('in-flight', $this->session);
        $token->rotate($this->endedAt->modify('+1 second'));

        // When
        $this->endTheSession();

        // Then
        static::assertSame([['oidc-demo', 1, 0]], $this->counted());
    }

    /**
     * beffroi/saml S-25
     */
    #[Test]
    public function aSuccessorSavedAfterTheEndWasHandledIsRevokedAtItsFirstUse(): void
    {
        // Given
        $family = Tokens::family(Fixtures::now(), $this->client->tenant);
        $this->refreshToken('rotated', $this->session, $family);
        $this->endTheSession();
        $successor = $this->refreshToken('successor', $this->session, $family, '+4 days');

        // When
        $this->revocation->outlived($this->session->id, $this->endedAt);

        // Then
        static::assertEquals($this->endedAt, $successor->revokedAt);
    }

    #[Test]
    public function aSuccessorRevokedAtItsFirstUseIsAnnouncedByNoAct(): void
    {
        // Given
        $family = Tokens::family(Fixtures::now(), $this->client->tenant);
        $this->refreshToken('rotated', $this->session, $family);
        $this->endTheSession();
        $this->refreshToken('successor', $this->session, $family, '+4 days');
        $this->events = new RecordingEventDispatcher();
        $revocation = $this->revocationRecordedBy($this->events);

        // When
        $revocation->outlived($this->session->id, $this->endedAt);

        // Then
        static::assertSame([], $this->events->events);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aRefreshBeforeTheEndIsHandledRevokesTheRefreshTokensAndAnnouncesNothing(): void
    {
        // Given
        $token = $this->refreshToken('held', $this->session);
        $this->accessToken('opaque', $this->client);

        // When
        $this->revocation->outlived($this->session->id, $this->endedAt);

        // Then
        static::assertSame([true, 1, []], [$token->isRevoked(), count($this->accessTokens->all()), $this->events->events]);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theEndHandledAfterSuchARefreshAnnouncesWhatTheSessionHeldUnderItsAuthor(): void
    {
        // Given
        $this->refreshToken('held', $this->session);
        $this->accessToken('opaque', $this->client);
        $this->revocation->outlived($this->session->id, $this->endedAt);
        $administrator = new Subject('administrator-subject');

        // When
        $this->endTheSessionAsAnAdministrator($administrator);

        // Then
        static::assertSame([['oidc-demo', 1, 1, 'administrator-subject']], array_map(
            static fn (SessionTokensRevoked $act): array => [$act->clientId, $act->refreshTokens, $act->accessTokens, $act->author()?->value],
            $this->events->of(SessionTokensRevoked::class),
        ));
    }

    private function endTheSession(): void
    {
        $this->revocation->sessionEnded($this->session->id, $this->endedAt, $this->alice->tenant, $this->alice->subject, $this->context);
    }

    private function endTheSessionAsAnAdministrator(Subject $administrator): void
    {
        $this->revocation->sessionEnded(
            $this->session->id,
            $this->endedAt,
            $this->alice->tenant,
            $this->alice->subject,
            $this->context,
            $administrator,
        );
    }

    private function revocationRecordedBy(RecordingEventDispatcher $events): SessionTokensRevocation
    {
        return new SessionTokensRevocation(
            $this->refreshTokens,
            new RefreshTokenRevocation($this->refreshTokens, $this->refreshTokens),
            $this->accessTokens,
            $this->writes,
            $events,
        );
    }

    /**
     * @return list<array{string, int, int}> each act by its client, the refresh tokens and the access tokens it counts
     */
    private function counted(): array
    {
        return array_map(
            static fn (SessionTokensRevoked $act): array => [$act->clientId, $act->refreshTokens, $act->accessTokens],
            $this->events->of(SessionTokensRevoked::class),
        );
    }

    private function accessToken(string $value, Client $client): void
    {
        $this->accessTokens->save(Tokens::storedAccessToken($value, $client, $this->session, $this->endedAt->modify('-1 minute')));
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
