<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #741, architecture §4.9, decision 0006: what was issued under a session is taken out of use when the
 * session ends, whatever ended it.
 */
final class SessionTokensRevocationTest extends TestCase
{
    private User $alice;

    private Client $client;

    private AuthenticationSession $session;

    private DateTimeImmutable $endedAt;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private InMemoryAccessTokenRepository $accessTokens;

    private SessionTokensRevocation $revocation;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user(Fixtures::tenant());
        $this->client = Clients::confidential($this->alice->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->session = Fixtures::session($this->alice);
        $this->endedAt = Fixtures::now()->modify('+5 days');
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->accessTokens = new InMemoryAccessTokenRepository();
        $this->revocation = new SessionTokensRevocation(new RefreshTokenRevocation($this->refreshTokens), $this->accessTokens);
    }

    /**
     * Every refresh token issued in the session is revoked, a rotated one included, dated by the end of the
     * session and not by the run that revokes it.
     */
    #[Test]
    public function theRefreshTokensOfTheSessionAreRevokedAtItsEnd(): void
    {
        // Given
        $family = Tokens::family(Fixtures::now(), $this->client->tenant);
        $rotated = $this->refreshToken('rotated', $this->session, $family);
        $rotated->rotate(Fixtures::now()->modify('+1 day'));
        $current = $this->refreshToken('current', $this->session, $family, '+2 days');

        // When
        $this->revocation->sessionEnded($this->session->id, $this->endedAt);

        // Then
        static::assertEquals([$this->endedAt, $this->endedAt], [$rotated->revokedAt, $current->revokedAt]);
    }

    #[Test]
    public function theRefreshTokensOfAnotherSessionAreNotRevoked(): void
    {
        // Given
        $elsewhere = $this->refreshToken('elsewhere', Fixtures::session($this->alice));

        // When
        $this->revocation->sessionEnded($this->session->id, $this->endedAt);

        // Then
        static::assertFalse($elsewhere->isRevoked());
    }

    /**
     * An opaque access token of the session is removed, an unknown token being an invalid one
     * (RFC 6750 §3.1); one of another session stays.
     */
    #[Test]
    public function theStoredAccessTokensOfTheSessionAreRemoved(): void
    {
        // Given
        $this->accessTokens->save(Tokens::storedAccessToken('here', $this->client, $this->session, Fixtures::now()));
        $elsewhere = Tokens::storedAccessToken('elsewhere', $this->client, Fixtures::session($this->alice), Fixtures::now());
        $this->accessTokens->save($elsewhere);

        // When
        $this->revocation->sessionEnded($this->session->id, $this->endedAt);

        // Then
        static::assertSame([$elsewhere], $this->accessTokens->all());
    }

    /**
     * A refresh token of the session, issued at the fixture's "now" plus an offset, saved.
     */
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
