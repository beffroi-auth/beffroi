<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\SuccessorWrittenAfterARead;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class RefreshTokenRevocationTest extends TestCase
{
    private User $alice;

    private Client $client;

    private AuthenticationSession $session;

    private MockClock $clock;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RefreshTokenFamily $family;

    private RefreshToken $first;

    private RefreshToken $second;

    private RefreshToken $alreadyRevoked;

    private RefreshToken $ofAnotherFamily;

    private RefreshTokenRevocation $revocation;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->client = Clients::public($this->alice->tenant);
        $this->session = Fixtures::session($this->alice);
        $this->clock = new MockClock('2026-09-20T10:00:00+00:00');
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $issuedAt = $this->clock->now()->modify('-1 hour');
        $this->family = Tokens::family($issuedAt, $this->client->tenant, 'the-code');
        $this->first = Tokens::refreshToken('first', $this->client, $this->session, $issuedAt, $this->family);
        $this->second = Tokens::refreshToken('second', $this->client, $this->session, $issuedAt->modify('+10 minutes'), $this->family);
        $this->alreadyRevoked = Tokens::refreshToken('revoked', $this->client, $this->session, $issuedAt, $this->family);
        $this->alreadyRevoked->revoke($issuedAt->modify('+5 minutes'));
        $this->ofAnotherFamily = Tokens::refreshToken(
            'other',
            $this->client,
            $this->session,
            $issuedAt,
            Tokens::family($issuedAt, $this->client->tenant, 'another-code'),
        );
        foreach ([$this->first, $this->second, $this->alreadyRevoked, $this->ofAnotherFamily] as $token) {
            $this->refreshTokens->save($token);
        }
        $this->revocation = new RefreshTokenRevocation($this->refreshTokens, $this->refreshTokens);
    }

    #[Test]
    public function itRevokesEveryLiveTokenOfAFamily(): void
    {
        // When
        $this->revocation->revokeFamily($this->family->id, $this->clock->now());

        // Then
        static::assertTrue($this->first->isRevoked());
        static::assertTrue($this->second->isRevoked());
        static::assertFalse($this->ofAnotherFamily->isRevoked());
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aSuccessorWrittenWhileItsFamilyIsRevokedIsRevokedToo(): void
    {
        // Given
        $successor = Tokens::refreshToken('successor', $this->client, $this->session, $this->clock->now(), $this->family);
        $revocation = new RefreshTokenRevocation(new SuccessorWrittenAfterARead($this->refreshTokens, $successor), $this->refreshTokens);

        // When
        $revocation->revokeFamily($this->family->id, $this->clock->now());

        // Then
        static::assertTrue($successor->isRevoked());
    }

    #[Test]
    public function itDatesTheRevocationNow(): void
    {
        // When
        $this->revocation->revokeFamily($this->family->id, $this->clock->now());

        // Then
        static::assertEquals($this->clock->now(), $this->first->revokedAt);
    }

    #[Test]
    public function itReturnsTheTokensRevokedByThisCallOnly(): void
    {
        // When
        $revoked = $this->revocation->revokeFamily($this->family->id, $this->clock->now());

        // Then
        static::assertSame([$this->first, $this->second], $revoked);
    }

    #[Test]
    public function aTokenAlreadyRevokedKeepsItsDate(): void
    {
        // Given
        $revokedAt = $this->alreadyRevoked->revokedAt;

        // When
        $this->revocation->revokeFamily($this->family->id, $this->clock->now());

        // Then
        static::assertEquals($revokedAt, $this->alreadyRevoked->revokedAt);
    }

    #[Test]
    public function itSavesEachTokenItRevokes(): void
    {
        // Given
        $saves = $this->refreshTokens->saves;

        // When
        $this->revocation->revokeFamily($this->family->id, $this->clock->now());

        // Then
        static::assertSame($saves + 2, $this->refreshTokens->saves);
    }

    #[Test]
    public function aSecondCallRevokesNothingAndReturnsNothing(): void
    {
        // Given
        $this->revocation->revokeFamily($this->family->id, $this->clock->now());

        // When
        $revoked = $this->revocation->revokeFamily($this->family->id, $this->clock->now()->modify('+1 minute'));

        // Then
        static::assertSame([], $revoked);
    }

    #[Test]
    public function itRevokesTheTokensDescendingFromACode(): void
    {
        // When
        $revoked = $this->revocation->revokeByAuthorizationCode($this->family->grantingRecordHash, $this->clock->now());

        // Then
        static::assertSame([$this->first, $this->second], $revoked);
        static::assertFalse($this->ofAnotherFamily->isRevoked());
    }

    #[Test]
    public function itRevokesTheTokensOfASession(): void
    {
        // Given
        $otherSession = Fixtures::session($this->alice);
        $ofAnotherSession = Tokens::refreshToken('elsewhere', $this->client, $otherSession, $this->clock->now()->modify('-1 hour'));
        $this->refreshTokens->save($ofAnotherSession);

        // When
        $revoked = $this->revocation->revokeBySession($this->session->id, $this->clock->now());

        // Then
        static::assertSame([$this->first, $this->second, $this->ofAnotherFamily], $revoked);
        static::assertFalse($ofAnotherSession->isRevoked());
    }

    #[Test]
    public function anUnknownFamilyRevokesNothing(): void
    {
        // When
        $revoked = $this->revocation->revokeFamily(Tokens::family($this->clock->now(), $this->client->tenant)->id, $this->clock->now());

        // Then
        static::assertSame([], $revoked);
    }
}
