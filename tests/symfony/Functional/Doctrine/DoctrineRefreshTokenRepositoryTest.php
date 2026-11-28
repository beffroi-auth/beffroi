<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use function array_map;
use function sprintf;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\CanRevokeARefreshTokenOnceInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRotationInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * Architecture §4.6, §5.3
 */
final class DoctrineRefreshTokenRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aTokenComesBackWithItsFamilyAndWhatTheNextRefreshNeeds(): void
    {
        // Given
        $session = self::session(self::user());
        $client = self::client();
        $family = self::family();
        $claims = new ClaimsRequest([], [
            'acr' => new ClaimRequest(true),
        ]);
        $token = Secrets::draw();
        self::tokens()->save(self::token($token, $client, $session, $family, $claims, self::now()->modify('+1 minute')));
        self::reload();

        // When
        $found = self::tokens()->findByTokenHash(DrawnSecret::digestOf($token)) ?? static::fail('The token was not stored.');

        // Then
        static::assertSame(DrawnSecret::digestOf($token), $found->tokenHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->registration->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertTrue($found->family->id->equals($family->id));
        static::assertSame($family->grantingRecordHash, $found->family->grantingRecordHash);
        static::assertEquals($family->startedAt, $found->family->startedAt);
        static::assertEquals($family->expiresAt, $found->family->expiresAt);
        static::assertEquals([new Scope('openid'), new Scope('offline_access')], $found->scopes->all);
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authentication->authenticatedAt);
        static::assertSame(['pwd'], $found->authentication->methods);
        static::assertSame('1', $found->authentication->contextClass);
        static::assertEquals(self::now()->modify('+1 minute'), $found->issuedAt);
        static::assertEquals(self::now()->modify('+30 days'), $found->expiresAt);
        static::assertNull($found->rotatedAt);
        static::assertNull($found->revokedAt);
    }

    #[Test]
    public function aRotationIsWrittenOnSave(): void
    {
        // Given
        $token = self::token(Secrets::draw(), self::client(), self::session(self::user()), self::family(), null, self::now()->modify('+1 minute'));
        self::tokens()->save($token);
        $token->rotate(self::now()->modify('+1 hour'));
        self::tokens()->save($token);
        self::reload();

        // When
        $rotated = self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');

        // Then
        static::assertTrue($rotated->isRotated());
        static::assertEquals(self::now()->modify('+1 hour'), $rotated->rotatedAt);
        static::assertFalse($rotated->isRevoked());
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aRotationClaimedIsWrittenToTheStore(): void
    {
        // Given
        $token = self::stored();

        // When
        self::rotation()->rotate($token, self::now()->modify('+1 hour'));

        // Then
        self::reload();
        $rotated = self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');
        static::assertEquals(self::now()->modify('+1 hour'), $rotated->rotatedAt);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aRotationClaimedMarksTheCopyOfTheCaller(): void
    {
        // Given
        $token = self::stored();

        // When
        self::rotation()->rotate($token, self::now()->modify('+1 hour'));

        // Then
        static::assertEquals(self::now()->modify('+1 hour'), $token->rotatedAt);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenAnotherRequestRotatedIsNotRotatedAgain(): void
    {
        // Given
        $token = self::stored();
        self::changedByAnotherRequest($token, 'rotated_at');

        // When / Then
        static::assertFalse(self::rotation()->rotate($token, self::now()->modify('+1 hour')));
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aTokenAnotherRequestRevokedIsNotRotated(): void
    {
        // Given
        $token = self::stored();
        self::changedByAnotherRequest($token, 'revoked_at');

        // When / Then
        static::assertFalse(self::rotation()->rotate($token, self::now()->modify('+1 hour')));
    }

    #[Test]
    public function aRevocationClaimedIsWrittenToTheStore(): void
    {
        // Given
        $token = self::stored();

        // When
        self::revocation()->revokeOnce($token, self::now()->modify('+1 hour'));

        // Then
        self::reload();
        $revoked = self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');
        static::assertEquals(self::now()->modify('+1 hour'), $revoked->revokedAt);
    }

    #[Test]
    public function aRevocationClaimedMarksTheCopyOfTheCaller(): void
    {
        // Given
        $token = self::stored();

        // When
        self::revocation()->revokeOnce($token, self::now()->modify('+1 hour'));

        // Then
        static::assertEquals(self::now()->modify('+1 hour'), $token->revokedAt);
    }

    #[Test]
    public function aTokenAnotherWorkerRevokedIsNotRevokedAgain(): void
    {
        // Given
        $token = self::stored();
        self::changedByAnotherRequest($token, 'revoked_at');

        // When / Then
        static::assertFalse(self::revocation()->revokeOnce($token, self::now()->modify('+1 hour')));
    }

    #[Test]
    public function aTokenAnotherWorkerRevokedIsReadBackRevokedByTheCaller(): void
    {
        // Given
        $token = self::stored();
        self::changedByAnotherRequest($token, 'revoked_at');

        // When
        self::revocation()->revokeOnce($token, self::now()->modify('+1 hour'));

        // Then
        static::assertEquals(self::now()->modify('+30 minutes'), $token->revokedAt);
    }

    #[Test]
    public function aTokenTheSweepTookInBetweenIsNotRevoked(): void
    {
        // Given
        $token = self::stored();
        self::entityManager()->getConnection()->executeStatement('DELETE FROM beffroi_refresh_token WHERE token_hash = ?', [$token->tokenHash]);

        // When / Then
        static::assertFalse(self::revocation()->revokeOnce($token, self::now()->modify('+1 hour')));
    }

    #[Test]
    public function aRevocationIsWrittenOnSave(): void
    {
        // Given
        $token = self::token(Secrets::draw(), self::client(), self::session(self::user()), self::family(), null, self::now()->modify('+1 hour'));
        self::tokens()->save($token);
        $token->revoke(self::now()->modify('+2 hours'));
        self::tokens()->save($token);
        self::reload();

        // When
        $revoked = self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');

        // Then
        static::assertTrue($revoked->isRevoked());
        static::assertEquals(self::now()->modify('+2 hours'), $revoked->revokedAt);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function tokensAreFoundByFamilyInIssuanceOrder(): void
    {
        // Given
        ['family' => $family, 'first' => $first, 'second' => $second, 'sibling' => $sibling, 'third' => $third] = self::twoFamilies();

        // When / Then
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes(self::tokens()->findByFamily($family->id)));
        static::assertSame([$third->tokenHash], self::hashes(self::tokens()->findByFamily($sibling->id)));
        static::assertSame([], self::hashes(self::tokens()->findByFamily(Uuid::v7())));
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    public function tokensAreFoundByAuthorizationCode(): void
    {
        // Given
        ['family' => $family, 'first' => $first, 'second' => $second] = self::twoFamilies();

        // When / Then
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes(self::tokens()->findByAuthorizationCode($family->grantingRecordHash)));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function tokensAreFoundBySession(): void
    {
        // Given
        ['aliceSession' => $aliceSession, 'first' => $first, 'second' => $second, 'otherSession' => $otherSession, 'third' => $third] = self::twoFamilies();

        // When / Then
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes(self::tokens()->findBySession($aliceSession->id)));
        static::assertSame([$third->tokenHash], self::hashes(self::tokens()->findBySession($otherSession->id)));
        static::assertSame([], self::hashes(self::tokens()->findBySession(Uuid::v7())));
    }

    #[Test]
    public function aTokenOfAnUnregisteredClientIsNotFound(): void
    {
        // Given
        ['orphan' => $orphan] = self::anOrphanAndAKeptToken();

        // When / Then
        static::assertNull(self::tokens()->findByTokenHash($orphan->tokenHash));
    }

    #[Test]
    public function aTokenOfAnUnregisteredClientIsNotListed(): void
    {
        // Given
        ['kept' => $kept, 'family' => $family, 'session' => $session] = self::anOrphanAndAKeptToken();

        // When / Then
        static::assertSame([$kept->tokenHash], self::hashes(self::tokens()->findByFamily($family->id)));
        static::assertSame([$kept->tokenHash], self::hashes(self::tokens()->findBySession($session->id)));
    }

    /**
     * @return array{family: RefreshTokenFamily, first: RefreshToken, second: RefreshToken, sibling: RefreshTokenFamily, third: RefreshToken, aliceSession: AuthenticationSession, otherSession: AuthenticationSession}
     */
    private static function twoFamilies(): array
    {
        $alice = self::user();
        $aliceSession = self::session($alice);
        $otherSession = self::session($alice, self::now()->modify('+1 minute'));
        $client = self::client();
        $family = self::family();
        $sibling = self::family();
        $first = self::token(Secrets::draw(), $client, $aliceSession, $family, null, self::now()->modify('+1 minute'));
        $second = self::token(Secrets::draw(), $client, $aliceSession, $family, null, self::now()->modify('+2 minutes'));
        $third = self::token(Secrets::draw(), $client, $otherSession, $sibling, null, self::now()->modify('+3 minutes'));
        self::tokens()->save($second);
        self::tokens()->save($first);
        self::tokens()->save($third);
        self::reload();

        return [
            'family' => $family,
            'first' => $first,
            'second' => $second,
            'sibling' => $sibling,
            'third' => $third,
            'aliceSession' => $aliceSession,
            'otherSession' => $otherSession,
        ];
    }

    /**
     * @return array{orphan: RefreshToken, kept: RefreshToken, family: RefreshTokenFamily, session: AuthenticationSession}
     */
    private static function anOrphanAndAKeptToken(): array
    {
        $session = self::session(self::user());
        $family = self::family();
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        $orphan = self::token(Secrets::draw(), $ghost, $session, $family, null, self::now()->modify('+1 minute'));
        $kept = self::token(Secrets::draw(), self::client(), $session, $family, null, self::now()->modify('+2 minutes'));
        self::tokens()->save($orphan);
        self::tokens()->save($kept);
        self::reload();

        return [
            'orphan' => $orphan,
            'kept' => $kept,
            'family' => $family,
            'session' => $session,
        ];
    }

    private static function family(): RefreshTokenFamily
    {
        return new RefreshTokenFamily(
            Uuid::v7(),
            self::tenant(),
            DrawnSecret::digestOf(Secrets::draw()),
            Uuid::v7(),
            self::now(),
            self::now()->modify('+90 days'),
        );
    }

    private static function token(
        string $token,
        Client $client,
        AuthenticationSession $session,
        RefreshTokenFamily $family,
        ?ClaimsRequest $claims,
        DateTimeImmutable $issuedAt,
    ): RefreshToken {
        return new RefreshToken(
            DrawnSecret::digestOf($token),
            $family,
            $client,
            $session,
            new Scopes([new Scope('openid'), new Scope('offline_access')]),
            null,
            null,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            self::now()->modify('+30 days'),
        );
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function theRefreshTokensOfAConsentAreThoseOfItsUserAndItsClient(): void
    {
        // Given
        $alice = self::user();
        $session = self::session($alice);
        $here = Secrets::draw();
        self::tokens()->save(self::token($here, self::client(), $session, self::family(), null, self::now()));
        self::tokens()->save(self::token(Secrets::draw(), self::client('native-app'), $session, self::family(), null, self::now()));
        self::tokens()->save(self::token(Secrets::draw(), self::client(), self::session(self::user('bob', 'bob-subject')), self::family(), null, self::now()));
        self::reload();

        // When
        $found = self::refreshTokensOfAConsent()->ofConsent(self::consent($alice, self::client()));

        // Then
        static::assertSame([DrawnSecret::digestOf($here)], self::hashes($found));
    }

    private static function consent(User $user, Client $client): Consent
    {
        return new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now());
    }

    private static function refreshTokensOfAConsent(): RefreshTokensOfAConsentInterface
    {
        return self::service('test.beffroi.refresh_tokens_of_a_consent', RefreshTokensOfAConsentInterface::class);
    }

    /**
     * @param list<RefreshToken> $tokens
     *
     * @return list<string>
     */
    private static function hashes(array $tokens): array
    {
        return array_map(static fn (RefreshToken $token): string => $token->tokenHash, $tokens);
    }

    /**
     * A token read back by this request, as a grant holds it.
     */
    private static function stored(): RefreshToken
    {
        $token = self::token(Secrets::draw(), self::client(), self::session(self::user()), self::family(), null, self::now()->modify('+1 minute'));
        self::tokens()->save($token);
        self::reload();

        return self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');
    }

    /**
     * What a concurrent request writes: the row, and nothing this request's manager holds.
     */
    private static function changedByAnotherRequest(RefreshToken $token, string $column): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(sprintf('UPDATE beffroi_refresh_token SET %s = ? WHERE token_hash = ?', $column), [
                self::now()->modify('+30 minutes')->format('Y-m-d H:i:s'),
                $token->tokenHash,
            ]);
    }

    private static function revocation(): CanRevokeARefreshTokenOnceInterface
    {
        return self::service('test.beffroi.refresh_token_revocation', CanRevokeARefreshTokenOnceInterface::class);
    }

    private static function rotation(): RefreshTokenRotationInterface
    {
        return self::service('test.beffroi.refresh_token_rotation', RefreshTokenRotationInterface::class);
    }

    private static function tokens(): RefreshTokenRepositoryInterface
    {
        return self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class);
    }
}
