<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\Tokens;

/**
 * Issue #741: a refresh token and an opaque access token issued to oidc-demo under a session, written as the
 * token endpoint writes them, and what is left of them once that session has ended, whatever ended it.
 *
 * What is read is the rows and not an answer of an endpoint: a resource of the provider refuses a token whose
 * session has ended already (AccessTokenInspector, RefreshTokenGrant), so presenting one answers the same
 * whether it was revoked or not, and only its row says that it was.
 */
trait TokensOfASession
{
    /**
     * @return array{refresh: string, access: string} the values the client holds
     */
    private static function tokensIssuedIn(AuthenticationSession $session): array
    {
        $tokens = [
            'refresh' => Secrets::draw(),
            'access' => Secrets::draw(),
        ];
        $client = self::client();
        $issuedAt = self::currentSecond();
        self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class)
            ->save(Tokens::refreshToken($tokens['refresh'], $client, $session, $issuedAt));
        self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)
            ->save(Tokens::storedAccessToken($tokens['access'], $client, $session, $issuedAt));

        return $tokens;
    }

    /**
     * The refresh token revoked, its row kept so that a reuse is told from an unknown token, and the access
     * token gone, an unknown token being an invalid one (RFC 6750 §3.1).
     *
     * @param array{refresh: string, access: string} $tokens
     */
    private static function assertTheTokensAreRevoked(array $tokens): void
    {
        self::reload();
        $refreshToken = self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class)
            ->findByTokenHash(DrawnSecret::digestOf($tokens['refresh']));
        $accessToken = self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)->find($tokens['access']);

        static::assertSame(
            [
                'the refresh token revoked' => true,
                'the access token found' => false,
            ],
            [
                'the refresh token revoked' => $refreshToken?->isRevoked(),
                'the access token found' => $accessToken !== null,
            ],
        );
    }
}
