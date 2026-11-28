<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use function array_filter;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

final readonly class SessionTokensRevocation
{
    public function __construct(
        private RefreshTokenRepositoryInterface $refreshTokens,
        private RefreshTokenRevocation $revocation,
        private CanRevokeAccessTokensBySessionInterface $accessTokens,
        private AtomicWritesInterface $writes,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * Every token of the session, and one act per client of those that were serving at its end. A refresh token is
     * counted from its state, whatever revoked it since the end; an opaque access token, which a revocation deletes, by
     * the call that deleted it.
     *
     * @param Subject      $person        the person of the session, by the subject of their account
     * @param Subject|null $administrator the administrator of the tenant who ended the session, whom each act names as its author
     */
    public function sessionEnded(
        Uuid $session,
        DateTimeImmutable $endedAt,
        Tenant $tenant,
        Subject $person,
        RequestContext $context,
        ?Subject $administrator = null,
    ): void {
        $refreshTokens = $this->refreshTokens->findBySession($session);
        $accessTokens = $this->writes->atomically(function () use ($refreshTokens, $endedAt, $session): array {
            $this->revocation->revokeAll($refreshTokens, $endedAt);

            return $this->accessTokens->revokeBySession($session);
        });
        $refreshTokens = array_filter($refreshTokens, static fn (RefreshToken $token): bool => $token->endedWithItsSession($endedAt));
        $accessTokens = array_filter($accessTokens, static fn (StoredAccessToken $token): bool => ! $token->isExpired($endedAt));
        foreach (self::clientsOf([...$refreshTokens, ...$accessTokens]) as $clientId) {
            $this->events->dispatch(new SessionTokensRevoked(
                $endedAt,
                $tenant,
                $clientId,
                $person,
                $session,
                self::countOf($refreshTokens, $clientId),
                self::countOf($accessTokens, $clientId),
                $context,
                $administrator,
            ));
        }
    }

    /**
     * A refresh token of the session presented after its end: one held at the end, before the end was handled, or the
     * successor a refresh in flight saved after it. The refresh tokens still unrevoked are revoked as of the end, which
     * counts them; the opaque access tokens are left to the end, which counts what it deletes, and the ended session
     * refuses both meanwhile. Nothing is announced here: the act would take the end's over, under another author.
     */
    public function outlived(Uuid $session, DateTimeImmutable $endedAt): void
    {
        $this->revocation->revokeBySession($session, $endedAt);
    }

    /**
     * @param list<ResolvesItsClientInterface> $tokens
     *
     * @return list<string> in the order of their first token
     */
    private static function clientsOf(array $tokens): array
    {
        return array_values(array_unique(array_map(static fn (ResolvesItsClientInterface $token): string => $token->clientId, $tokens)));
    }

    /**
     * @param array<array-key, ResolvesItsClientInterface> $tokens
     *
     * @return non-negative-int
     */
    private static function countOf(array $tokens, string $clientId): int
    {
        return count(array_filter($tokens, static fn (ResolvesItsClientInterface $token): bool => $token->clientId === $clientId));
    }
}
