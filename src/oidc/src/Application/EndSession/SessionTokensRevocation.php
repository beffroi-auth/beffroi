<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use function array_filter;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use DateTimeImmutable;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Port\AnnouncedSessionEndsInterface;
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
        private AnnouncedSessionEndsInterface $announced,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * Every token of the session, and one act per client of those that were serving at its end, announced once whatever
     * the number of runs. A refresh token is counted from its state, whether this run or the refusal of a late token
     * revoked it as of the end; an opaque access token, which a revocation deletes, by the run that deleted it.
     *
     * @param Subject         $person the person of the session, by the subject of their account
     * @param AuthorInterface $author who ended the session, whom each act names as its author
     */
    public function sessionEnded(
        Uuid $session,
        DateTimeImmutable $endedAt,
        Tenant $tenant,
        Subject $person,
        RequestContext $context,
        AuthorInterface $author,
    ): void {
        $refreshTokens = $this->refreshTokens->findBySession($session);
        $counted = $this->writes->atomically(function () use ($refreshTokens, $endedAt, $session, $tenant): array {
            $this->revocation->revokeAll($refreshTokens, $endedAt);
            $counted = self::countedByClient(
                array_values(array_filter($refreshTokens, static fn (RefreshToken $token): bool => $token->endedWithItsSession($endedAt))),
                array_values(array_filter(
                    $this->accessTokens->revokeBySession($session),
                    static fn (StoredAccessToken $token): bool => ! $token->isExpired($endedAt),
                )),
            );

            return $counted === [] || ! $this->announced->announceOnce($tenant, $session) ? [] : $counted;
        });
        foreach ($counted as [$clientId, $refreshed, $accessed]) {
            $this->events->dispatch(new SessionTokensRevoked(
                $endedAt,
                $tenant,
                $clientId,
                $person,
                $session,
                $refreshed,
                $accessed,
                $context,
                $author,
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
     * @param list<RefreshToken>      $refreshTokens
     * @param list<StoredAccessToken> $accessTokens
     *
     * @return list<array{string, non-negative-int, non-negative-int}> each client, in the order of its first token, with
     *                                                                   the refresh tokens and the access tokens it lost
     */
    private static function countedByClient(array $refreshTokens, array $accessTokens): array
    {
        $clients = array_values(array_unique(array_map(
            static fn (ResolvesItsClientInterface $token): string => $token->clientId,
            [...$refreshTokens, ...$accessTokens],
        )));

        return array_map(
            static fn (string $clientId): array => [$clientId, self::countOf($refreshTokens, $clientId), self::countOf($accessTokens, $clientId)],
            $clients,
        );
    }

    /**
     * @param list<ResolvesItsClientInterface> $tokens
     *
     * @return non-negative-int
     */
    private static function countOf(array $tokens, string $clientId): int
    {
        return count(array_filter($tokens, static fn (ResolvesItsClientInterface $token): bool => $token->clientId === $clientId));
    }
}
