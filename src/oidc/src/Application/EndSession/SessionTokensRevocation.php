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
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

final readonly class SessionTokensRevocation
{
    public function __construct(
        private RefreshTokenRevocation $refreshTokens,
        private CanRevokeAccessTokensBySessionInterface $accessTokens,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
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
        $refreshTokens = $this->refreshTokens->revokeBySession($session, $endedAt);
        $accessTokens = $this->accessTokens->revokeBySession($session);
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
     * @param list<ResolvesItsClientInterface> $tokens
     *
     * @return list<string> in the order their first token was revoked
     */
    private static function clientsOf(array $tokens): array
    {
        return array_values(array_unique(array_map(static fn (ResolvesItsClientInterface $token): string => $token->clientId, $tokens)));
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
