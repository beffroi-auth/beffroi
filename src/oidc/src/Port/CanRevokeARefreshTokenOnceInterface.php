<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\RefreshToken;
use DateTimeImmutable;

interface CanRevokeARefreshTokenOnceInterface
{
    /**
     * Marks the token revoked in the store, atomically, only if it is not revoked there; the caller's copy is marked
     * revoked with it, or, when something revoked it first, holds the revocation the store holds.
     *
     * @return bool false when something revoked it first
     */
    public function revokeOnce(RefreshToken $token, DateTimeImmutable $now): bool;
}
