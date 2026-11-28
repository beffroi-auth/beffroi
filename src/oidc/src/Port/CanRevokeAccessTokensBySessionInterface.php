<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

interface CanRevokeAccessTokensBySessionInterface
{
    /**
     * @return list<StoredAccessToken> those this call removed, and not another that removed them first
     */
    public function revokeBySession(Uuid $session): array;
}
