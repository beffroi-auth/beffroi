<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

interface AnnouncedSessionEndsInterface
{
    /**
     * Records, atomically, that the end of the session is announced.
     *
     * @return bool false when it was recorded before
     */
    public function announceOnce(Tenant $tenant, Uuid $session): bool;
}
