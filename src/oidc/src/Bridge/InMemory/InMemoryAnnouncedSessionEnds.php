<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\AnnouncedSessionEndsInterface;
use Symfony\Component\Uid\Uuid;

final class InMemoryAnnouncedSessionEnds implements AnnouncedSessionEndsInterface
{
    /**
     * @var array<string, true> by the identifier of the session
     */
    private array $announced = [];

    public function announceOnce(Tenant $tenant, Uuid $session): bool
    {
        if (isset($this->announced[$session->toRfc4122()])) {
            return false;
        }
        $this->announced[$session->toRfc4122()] = true;

        return true;
    }
}
