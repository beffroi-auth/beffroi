<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * Whether a tenant still holds a password hashed as it was typed, before the provider enforced the OpaqueString profile
 * (decision 0065).
 */
interface PasswordsHashedAsTypedInterface
{
    public function remainIn(Tenant $tenant): bool;
}
