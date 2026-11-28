<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * How many passwords of a tenant are still hashed as they were typed, before the provider enforced the OpaqueString
 * profile (decision 0065): the sign-ins of the tenant verify two forms until none is left.
 */
interface CanCountPasswordsHashedAsTypedInterface
{
    public function countIn(Tenant $tenant): int;
}
