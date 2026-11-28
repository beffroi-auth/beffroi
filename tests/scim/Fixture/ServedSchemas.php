<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Fixture;

use Beffroi\Scim\Domain\Name\Schemas;
use Beffroi\Scim\Domain\Schema\EnterpriseUserSchema;
use Beffroi\Scim\Domain\Schema\GroupSchema;
use Beffroi\Scim\Domain\Schema\UserSchema;

/**
 * The three schemas the provider serves, as the application wires them.
 */
final class ServedSchemas
{
    public static function all(): Schemas
    {
        return new Schemas([new UserSchema(), new EnterpriseUserSchema(), new GroupSchema()]);
    }
}
