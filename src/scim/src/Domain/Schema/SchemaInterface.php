<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Schema;

/**
 * A schema the provider serves (RFC 7643 §3), named by its URN.
 */
interface SchemaInterface
{
    public function urn(): string;
}
