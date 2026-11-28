<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Schema;

/**
 * RFC 7643 §4.3
 */
final readonly class EnterpriseUserSchema implements SchemaInterface
{
    public const string URN = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

    public function urn(): string
    {
        return self::URN;
    }
}
