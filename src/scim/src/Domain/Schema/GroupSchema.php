<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Schema;

/**
 * RFC 7643 §4.2
 */
final readonly class GroupSchema implements SchemaInterface
{
    public const string URN = 'urn:ietf:params:scim:schemas:core:2.0:Group';

    public function urn(): string
    {
        return self::URN;
    }
}
