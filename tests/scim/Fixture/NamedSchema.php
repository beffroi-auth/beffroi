<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Fixture;

use Beffroi\Scim\Domain\Schema\SchemaInterface;

final readonly class NamedSchema implements SchemaInterface
{
    public function __construct(
        private string $urn,
    ) {
    }

    public function urn(): string
    {
        return $this->urn;
    }
}
