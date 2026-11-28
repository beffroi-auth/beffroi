<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Name;

use Beffroi\Scim\Domain\Schema\SchemaInterface;

/**
 * P-21: what a name of a body names, its parts folded by ASCII: an attribute of a schema, one of its sub-attributes,
 * or the schema whole, which the URN of an extension names as its container (RFC 7643 §3.3).
 */
final readonly class AttributeName
{
    public function __construct(
        public SchemaInterface $schema,
        public ?string $attribute = null,
        public ?string $subAttribute = null,
    ) {
    }

    public function namesTheSchema(): bool
    {
        return $this->attribute === null;
    }

    /**
     * @return non-empty-list<string> what the name names, then each part that holds it, up to its schema
     */
    public function scopes(): array
    {
        $schema = $this->schema->urn();
        if ($this->attribute === null) {
            return [$schema];
        }
        $attribute = $schema . ' ' . $this->attribute;
        if ($this->subAttribute === null) {
            return [$attribute, $schema];
        }

        return [$attribute . '.' . $this->subAttribute, $attribute, $schema];
    }
}
