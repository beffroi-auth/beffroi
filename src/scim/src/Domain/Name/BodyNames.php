<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Name;

use Beffroi\Scim\Domain\Schema\SchemaInterface;
use Beffroi\Scim\Exception\ScimRefusedException;
use function get_object_vars;
use function is_array;
use stdClass;

/**
 * P-21, section 6.1 step 5: every name of every object of a decoded body resolved, the names of an object under the
 * schema it stands in, the base schema of its endpoint or the extension whose container holds it, and refused when two
 * of them name one attribute.
 */
final readonly class BodyNames
{
    public function __construct(
        private Schemas $schemas,
    ) {
    }

    /**
     * @throws ScimRefusedException
     */
    public function assertResolved(stdClass $document, SchemaInterface $base): void
    {
        $this->object($document, $base);
    }

    /**
     * @throws ScimRefusedException
     */
    private function object(stdClass $object, SchemaInterface $schema): void
    {
        $names = new ObjectNames();
        foreach (get_object_vars($object) as $name => $value) {
            $resolved = $this->schemas->resolve(self::written($name), $schema);
            $names->hold($resolved);
            $this->value($value, $resolved->namesTheSchema() ? $resolved->schema : $schema);
        }
    }

    /**
     * @throws ScimRefusedException
     */
    private function value(mixed $value, SchemaInterface $schema): void
    {
        if ($value instanceof stdClass) {
            $this->object($value, $schema);

            return;
        }
        if (is_array($value)) {
            foreach ($value as $element) {
                $this->value($element, $schema);
            }
        }
    }

    /**
     * A name made of digits is an integer key of the properties PHP reads off the object.
     */
    private static function written(int|string $name): string
    {
        return (string) $name;
    }
}
