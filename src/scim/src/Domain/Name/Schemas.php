<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Name;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Schema\SchemaInterface;
use Beffroi\Scim\Exception\ScimRefusedException;
use function iterator_to_array;
use function preg_match;
use function str_starts_with;
use function strlen;
use function strtolower;
use function substr;
use function usort;

/**
 * P-21, RFC 7643 §2.1, RFC 7644 §3.10: the schemas a name of a body is resolved against, the longest URN first, so
 * that no URN is ever read as an attribute of a shorter one. A name is read in US-ASCII and folded by ASCII alone,
 * so that no folding of Unicode brings a name onto another.
 */
final readonly class Schemas
{
    public const int STATUS = 400;

    public const string NOT_A_NAME = 'A name of the body is not the name of an attribute (RFC 7643 §2.1).';

    public const string UNSERVED_SCHEMA = 'A name of the body carries the URN of a schema the provider does not serve.';

    private const string URN = 'urn:';

    /**
     * RFC 7643 §2.1, folded: ATTRNAME, or the "$ref" of RFC 7643 §2.3.7, followed by the name of a sub-attribute.
     */
    private const string PATH = '/^(?:\$ref|([a-z][a-z0-9$_-]*)(?:\.(\$ref|[a-z][a-z0-9$_-]*))?)$/D';

    /**
     * @var list<SchemaInterface>
     */
    private array $longestFirst;

    /**
     * @param iterable<SchemaInterface> $schemas
     */
    public function __construct(iterable $schemas)
    {
        $longestFirst = iterator_to_array($schemas, false);
        usort($longestFirst, static fn (SchemaInterface $one, SchemaInterface $other): int => strlen($other->urn()) <=> strlen($one->urn()));
        $this->longestFirst = $longestFirst;
    }

    /**
     * @param SchemaInterface $base the schema a name without a URN belongs to (RFC 7644 §3.10)
     *
     * @throws ScimRefusedException
     */
    public function resolve(string $name, SchemaInterface $base): AttributeName
    {
        if (preg_match('/^[\x21-\x7E]+$/D', $name) !== 1) {
            throw self::refused(ScimType::InvalidSyntax, self::NOT_A_NAME);
        }
        $folded = strtolower($name);
        if (! str_starts_with($folded, self::URN)) {
            return self::path($folded, $base);
        }
        foreach ($this->longestFirst as $schema) {
            $urn = strtolower($schema->urn());
            if ($folded === $urn) {
                return new AttributeName($schema);
            }
            if (str_starts_with($folded, $urn . ':')) {
                return self::path(substr($folded, strlen($urn) + 1), $schema);
            }
        }

        throw self::refused(ScimType::InvalidValue, self::UNSERVED_SCHEMA);
    }

    /**
     * @throws ScimRefusedException
     */
    private static function path(string $folded, SchemaInterface $schema): AttributeName
    {
        if (preg_match(self::PATH, $folded, $parts) !== 1) {
            throw self::refused(ScimType::InvalidSyntax, self::NOT_A_NAME);
        }
        $attribute = $parts[1] ?? '';

        return $attribute === ''
            ? new AttributeName($schema, $folded)
            : new AttributeName($schema, $attribute, $parts[2] ?? null);
    }

    private static function refused(ScimType $type, string $detail): ScimRefusedException
    {
        return new ScimRefusedException(new ScimError(self::STATUS, $type, $detail));
    }
}
