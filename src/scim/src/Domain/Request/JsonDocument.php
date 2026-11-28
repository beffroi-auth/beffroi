<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Request;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Exception\ScimRefusedException;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use stdClass;

/**
 * Section 6.1 step 4, RFC 8259, RFC 7644 §3.8: the bytes the reader of P-5 let through, decoded in UTF-8 into the
 * object a body is. Its objects stay objects, so that a complex value is never mistaken for a multi-valued one (P-6).
 */
final readonly class JsonDocument
{
    public const int STATUS = 400;

    public const string NOT_AN_OBJECT = 'The body of the request is not a JSON object in UTF-8 (RFC 8259, RFC 7644 §3.8).';

    /**
     * @throws ScimRefusedException
     */
    public static function decode(string $bytes): stdClass
    {
        try {
            // Without JSON_BIGINT_AS_STRING: a number too large for an integer stays a number, which no string
            // attribute takes (P-6), and never becomes a string.
            $document = json_decode($bytes, false, JsonStructure::NESTING + 1, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw self::refused();
        }
        if (! $document instanceof stdClass) {
            throw self::refused();
        }

        return $document;
    }

    private static function refused(): ScimRefusedException
    {
        return new ScimRefusedException(new ScimError(self::STATUS, ScimType::InvalidSyntax, self::NOT_AN_OBJECT));
    }
}
