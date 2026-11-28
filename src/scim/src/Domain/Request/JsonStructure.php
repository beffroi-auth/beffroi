<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Request;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Exception\ScimRefusedException;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use function preg_match;
use function str_contains;
use function strlen;
use function strspn;
use function substr;

/**
 * P-5, section 7, RFC 8259, RFC 7493 §2.3: the bytes of a body read once, before json_decode() builds anything, with a
 * frame per level and the names of each object open. Its nesting, its values, the elements of each of its arrays and
 * the names of each of its objects are counted against their bounds, the names before one is hashed; a name an object
 * holds twice once its escapes are decoded, which json_decode() would reduce to the last one, is refused, and so is
 * anything RFC 8259 does not write.
 */
final class JsonStructure
{
    public const int NESTING = 8;

    public const int VALUES = 16_384;

    public const int ELEMENTS = 1_000;

    public const int NAMES = 100;

    public const int TOO_LARGE = 413;

    public const int MALFORMED = 400;

    public const string NOT_JSON = 'The body of the request is not a JSON document (RFC 8259).';

    public const string NAME_TWICE = 'An object of the body holds a name twice (RFC 7493 §2.3).';

    public const string TOO_DEEP = 'The body of the request nests deeper than the 8 levels the provider reads.';

    public const string TOO_MANY_VALUES = 'The body of the request holds more than the 16 384 values the provider reads.';

    public const string TOO_MANY_ELEMENTS = 'An array of the body holds more than the 1 000 elements the provider reads.';

    public const string TOO_MANY_NAMES = 'An object of the body holds more than the 100 names the provider reads.';

    /**
     * RFC 8259 §2
     */
    private const string WHITESPACE = " \t\n\r";

    /**
     * RFC 8259 §6
     */
    private const string NUMBER = '/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/';

    /**
     * RFC 8259 §7: its quotes, and between them characters that are no quote, no escape and no control character, or
     * escapes; possessive, so that the expression reads a string once whatever its length.
     */
    private const string STRING = '/\G"(?:[^"\\\\\x00-\x1F]++|\\\\(?:["\\\\\/bfnrt]|u[0-9a-fA-F]{4}))*+"/';

    private const array LITERALS = ['true', 'false', 'null'];

    private readonly int $length;

    private int $offset = 0;

    private int $depth = 0;

    private int $values = 0;

    private function __construct(
        private readonly string $bytes,
    ) {
        $this->length = strlen($bytes);
    }

    /**
     * @throws ScimRefusedException
     */
    public static function assertWithinBounds(string $bytes): void
    {
        $reader = new self($bytes);
        $reader->value();
        $reader->whitespace();
        if ($reader->offset !== $reader->length) {
            throw self::malformed(self::NOT_JSON);
        }
    }

    /**
     * @throws ScimRefusedException
     */
    private function value(): void
    {
        $this->whitespace();
        if (++$this->values > self::VALUES) {
            throw self::tooLarge(self::TOO_MANY_VALUES);
        }
        $byte = $this->next();
        if ($byte === '{') {
            $this->object();
        } elseif ($byte === '[') {
            $this->array();
        } elseif ($byte === '"') {
            $this->string();
        } elseif ($byte !== '' && str_contains('-0123456789', $byte)) {
            $this->number();
        } else {
            $this->literal();
        }
    }

    /**
     * @throws ScimRefusedException
     */
    private function object(): void
    {
        $this->enter();
        $names = [];
        $this->whitespace();
        if ($this->next() === '}') {
            ++$this->offset;
            --$this->depth;

            return;
        }
        $count = 0;
        do {
            if (++$count > self::NAMES) {
                throw self::tooLarge(self::TOO_MANY_NAMES);
            }
            $this->whitespace();
            if ($this->next() !== '"') {
                throw self::malformed(self::NOT_JSON);
            }
            $name = $this->name();
            if (isset($names[$name])) {
                throw self::malformed(self::NAME_TWICE);
            }
            $names[$name] = true;
            $this->whitespace();
            if ($this->next() !== ':') {
                throw self::malformed(self::NOT_JSON);
            }
            ++$this->offset;
            $this->value();
        } while ($this->separator('}'));
        --$this->depth;
    }

    /**
     * @throws ScimRefusedException
     */
    private function array(): void
    {
        $this->enter();
        $this->whitespace();
        if ($this->next() === ']') {
            ++$this->offset;
            --$this->depth;

            return;
        }
        $elements = 0;
        do {
            if (++$elements > self::ELEMENTS) {
                throw self::tooLarge(self::TOO_MANY_ELEMENTS);
            }
            $this->value();
        } while ($this->separator(']'));
        --$this->depth;
    }

    /**
     * @throws ScimRefusedException
     */
    private function enter(): void
    {
        if (++$this->depth > self::NESTING) {
            throw self::tooLarge(self::TOO_DEEP);
        }
        ++$this->offset;
    }

    /**
     * Whether another member or element follows: true past a comma, false past the closing byte.
     *
     * @throws ScimRefusedException
     */
    private function separator(string $closing): bool
    {
        $this->whitespace();
        $byte = $this->next();
        ++$this->offset;
        if ($byte === ',') {
            return true;
        }
        if ($byte === $closing) {
            return false;
        }

        throw self::malformed(self::NOT_JSON);
    }

    /**
     * @return string the string with its escapes decoded, which is how RFC 7493 §2.3 compares two names
     *
     * @throws ScimRefusedException
     */
    private function name(): string
    {
        $token = $this->string();
        if (! str_contains($token, '\\')) {
            return substr($token, 1, -1);
        }
        try {
            // The decoding json_decode() gives the whole body, so that two names compare as it would hold them.
            $name = json_decode($token, false, 1, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw self::malformed(self::NOT_JSON);
        }

        return is_string($name) ? $name : throw self::malformed(self::NOT_JSON);
    }

    /**
     * @return string the string as the body writes it, its quotes included
     *
     * @throws ScimRefusedException
     */
    private function string(): string
    {
        if (preg_match(self::STRING, $this->bytes, $token, 0, $this->offset) !== 1) {
            throw self::malformed(self::NOT_JSON);
        }
        $this->offset += strlen($token[0]);

        return $token[0];
    }

    /**
     * @throws ScimRefusedException
     */
    private function number(): void
    {
        if (preg_match(self::NUMBER, $this->bytes, $number, 0, $this->offset) !== 1) {
            throw self::malformed(self::NOT_JSON);
        }
        $this->offset += strlen($number[0]);
    }

    /**
     * @throws ScimRefusedException
     */
    private function literal(): void
    {
        foreach (self::LITERALS as $literal) {
            if (substr($this->bytes, $this->offset, strlen($literal)) === $literal) {
                $this->offset += strlen($literal);

                return;
            }
        }

        throw self::malformed(self::NOT_JSON);
    }

    private function whitespace(): void
    {
        $this->offset += strspn($this->bytes, self::WHITESPACE, $this->offset);
    }

    /**
     * @return string the byte at the offset, or nothing past the last one
     */
    private function next(): string
    {
        return $this->bytes[$this->offset] ?? '';
    }

    private static function malformed(string $detail): ScimRefusedException
    {
        return new ScimRefusedException(new ScimError(self::MALFORMED, ScimType::InvalidSyntax, $detail));
    }

    private static function tooLarge(string $detail): ScimRefusedException
    {
        return new ScimRefusedException(new ScimError(self::TOO_LARGE, null, $detail));
    }
}
