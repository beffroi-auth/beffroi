<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Request;

use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Request\JsonStructure;
use Beffroi\Scim\Tests\Fixture\Refusals;
use function array_fill;
use function implode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function min;
use function sprintf;
use function str_repeat;

/**
 * spec/scim.md P-5, section 7
 */
final class JsonStructureTest extends TestCase
{
    /**
     * P-5, RFC 8259 §2
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function whatRfc8259WritesIsLetThrough(string $bytes): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        JsonStructure::assertWithinBounds($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'an empty object' => ['{}'];
        yield 'an empty array' => ['[]'];
        yield 'every kind of value, with whitespace' => [" {\t\"a\" : [ 1 , -0.5e+10 , 2E-3 , true , false , null , \"x\" ] ,\r\n\"b\" : { } } "];
        yield 'every escape' => ['{"a":"\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u00e9 \\ud83d\\ude00"}'];
        yield 'one name in two objects' => ['[{"a":1},{"a":2}]'];
        yield 'a string as the whole document' => ['"x"'];
        yield 'bytes outside ASCII in a string' => ["{\"a\":\"\u{e9}\u{1F600}\"}"];
    }

    /**
     * P-5, RFC 8259 §2, §6, §7, section 6.1 step 4
     */
    #[Test]
    #[DataProvider('provideMalformedBytes')]
    public function whatRfc8259DoesNotWriteIsRefusedAsInvalidSyntax(string $bytes): void
    {
        // When
        $error = Refusals::of(static fn () => JsonStructure::assertWithinBounds($bytes));

        // Then
        static::assertSame(400, $error->status);
        static::assertSame(ScimType::InvalidSyntax, $error->scimType);
        static::assertSame(JsonStructure::NOT_JSON, $error->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedBytes(): iterable
    {
        yield 'nothing' => [''];
        yield 'whitespace alone' => [' '];
        yield 'an object not closed' => ['{'];
        yield 'an array not closed' => ['[1'];
        yield 'a string not closed' => ['{"a":"x'];
        yield 'a member without its value' => ['{"a":}'];
        yield 'a member without its colon' => ['{"a" 1}'];
        yield 'a name that is not a string' => ['{a:1}'];
        yield 'a name in single quotes' => ["{'a':1}"];
        yield 'a trailing comma in an object' => ['{"a":1,}'];
        yield 'a trailing comma in an array' => ['[1,]'];
        yield 'two values side by side' => ['[1 2]'];
        yield 'a second document' => ['{} {}'];
        yield 'a byte order mark' => ["\u{FEFF}{}"];
        yield 'a number with a leading zero' => ['[01]'];
        yield 'a number without its fraction' => ['[1.]'];
        yield 'a minus sign alone' => ['[-]'];
        yield 'NaN' => ['[NaN]'];
        yield 'a literal cut short' => ['[tru]'];
        yield 'a literal in capitals' => ['[True]'];
        yield 'a control character in a string' => ["[\"a\nb\"]"];
        yield 'an unknown escape' => ['["\\q"]'];
        yield 'an escape cut short' => ['["\\u12"]'];
        yield 'an escape that is not hexadecimal' => ['["\\u12g4"]'];
        yield 'an escape at the end' => ['["\\'];
        yield 'a high surrogate alone in a name' => ['{"\\ud800":1}'];
        yield 'a low surrogate alone in a name' => ['{"\\udc00":1}'];
        yield 'a high surrogate before another character in a name' => ['{"\\ud800\\u0041":1}'];
        yield 'a comment' => ['{} // comment'];
    }

    /**
     * P-5, RFC 7493 §2.3, RFC 7644 §3.5.2
     */
    #[Test]
    #[DataProvider('provideNamesHeldTwice')]
    public function aNameAnObjectHoldsTwiceIsRefusedOnceItsEscapesAreDecoded(string $bytes): void
    {
        // When
        $error = Refusals::of(static fn () => JsonStructure::assertWithinBounds($bytes));

        // Then
        static::assertSame(400, $error->status);
        static::assertSame(ScimType::InvalidSyntax, $error->scimType);
        static::assertSame(JsonStructure::NAME_TWICE, $error->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesHeldTwice(): iterable
    {
        yield 'written twice' => ['{"op":"add","op":"remove"}'];
        yield 'under the escape of a letter' => ['{"op":"add","\\u006fp":"remove"}'];
        yield 'under a short escape' => ['{"a/b":1,"a\\/b":2}'];
        yield 'under the escape of a pair of surrogates' => ["{\"\u{1F600}\":1,\"\\ud83d\\ude00\":2}"];
        yield 'in an object of an array' => ['{"Operations":[{"op":"add","value":1,"op":"remove"}]}'];
    }

    /**
     * P-5, section 7
     */
    #[Test]
    public function aBodyThatNestsAsDeepAsTheBoundIsLetThrough(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        JsonStructure::assertWithinBounds(self::nested(8));
    }

    /**
     * P-5, section 7, RFC 9110 §15.5.14
     */
    #[Test]
    public function aBodyThatNestsDeeperThanTheBoundIsRefusedAsTooLarge(): void
    {
        // When
        $error = Refusals::of(static fn () => JsonStructure::assertWithinBounds(self::nested(9)));

        // Then
        static::assertSame(413, $error->status);
        static::assertNull($error->scimType);
        static::assertSame(JsonStructure::TOO_DEEP, $error->detail);
    }

    /**
     * P-5, section 7
     */
    #[Test]
    public function aBodyOfAsManyValuesAsTheBoundIsLetThrough(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        JsonStructure::assertWithinBounds(self::values(16_384));
    }

    /**
     * P-5, section 7, RFC 9110 §15.5.14
     */
    #[Test]
    public function aBodyOfMoreValuesThanTheBoundIsRefusedAsTooLarge(): void
    {
        // When
        $error = Refusals::of(static fn () => JsonStructure::assertWithinBounds(self::values(16_385)));

        // Then
        static::assertSame(413, $error->status);
        static::assertNull($error->scimType);
        static::assertSame(JsonStructure::TOO_MANY_VALUES, $error->detail);
    }

    /**
     * P-5, section 7
     */
    #[Test]
    public function anArrayOfAsManyElementsAsTheBoundIsLetThrough(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        JsonStructure::assertWithinBounds(self::elements(1_000));
    }

    /**
     * P-5, section 7, RFC 9110 §15.5.14
     */
    #[Test]
    public function anArrayOfMoreElementsThanTheBoundIsRefusedAsTooLarge(): void
    {
        // When
        $error = Refusals::of(static fn () => JsonStructure::assertWithinBounds(self::elements(1_001)));

        // Then
        static::assertSame(413, $error->status);
        static::assertNull($error->scimType);
        static::assertSame(JsonStructure::TOO_MANY_ELEMENTS, $error->detail);
    }

    /**
     * P-5, section 7
     */
    #[Test]
    public function anObjectOfAsManyNamesAsTheBoundIsLetThrough(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        JsonStructure::assertWithinBounds(self::names(100));
    }

    /**
     * P-5, section 7, RFC 9110 §15.5.14
     */
    #[Test]
    public function anObjectOfMoreNamesThanTheBoundIsRefusedAsTooLarge(): void
    {
        // When
        $error = Refusals::of(static fn () => JsonStructure::assertWithinBounds(self::names(101)));

        // Then
        static::assertSame(413, $error->status);
        static::assertNull($error->scimType);
        static::assertSame(JsonStructure::TOO_MANY_NAMES, $error->detail);
    }

    /**
     * @param int<1, max> $levels
     */
    private static function nested(int $levels): string
    {
        return str_repeat('{"a":', $levels - 1) . '[]' . str_repeat('}', $levels - 1);
    }

    /**
     * An object of arrays of a thousand numbers each, the last one shorter, holding the values asked, itself and its
     * arrays included.
     */
    private static function values(int $values): string
    {
        $members = [];
        $left = $values - 1;
        for ($array = 0; $left > 0; ++$array) {
            $elements = min(1_000, $left - 1);
            $members[] = sprintf('"a%d":[%s]', $array, implode(',', array_fill(0, $elements, '0')));
            $left -= $elements + 1;
        }

        return '{' . implode(',', $members) . '}';
    }

    private static function names(int $names): string
    {
        $members = [];
        for ($name = 0; $name < $names; ++$name) {
            $members[] = sprintf('"a%d":0', $name);
        }

        return '{' . implode(',', $members) . '}';
    }

    private static function elements(int $elements): string
    {
        return '[' . implode(',', array_fill(0, $elements, 'null')) . ']';
    }
}
