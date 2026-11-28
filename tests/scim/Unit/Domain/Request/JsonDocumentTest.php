<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Request;

use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Request\JsonDocument;
use Beffroi\Scim\Tests\Fixture\Refusals;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * spec/scim.md section 6.1 step 4, P-6
 */
final class JsonDocumentTest extends TestCase
{
    /**
     * Section 6.1 step 4, P-6, RFC 7643 §2.3.8, §2.4
     */
    #[Test]
    public function anObjectOfTheBodyStaysAnObjectAndAnArrayAnArray(): void
    {
        // When
        $document = JsonDocument::decode('{"name":{},"emails":[]}');

        // Then
        static::assertInstanceOf(stdClass::class, $document->name);
        static::assertSame([], $document->emails);
    }

    /**
     * Section 6.1 step 4, RFC 8259 §8.1, RFC 7644 §3.8
     */
    #[Test]
    #[DataProvider('provideBodiesThatAreNoObjectInUtf8')]
    public function aBodyThatIsNoJsonObjectInUtf8IsRefusedAsInvalidSyntax(string $bytes): void
    {
        // When
        $error = Refusals::of(static fn () => JsonDocument::decode($bytes));

        // Then
        static::assertSame(400, $error->status);
        static::assertSame(ScimType::InvalidSyntax, $error->scimType);
        static::assertSame(JsonDocument::NOT_AN_OBJECT, $error->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBodiesThatAreNoObjectInUtf8(): iterable
    {
        yield 'an array' => ['[]'];
        yield 'a string' => ['"x"'];
        yield 'a number' => ['1'];
        yield 'null' => ['null'];
        yield 'bytes that are not UTF-8' => ["{\"a\":\"\xFF\"}"];
        yield 'a surrogate alone' => ['{"a":"\\ud800"}'];
        yield 'a name that PHP cannot hold' => ['{"\u0000a":1}'];
    }
}
