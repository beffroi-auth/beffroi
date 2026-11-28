<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Request;

use Beffroi\Scim\Domain\Request\MediaType;
use Beffroi\Scim\Tests\Fixture\Refusals;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/scim.md section 6.1 step 4
 */
final class MediaTypeTest extends TestCase
{
    /**
     * Section 6.1 step 4, RFC 7644 §3.8, RFC 9110 §8.3.1, §5.6.6, §8.3.2
     */
    #[Test]
    #[DataProvider('provideReadableTypes')]
    public function aBodyOfAJsonTypeInUtf8IsRead(?string $contentType): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        MediaType::assertReadable($contentType);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideReadableTypes(): iterable
    {
        yield 'no type, read as the one RFC 7644 §3.8 defaults to' => [null];
        yield 'the type of SCIM' => ['application/scim+json'];
        yield 'the type of JSON' => ['application/json'];
        yield 'a type in capitals' => ['APPLICATION/SCIM+JSON'];
        yield 'a charset in capitals' => ['application/scim+json;charset=UTF-8'];
        yield 'a charset after whitespace' => ['application/scim+json ; charset=utf-8'];
        yield 'a charset whose name is in capitals' => ['application/json; Charset=utf-8'];
        yield 'a charset quoted' => ['application/json; charset="utf-8"'];
        yield 'an empty parameter' => ['application/scim+json;'];
    }

    /**
     * Section 6.1 step 4, RFC 9110 §15.5.16
     */
    #[Test]
    #[DataProvider('provideUnreadableTypes')]
    public function aBodyOfAnotherTypeIsRefusedAsUnsupported(string $contentType): void
    {
        // When
        $error = Refusals::of(static fn () => MediaType::assertReadable($contentType));

        // Then
        static::assertSame(415, $error->status);
        static::assertNull($error->scimType);
        static::assertSame(MediaType::DETAIL, $error->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnreadableTypes(): iterable
    {
        yield 'a form' => ['application/x-www-form-urlencoded'];
        yield 'plain text' => ['text/plain'];
        yield 'a merge patch' => ['application/merge-patch+json'];
        yield 'a type of JSON with a suffix of its own' => ['application/scim+json-seq'];
        yield 'an empty type' => [''];
        yield 'another charset' => ['application/scim+json; charset=iso-8859-1'];
        yield 'another parameter' => ['application/scim+json; version=2'];
        yield 'a charset written twice' => ['application/scim+json; charset=utf-8; charset=utf-8'];
        yield 'whitespace around the equals sign' => ['application/scim+json; charset = utf-8'];
        yield 'a charset without a value' => ['application/scim+json; charset'];
    }
}
