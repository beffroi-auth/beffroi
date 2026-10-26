<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Encoding;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #603: the document a value object was written as, read member by member. Every reading says what
 * it expected, and a member that is not that is refused instead of coerced.
 */
final class DocumentTest extends TestCase
{
    #[Test]
    public function aMemberThatIsAStringIsRead(): void
    {
        // When / Then
        static::assertSame(
            'Paris',
            new Document([
                'city' => 'Paris',
            ])->nullableString('city'),
        );
    }

    #[Test]
    public function aMemberThatIsAbsentIsNull(): void
    {
        // When / Then
        static::assertNull(new Document()->nullableString('city'));
    }

    #[Test]
    public function aMemberThatIsAnIntegerIsRead(): void
    {
        // When / Then
        static::assertSame(
            3215,
            new Document([
                'asn' => 3215,
            ])->nullableInt('asn'),
        );
    }

    #[Test]
    public function aMemberThatIsABooleanIsRead(): void
    {
        // When / Then
        static::assertFalse(new Document([
            'is_passive' => false,
        ])->nullableBool('is_passive'));
    }

    /**
     * A whole JSON number decodes as an integer, and a number is what the member asked for.
     */
    #[Test]
    public function aWholeNumberIsReadAsAFloat(): void
    {
        // When / Then
        static::assertSame(
            48.0,
            new Document([
                'latitude' => 48,
            ])->nullableFloat('latitude'),
        );
    }

    #[Test]
    public function aMemberThatIsADocumentIsRead(): void
    {
        // When / Then
        static::assertSame(
            ['city' => 'Paris'],
            new Document([
                'location' => [
                    'city' => 'Paris',
                ],
            ])->nested('location'),
        );
    }

    #[Test]
    public function aListMemberIsReadInItsOrder(): void
    {
        // When / Then
        static::assertSame(
            ['1', '2'],
            new Document([
                'classes' => ['1', '2'],
            ])->entries('classes'),
        );
    }

    #[Test]
    public function aListMemberThatIsAbsentHoldsNothing(): void
    {
        // When / Then
        static::assertSame([], new Document()->entries('classes'));
    }

    #[Test]
    #[DataProvider('provideReadingsOfAMemberThatIsNotWhatWasRead')]
    public function aMemberThatIsNotWhatWasReadIsRefused(callable $reading, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $reading();
    }

    /**
     * @return iterable<string, array{callable(): mixed, string}>
     */
    public static function provideReadingsOfAMemberThatIsNotWhatWasRead(): iterable
    {
        yield 'a number where a string was read' => [
            static fn (): ?string => new Document([
                'city' => 75,
            ])->nullableString('city'),
            'The member "city" must be a string or absent.',
        ];
        yield 'a string where an integer was read' => [
            static fn (): ?int => new Document([
                'asn' => '3215',
            ])->nullableInt('asn'),
            'The member "asn" must be an integer or absent.',
        ];
        yield 'a string where a boolean was read' => [
            static fn (): ?bool => new Document([
                'is_passive' => 'false',
            ])->nullableBool('is_passive'),
            'The member "is_passive" must be a boolean or absent.',
        ];
        yield 'a string where a number was read' => [
            static fn (): ?float => new Document([
                'latitude' => '48.8',
            ])->nullableFloat('latitude'),
            'The member "latitude" must be a number or absent.',
        ];
        yield 'a string where a document was read' => [
            static fn (): ?array => new Document([
                'location' => 'Paris',
            ])->nested('location'),
            'The member "location" must be a JSON object, got string.',
        ];
        yield 'an object where a list was read' => [
            static fn (): array => new Document([
                'classes' => [
                    'name' => '1',
                ],
            ])->entries('classes'),
            'The member "classes" must be a JSON list.',
        ];
    }

    #[Test]
    public function aValueThatIsNotADocumentIsRefusedUnderTheNameThatLedToIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The backup code must be a JSON object, got int.');

        // When
        Document::of(12, 'backup code');
    }
}
