<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Internal;

use Beffroi\Xml\Enc\Internal\BlockPadding;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * E-16, XML Encryption 1.1 §5.2: the padding of AES-CBC, read by its count, the last octet, from 1 to a block.
 */
final class BlockPaddingTest extends TestCase
{
    /**
     * §9.3 row 23, E-16: a count of 1 to 16 removes that many octets, whatever the others of the padding hold.
     */
    #[Test]
    #[DataProvider('provideCountsInRange')]
    public function itRemovesAsManyOctetsAsTheCountSays(string $padded, string $plaintext): void
    {
        // When / Then
        static::assertSame($plaintext, BlockPadding::strip($padded));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCountsInRange(): iterable
    {
        yield 'a count of 1' => [str_repeat('A', 15) . "\x01", str_repeat('A', 15)];
        yield 'a count of 2, the octet before it another' => [str_repeat('A', 14) . "\xfe\x02", str_repeat('A', 14)];
        yield 'a count of 16, a whole block of random octets' => [
            str_repeat('A', 16) . "\x9c\x01\x7f\xe2\x10\x33\xa0\x05\x88\x41\xd4\x0f\x6b\x20\xee\x10",
            str_repeat('A', 16),
        ];
        yield 'a count of 16, the count repeated, as xmlseclibs writes it' => [
            str_repeat('A', 16) . str_repeat("\x10", 16),
            str_repeat('A', 16),
        ];
    }

    /**
     * §9.3 row 23, E-16: a count of 0, or above 16, is no padding of a block of 16 octets.
     */
    #[Test]
    #[DataProvider('provideCountsOutOfRange')]
    public function itRefusesACountOutOfRange(string $padded): void
    {
        // When / Then
        static::assertNull(BlockPadding::strip($padded));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCountsOutOfRange(): iterable
    {
        yield 'a count of 0' => [str_repeat('A', 31) . "\x00"];
        yield 'a count of 17' => [str_repeat('A', 31) . "\x11"];
        yield 'a count of 32' => [str_repeat('A', 31) . "\x20"];
        yield 'a count of 255' => [str_repeat('A', 31) . "\xff"];
    }
}
