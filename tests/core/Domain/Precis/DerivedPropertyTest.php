<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Precis;

use Beffroi\Core\Domain\Precis\DerivedProperty;
use Beffroi\Core\Domain\Precis\DerivedPropertyValue;
use function explode;
use function fgetcsv;
use function fopen;
use function hexdec;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_contains;

final class DerivedPropertyTest extends TestCase
{
    /**
     * The registry of RFC 8264 §11.1 for Unicode 6.3.0, as the IANA publishes it.
     */
    private const string REGISTRY = __DIR__ . '/../../Fixture/Precis/precis-tables-6.3.0.csv';

    /**
     * RFC 8264 §8, §9
     */
    #[Test]
    #[DataProvider('provideCodePoints')]
    public function aCodePointTakesTheValueOfTheFirstCategoryItIsIn(int $codePoint, DerivedPropertyValue $value): void
    {
        // When / Then
        static::assertSame($value, DerivedProperty::of($codePoint));
    }

    /**
     * @return iterable<string, array{int, DerivedPropertyValue}>
     */
    public static function provideCodePoints(): iterable
    {
        yield 'an exception made valid, the eszett' => [0x00DF, DerivedPropertyValue::Pvalid];
        yield 'an exception given a contextual rule, the middle dot' => [0x00B7, DerivedPropertyValue::Contexto];
        yield 'an exception given a contextual rule, an Arabic-Indic digit' => [0x0661, DerivedPropertyValue::Contexto];
        yield 'an exception disallowed, the Arabic tatweel' => [0x0640, DerivedPropertyValue::Disallowed];
        yield 'unassigned' => [0x40000, DerivedPropertyValue::Unassigned];
        yield 'ASCII7, a punctuation mark it keeps' => [0x0021, DerivedPropertyValue::Pvalid];
        yield 'JoinControl, the zero width joiner' => [0x200D, DerivedPropertyValue::Contextj];
        yield 'OldHangulJamo' => [0x1100, DerivedPropertyValue::Disallowed];
        yield 'PrecisIgnorableProperties, the soft hyphen' => [0x00AD, DerivedPropertyValue::Disallowed];
        yield 'PrecisIgnorableProperties, a noncharacter' => [0xFDD0, DerivedPropertyValue::Disallowed];
        yield 'Controls' => [0x0085, DerivedPropertyValue::Disallowed];
        yield 'HasCompat, a fullwidth letter' => [0xFF21, DerivedPropertyValue::FreePval];
        yield 'HasCompat, a no-break space' => [0x00A0, DerivedPropertyValue::FreePval];
        yield 'LetterDigits, a small letter' => [0x03C0, DerivedPropertyValue::Pvalid];
        yield 'LetterDigits, a capital letter' => [0x0416, DerivedPropertyValue::Pvalid];
        yield 'LetterDigits, a combining mark' => [0x0301, DerivedPropertyValue::Pvalid];
        yield 'OtherLetterDigits, an enclosing mark' => [0x20DD, DerivedPropertyValue::FreePval];
        yield 'Spaces, the space' => [0x0020, DerivedPropertyValue::FreePval];
        yield 'Spaces, the Ogham space mark' => [0x1680, DerivedPropertyValue::FreePval];
        yield 'Symbols, an emoji' => [0x1F600, DerivedPropertyValue::FreePval];
        yield 'Punctuation, the em dash' => [0x2014, DerivedPropertyValue::FreePval];
        yield 'none of them, a code point of private use' => [0xE000, DerivedPropertyValue::Disallowed];
        yield 'none of them, the line separator' => [0x2028, DerivedPropertyValue::Disallowed];
    }

    /**
     * RFC 8264 §11.1: every code point the registry assigns a value under Unicode 6.3.0, the unassigned ones left out,
     * which later versions assign.
     */
    #[Test]
    public function everyCodePointTakesTheValueTheRegistryOfUnicode630Gives(): void
    {
        // Given
        $registry = fopen(self::REGISTRY, 'r');
        if ($registry === false) {
            static::fail('The registry of the IANA cannot be read.');
        }
        fgetcsv($registry, escape: '');

        // When
        $differing = [];
        while (($row = fgetcsv($registry, escape: '')) !== false) {
            [$range, $value] = [(string) $row[0], (string) $row[1]];
            if ($value === 'UNASSIGNED') {
                continue;
            }
            [$first, $last] = str_contains($range, '-') ? explode('-', $range) : [$range, $range];
            for ($codePoint = (int) hexdec($first); $codePoint <= (int) hexdec($last); ++$codePoint) {
                $derived = DerivedProperty::of($codePoint);
                if (($derived === DerivedPropertyValue::FreePval ? 'ID_DIS or FREE_PVAL' : $derived->value) !== $value) {
                    $differing[] = sprintf('U+%04X: %s, %s in the registry', $codePoint, $derived->value, $value);
                }
            }
        }

        // Then
        static::assertSame([], $differing);
    }
}
