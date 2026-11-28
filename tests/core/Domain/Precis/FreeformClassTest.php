<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Precis;

use Beffroi\Core\Domain\Precis\CodePoints;
use Beffroi\Core\Domain\Precis\FreeformClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class FreeformClassTest extends TestCase
{
    /**
     * RFC 8264 §4.3.1, §4.3.2, RFC 5892 Appendix A
     */
    #[Test]
    #[DataProvider('provideStringsTheClassAdmits')]
    public function aStringOfCodePointsTheClassAdmitsWhereTheyStandIsAdmitted(string $text): void
    {
        // When / Then
        static::assertNull(FreeformClass::firstRefused(CodePoints::of($text)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStringsTheClassAdmits(): iterable
    {
        yield 'letters and digits of several scripts, LetterDigits (A)' => ['alice42πжא張'];
        yield 'printable ASCII, ASCII7 (K)' => ['~!@#$%^&*()_+'];
        yield 'a space and a no-break space, Spaces (N)' => ["a b\u{00A0}c\u{1680}d"];
        yield 'a black diamond suit and a euro sign, Symbols (O)' => ["\u{2666}\u{20AC}"];
        yield 'an em dash and a guillemet, Punctuation (P)' => ["\u{2014}\u{00AB}"];
        yield 'a Roman numeral and a ligature, HasCompat (Q)' => ["\u{2163}\u{FB01}"];
        yield 'a fullwidth letter, HasCompat (Q)' => ["\u{FF41}"];
        yield 'a runic letter number, OtherLetterDigits (R)' => ["\u{16EE}"];
        yield 'an emoji' => ["\u{1F600}"];
        yield 'a zero width joiner after a virama, Appendix A.2' => ["\u{0915}\u{094D}\u{200D}\u{0937}"];
        yield 'a middle dot between two l, Appendix A.3' => ["col\u{00B7}lecci\u{00F3}"];
    }

    /**
     * RFC 8264 §4.3.2, §4.3.3, §4.3.4, RFC 8265 §4.1, RFC 5892 Appendix A
     *
     * @param int $position of the first code point refused
     */
    #[Test]
    #[DataProvider('provideStringsTheClassRefuses')]
    public function theFirstCodePointTheClassRefusesIsNamedByItsPosition(string $text, int $position): void
    {
        // When / Then
        static::assertSame($position, FreeformClass::firstRefused(CodePoints::of($text)));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideStringsTheClassRefuses(): iterable
    {
        yield 'a tabulation, Controls (L)' => ["my cat is a \u{0009}by", 12];
        yield 'a delete, Controls (L)' => ["ab\u{007F}", 2];
        yield 'a soft hyphen, PrecisIgnorableProperties (M)' => ["al\u{00AD}ice", 2];
        yield 'a zero width space, PrecisIgnorableProperties (M)' => ["a\u{200B}b", 1];
        yield 'the variation selector of an emoji, PrecisIgnorableProperties (M)' => ["\u{2764}\u{FE0F}", 1];
        yield 'a noncharacter, PrecisIgnorableProperties (M)' => ["a\u{FDD0}", 1];
        yield 'an old Hangul jamo, OldHangulJamo (I)' => ["\u{1100}", 0];
        yield 'a code point of private use, refused by RFC 8265 §4.1' => ["a\u{E000}", 1];
        yield 'a code point no version of Unicode assigns yet, Unassigned (J)' => ["a\u{40000}", 1];
        yield 'a zero width joiner between two emoji, Appendix A.2' => ["\u{1F468}\u{200D}\u{1F469}", 1];
        yield 'a middle dot after a capital L, Appendix A.3' => ["L\u{00B7}l", 1];
    }
}
