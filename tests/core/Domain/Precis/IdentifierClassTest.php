<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Precis;

use function array_map;
use Beffroi\Core\Domain\Precis\IdentifierClass;
use function mb_ord;
use function mb_str_split;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class IdentifierClassTest extends TestCase
{
    /**
     * RFC 8264 §4.2.1, §4.2.2, RFC 5892 Appendix A
     */
    #[Test]
    #[DataProvider('provideStringsTheClassAdmits')]
    public function aStringOfCodePointsTheClassAdmitsWhereTheyStandIsAdmitted(string $text): void
    {
        // When / Then
        static::assertNull(IdentifierClass::firstRefused(self::codePoints($text)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStringsTheClassAdmits(): iterable
    {
        yield 'letters and digits of several scripts' => ['alice42πжא張'];
        yield 'printable ASCII' => ['~!@#$%^&*()_+'];
        yield 'a zero width non-joiner after a virama, Appendix A.1' => ["\u{0915}\u{094D}\u{200C}\u{0937}"];
        yield 'a zero width non-joiner between two Arabic letters that join, Appendix A.1' => ["\u{0628}\u{200C}\u{0628}"];
        yield 'a zero width joiner after a virama, Appendix A.2' => ["\u{0915}\u{094D}\u{200D}\u{0937}"];
        yield 'a middle dot between two l, Appendix A.3' => ["col\u{00B7}lecci\u{00F3}"];
        yield 'a keraia followed by a Greek letter, Appendix A.4' => ["\u{0375}\u{03B1}"];
        yield 'a geresh after a Hebrew letter, Appendix A.5' => ["\u{05D0}\u{05F3}"];
        yield 'a gershayim after a Hebrew letter, Appendix A.6' => ["\u{05D0}\u{05F4}"];
        yield 'a Katakana middle dot beside Katakana, Appendix A.7' => ["\u{30AB}\u{30FB}\u{30AB}"];
        yield 'Katakana middle dots before the one Katakana letter, Appendix A.7' => ["\u{30FB}\u{30FB}\u{30AB}"];
        yield 'Arabic-Indic digits alone, Appendix A.8' => ["\u{0661}\u{0662}"];
        yield 'extended Arabic-Indic digits alone, Appendix A.9' => ["\u{06F1}\u{06F2}"];
    }

    /**
     * RFC 8264 §4.2.2, §4.2.3, §8, RFC 5892 Appendix A
     *
     * @param int $position of the first code point refused
     */
    #[Test]
    #[DataProvider('provideStringsTheClassRefuses')]
    public function theFirstCodePointTheClassRefusesIsNamedByItsPosition(string $text, int $position): void
    {
        // When / Then
        static::assertSame($position, IdentifierClass::firstRefused(self::codePoints($text)));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideStringsTheClassRefuses(): iterable
    {
        yield 'a space, then a symbol' => ['ab c∞', 2];
        yield 'a zero width non-joiner between Latin letters, Appendix A.1' => ["a\u{200C}b", 1];
        yield 'a zero width non-joiner first, Appendix A.1' => ["\u{200C}\u{0628}", 0];
        yield 'a zero width joiner after no virama, Appendix A.2' => ["\u{0915}\u{200D}", 1];
        yield 'a middle dot after a capital L, Appendix A.3' => ["L\u{00B7}l", 1];
        yield 'a middle dot that ends the string, Appendix A.3' => ["l\u{00B7}", 1];
        yield 'a keraia followed by a Latin letter, Appendix A.4' => ["\u{0375}a", 0];
        yield 'a keraia that ends the string, Appendix A.4' => ["\u{03B1}\u{0375}", 1];
        yield 'a geresh after a Latin letter, Appendix A.5' => ["a\u{05F3}", 1];
        yield 'a gershayim that begins the string, Appendix A.6' => ["\u{05F4}\u{05D0}", 0];
        yield 'a Katakana middle dot with no Hiragana, Katakana or Han, Appendix A.7' => ["a\u{30FB}b", 1];
        yield 'an Arabic-Indic digit beside an extended one, Appendix A.8' => ["\u{0661}\u{06F2}", 0];
        yield 'an extended Arabic-Indic digit beside an Arabic-Indic one, Appendix A.9' => ["\u{06F2}\u{0661}", 0];
    }

    /**
     * @return list<int>
     */
    private static function codePoints(string $text): array
    {
        return array_map(mb_ord(...), mb_str_split($text));
    }
}
