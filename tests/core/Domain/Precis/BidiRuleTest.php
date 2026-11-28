<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Precis;

use function array_map;
use Beffroi\Core\Domain\Precis\BidiRule;
use function mb_ord;
use function mb_str_split;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class BidiRuleTest extends TestCase
{
    /**
     * RFC 5893 §1.4
     */
    #[Test]
    #[DataProvider('provideRightToLeftLabels')]
    public function aLabelThatHoldsACharacterOfTheBidiPropertyRAlOrAnIsRightToLeft(string $label): void
    {
        // When / Then
        static::assertTrue(BidiRule::isRightToLeft(self::codePoints($label)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRightToLeftLabels(): iterable
    {
        yield 'R, a Hebrew letter among Latin ones' => ["ab\u{05D0}"];
        yield 'AL, an Arabic letter' => ["\u{0628}"];
        yield 'AN, an Arabic-Indic digit' => ["1\u{0661}"];
    }

    /**
     * RFC 5893 §1.4
     */
    #[Test]
    public function aLabelOfLeftToRightAndNeutralCharactersIsNot(): void
    {
        // When / Then
        static::assertFalse(BidiRule::isRightToLeft(self::codePoints('alice-42@example.com')));
    }

    /**
     * RFC 5893 §2
     */
    #[Test]
    #[DataProvider('provideLabelsThatHoldTheRule')]
    public function aLabelThatMeetsTheSixConditionsHoldsTheRule(string $label): void
    {
        // When / Then
        static::assertTrue(BidiRule::holds(self::codePoints($label)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLabelsThatHoldTheRule(): iterable
    {
        yield 'a Hebrew word' => ["\u{05E9}\u{05DC}\u{05D5}\u{05DD}"];
        yield 'an Arabic word ending with Arabic-Indic digits' => ["\u{0628}\u{0661}\u{0662}"];
        yield 'a Hebrew word ending with European digits' => ["\u{05D0}12"];
        yield 'a Hebrew word ending with a nonspacing mark' => ["\u{05D0}\u{05B7}"];
        yield 'a Latin word with a European digit' => ['alice2'];
    }

    /**
     * RFC 5893 §2
     */
    #[Test]
    #[DataProvider('provideLabelsThatBreakTheRule')]
    public function aLabelThatBreaksAConditionDoesNotHoldTheRule(string $label): void
    {
        // When / Then
        static::assertFalse(BidiRule::holds(self::codePoints($label)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLabelsThatBreakTheRule(): iterable
    {
        yield 'condition 1, beginning with a European digit' => ["1\u{05D0}"];
        yield 'condition 1, beginning with an Arabic-Indic digit' => ["\u{0661}\u{0628}"];
        yield 'condition 1, empty' => [''];
        yield 'condition 2, a Latin letter in a right-to-left label' => ["\u{05D0}a\u{05D1}"];
        yield 'condition 3, a right-to-left label ending with a neutral' => ["\u{05D0}@"];
        yield 'condition 4, European and Arabic-Indic digits in one label' => ["\u{0628}1\u{0662}"];
        yield 'condition 5, a Hebrew letter in a left-to-right label' => ["a\u{05D0}b"];
        yield 'condition 6, a left-to-right label ending with a neutral' => ['alice@'];
    }

    /**
     * @return list<int>
     */
    private static function codePoints(string $text): array
    {
        return array_map(mb_ord(...), mb_str_split($text));
    }
}
