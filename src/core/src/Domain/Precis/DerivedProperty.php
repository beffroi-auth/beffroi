<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use function in_array;
use IntlChar;
use Normalizer;

/**
 * RFC 8264 §8, from the categories of §9 as the intl of the running PHP reads the Unicode properties.
 */
final readonly class DerivedProperty
{
    /**
     * RFC 5892 §2.6, the table of the Exceptions (F) category.
     */
    private const array EXCEPTIONS = [
        0x00DF => DerivedPropertyValue::Pvalid,
        0x03C2 => DerivedPropertyValue::Pvalid,
        0x06FD => DerivedPropertyValue::Pvalid,
        0x06FE => DerivedPropertyValue::Pvalid,
        0x0F0B => DerivedPropertyValue::Pvalid,
        0x3007 => DerivedPropertyValue::Pvalid,
        0x00B7 => DerivedPropertyValue::Contexto,
        0x0375 => DerivedPropertyValue::Contexto,
        0x05F3 => DerivedPropertyValue::Contexto,
        0x05F4 => DerivedPropertyValue::Contexto,
        0x30FB => DerivedPropertyValue::Contexto,
        0x0660 => DerivedPropertyValue::Contexto,
        0x0661 => DerivedPropertyValue::Contexto,
        0x0662 => DerivedPropertyValue::Contexto,
        0x0663 => DerivedPropertyValue::Contexto,
        0x0664 => DerivedPropertyValue::Contexto,
        0x0665 => DerivedPropertyValue::Contexto,
        0x0666 => DerivedPropertyValue::Contexto,
        0x0667 => DerivedPropertyValue::Contexto,
        0x0668 => DerivedPropertyValue::Contexto,
        0x0669 => DerivedPropertyValue::Contexto,
        0x06F0 => DerivedPropertyValue::Contexto,
        0x06F1 => DerivedPropertyValue::Contexto,
        0x06F2 => DerivedPropertyValue::Contexto,
        0x06F3 => DerivedPropertyValue::Contexto,
        0x06F4 => DerivedPropertyValue::Contexto,
        0x06F5 => DerivedPropertyValue::Contexto,
        0x06F6 => DerivedPropertyValue::Contexto,
        0x06F7 => DerivedPropertyValue::Contexto,
        0x06F8 => DerivedPropertyValue::Contexto,
        0x06F9 => DerivedPropertyValue::Contexto,
        0x0640 => DerivedPropertyValue::Disallowed,
        0x07FA => DerivedPropertyValue::Disallowed,
        0x302E => DerivedPropertyValue::Disallowed,
        0x302F => DerivedPropertyValue::Disallowed,
        0x3031 => DerivedPropertyValue::Disallowed,
        0x3032 => DerivedPropertyValue::Disallowed,
        0x3033 => DerivedPropertyValue::Disallowed,
        0x3034 => DerivedPropertyValue::Disallowed,
        0x3035 => DerivedPropertyValue::Disallowed,
        0x303B => DerivedPropertyValue::Disallowed,
    ];

    /**
     * RFC 5892 §2.1
     */
    private const array LETTER_DIGITS = [
        IntlChar::CHAR_CATEGORY_LOWERCASE_LETTER,
        IntlChar::CHAR_CATEGORY_UPPERCASE_LETTER,
        IntlChar::CHAR_CATEGORY_OTHER_LETTER,
        IntlChar::CHAR_CATEGORY_DECIMAL_DIGIT_NUMBER,
        IntlChar::CHAR_CATEGORY_MODIFIER_LETTER,
        IntlChar::CHAR_CATEGORY_NON_SPACING_MARK,
        IntlChar::CHAR_CATEGORY_COMBINING_SPACING_MARK,
    ];

    /**
     * RFC 8264 §9.18, §9.14, §9.15 and §9.16, which come one after the other in §8 and give one value.
     */
    private const array OTHER_LETTER_DIGITS_SPACES_SYMBOLS_PUNCTUATION = [
        IntlChar::CHAR_CATEGORY_TITLECASE_LETTER,
        IntlChar::CHAR_CATEGORY_LETTER_NUMBER,
        IntlChar::CHAR_CATEGORY_OTHER_NUMBER,
        IntlChar::CHAR_CATEGORY_ENCLOSING_MARK,
        IntlChar::CHAR_CATEGORY_SPACE_SEPARATOR,
        IntlChar::CHAR_CATEGORY_MATH_SYMBOL,
        IntlChar::CHAR_CATEGORY_CURRENCY_SYMBOL,
        IntlChar::CHAR_CATEGORY_MODIFIER_SYMBOL,
        IntlChar::CHAR_CATEGORY_OTHER_SYMBOL,
        IntlChar::CHAR_CATEGORY_CONNECTOR_PUNCTUATION,
        IntlChar::CHAR_CATEGORY_DASH_PUNCTUATION,
        IntlChar::CHAR_CATEGORY_START_PUNCTUATION,
        IntlChar::CHAR_CATEGORY_END_PUNCTUATION,
        IntlChar::CHAR_CATEGORY_INITIAL_PUNCTUATION,
        IntlChar::CHAR_CATEGORY_FINAL_PUNCTUATION,
        IntlChar::CHAR_CATEGORY_OTHER_PUNCTUATION,
    ];

    /**
     * The order of §8 is the specification's, and an implementation must not change it. BackwardCompatible (G) is
     * the empty set (RFC 5892 §2.7).
     */
    public static function of(int $codePoint): DerivedPropertyValue
    {
        $category = IntlChar::charType($codePoint);
        if (isset(self::EXCEPTIONS[$codePoint])) {
            return self::EXCEPTIONS[$codePoint];
        }
        if (self::isUnassigned($codePoint, $category)) {
            return DerivedPropertyValue::Unassigned;
        }
        if (self::isAscii7($codePoint)) {
            return DerivedPropertyValue::Pvalid;
        }
        if (IntlChar::hasBinaryProperty($codePoint, IntlChar::PROPERTY_JOIN_CONTROL)) {
            return DerivedPropertyValue::Contextj;
        }
        // Control(cp) of §9.12 is the General_Category Control (Cc), which Unicode names no other property.
        if (self::isOldHangulJamo($codePoint) || self::isPrecisIgnorable($codePoint) || $category === IntlChar::CHAR_CATEGORY_CONTROL_CHAR) {
            return DerivedPropertyValue::Disallowed;
        }
        if (self::hasCompat($codePoint)) {
            return DerivedPropertyValue::FreePval;
        }
        if (in_array($category, self::LETTER_DIGITS, true)) {
            return DerivedPropertyValue::Pvalid;
        }

        return in_array($category, self::OTHER_LETTER_DIGITS_SPACES_SYMBOLS_PUNCTUATION, true)
            ? DerivedPropertyValue::FreePval
            : DerivedPropertyValue::Disallowed;
    }

    /**
     * RFC 5892 §2.10
     */
    private static function isUnassigned(int $codePoint, ?int $category): bool
    {
        return $category === IntlChar::CHAR_CATEGORY_UNASSIGNED && ! IntlChar::hasBinaryProperty($codePoint, IntlChar::PROPERTY_NONCHARACTER_CODE_POINT);
    }

    /**
     * RFC 8264 §9.11
     */
    private static function isAscii7(int $codePoint): bool
    {
        return $codePoint >= 0x21 && $codePoint <= 0x7E;
    }

    /**
     * RFC 5892 §2.9
     */
    private static function isOldHangulJamo(int $codePoint): bool
    {
        return in_array(
            IntlChar::getIntPropertyValue($codePoint, IntlChar::PROPERTY_HANGUL_SYLLABLE_TYPE),
            [IntlChar::HST_LEADING_JAMO, IntlChar::HST_VOWEL_JAMO, IntlChar::HST_TRAILING_JAMO],
            true,
        );
    }

    /**
     * RFC 8264 §9.13
     */
    private static function isPrecisIgnorable(int $codePoint): bool
    {
        return (
            IntlChar::hasBinaryProperty($codePoint, IntlChar::PROPERTY_DEFAULT_IGNORABLE_CODE_POINT)
            || IntlChar::hasBinaryProperty($codePoint, IntlChar::PROPERTY_NONCHARACTER_CODE_POINT)
        );
    }

    /**
     * RFC 8264 §9.17
     */
    private static function hasCompat(int $codePoint): bool
    {
        $character = IntlChar::chr($codePoint) ?? '';
        $normalized = Normalizer::normalize($character, Normalizer::FORM_KC);

        return $normalized !== false && $normalized !== $character;
    }
}
