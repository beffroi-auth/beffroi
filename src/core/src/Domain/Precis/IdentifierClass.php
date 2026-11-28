<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 8264 §4.2
 */
final readonly class IdentifierClass
{
    /**
     * @param list<int> $codePoints
     *
     * @return int|null the position of the first code point the class refuses
     */
    public static function firstRefused(array $codePoints): ?int
    {
        $rules = self::contextualRules();
        $verdicts = [];
        foreach ($codePoints as $position => $codePoint) {
            $admitted = match (DerivedProperty::of($codePoint)) {
                DerivedPropertyValue::Pvalid => true,
                DerivedPropertyValue::Contextj, DerivedPropertyValue::Contexto => self::allowedWhereItStands($rules, $codePoints, $position, $verdicts),
                default => false,
            };
            if (! $admitted) {
                return $position;
            }
        }

        return null;
    }

    /**
     * RFC 8264 §8: a code point of a contextual rule is refused when no rule applies to it, as when its rule does not
     * allow it there.
     *
     * @param list<ContextualRuleInterface> $rules
     * @param list<int> $codePoints
     * @param array<int, bool> $verdicts of the rules that read the whole string, by their place in the list
     */
    private static function allowedWhereItStands(array $rules, array $codePoints, int $position, array &$verdicts): bool
    {
        foreach ($rules as $place => $rule) {
            if ($rule->appliesTo($codePoints[$position])) {
                return $rule instanceof WholeStringRuleInterface
                    ? ($verdicts[$place] ??= $rule->allows($codePoints, $position))
                    : $rule->allows($codePoints, $position);
            }
        }

        return false;
    }

    /**
     * @return list<ContextualRuleInterface> RFC 5892 Appendix A
     */
    private static function contextualRules(): array
    {
        return [
            new ZeroWidthNonJoiner(),
            new ZeroWidthJoiner(),
            new MiddleDot(),
            new GreekLowerNumeralSign(),
            new HebrewGereshOrGershayim(),
            new KatakanaMiddleDot(),
            ArabicDigitsUnmixed::arabicIndic(),
            ArabicDigitsUnmixed::extendedArabicIndic(),
        ];
    }
}
