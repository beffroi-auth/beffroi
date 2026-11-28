<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use function in_array;
use IntlChar;
use SensitiveParameter;

/**
 * RFC 5892 Appendix A.1, the regular expression anchored on the occurrence evaluated (erratum 3312).
 */
final readonly class ZeroWidthNonJoiner implements ContextualRuleInterface
{
    public function appliesTo(#[SensitiveParameter] int $codePoint): bool
    {
        return $codePoint === 0x200C;
    }

    public function allows(#[SensitiveParameter] array $codePoints, int $position): bool
    {
        return (
            Virama::precedes($codePoints, $position)
            || self::nearestJoining($codePoints, $position, -1, [IntlChar::JT_LEFT_JOINING, IntlChar::JT_DUAL_JOINING])
            && self::nearestJoining($codePoints, $position, 1, [IntlChar::JT_RIGHT_JOINING, IntlChar::JT_DUAL_JOINING])
        );
    }

    /**
     * (Joining_Type:T)* then one of the types, walking away from the position in the direction given.
     *
     * @param list<int> $codePoints
     * @param list<int> $types
     */
    private static function nearestJoining(#[SensitiveParameter] array $codePoints, int $position, int $direction, array $types): bool
    {
        for ($at = $position + $direction; isset($codePoints[$at]); $at += $direction) {
            $type = IntlChar::getIntPropertyValue($codePoints[$at], IntlChar::PROPERTY_JOINING_TYPE);
            if ($type !== IntlChar::JT_TRANSPARENT) {
                return in_array($type, $types, true);
            }
        }

        return false;
    }
}
