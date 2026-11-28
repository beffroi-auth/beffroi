<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use function array_any;
use function array_reverse;
use function in_array;
use IntlChar;

/**
 * RFC 5893 §2
 */
final readonly class BidiRule
{
    /**
     * RFC 5893 §1.4
     */
    private const array RIGHT_TO_LEFT = [
        IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT,
        IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT_ARABIC,
        IntlChar::CHAR_DIRECTION_ARABIC_NUMBER,
    ];

    /**
     * Condition 2
     */
    private const array IN_A_RIGHT_TO_LEFT_LABEL = [
        IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT,
        IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT_ARABIC,
        IntlChar::CHAR_DIRECTION_ARABIC_NUMBER,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER_SEPARATOR,
        IntlChar::CHAR_DIRECTION_COMMON_NUMBER_SEPARATOR,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER_TERMINATOR,
        IntlChar::CHAR_DIRECTION_OTHER_NEUTRAL,
        IntlChar::CHAR_DIRECTION_BOUNDARY_NEUTRAL,
        IntlChar::CHAR_DIRECTION_DIR_NON_SPACING_MARK,
    ];

    /**
     * Condition 3
     */
    private const array ENDING_A_RIGHT_TO_LEFT_LABEL = [
        IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT,
        IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT_ARABIC,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER,
        IntlChar::CHAR_DIRECTION_ARABIC_NUMBER,
    ];

    /**
     * Condition 5
     */
    private const array IN_A_LEFT_TO_RIGHT_LABEL = [
        IntlChar::CHAR_DIRECTION_LEFT_TO_RIGHT,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER_SEPARATOR,
        IntlChar::CHAR_DIRECTION_COMMON_NUMBER_SEPARATOR,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER_TERMINATOR,
        IntlChar::CHAR_DIRECTION_OTHER_NEUTRAL,
        IntlChar::CHAR_DIRECTION_BOUNDARY_NEUTRAL,
        IntlChar::CHAR_DIRECTION_DIR_NON_SPACING_MARK,
    ];

    /**
     * Condition 6
     */
    private const array ENDING_A_LEFT_TO_RIGHT_LABEL = [
        IntlChar::CHAR_DIRECTION_LEFT_TO_RIGHT,
        IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER,
    ];

    /**
     * RFC 5893 §1.4: a label that holds a character of the Bidi property R, AL or AN.
     *
     * @param list<int> $codePoints
     */
    public static function isRightToLeft(array $codePoints): bool
    {
        return array_any($codePoints, static fn (int $codePoint): bool => in_array(IntlChar::charDirection($codePoint), self::RIGHT_TO_LEFT, true));
    }

    /**
     * The six conditions, the first deciding which of the others apply.
     *
     * @param list<int> $codePoints
     */
    public static function holds(array $codePoints): bool
    {
        $directions = [];
        foreach ($codePoints as $codePoint) {
            $directions[] = IntlChar::charDirection($codePoint);
        }

        return match ($directions[0] ?? null) {
            IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT, IntlChar::CHAR_DIRECTION_RIGHT_TO_LEFT_ARABIC => self::holdsRightToLeft($directions),
            IntlChar::CHAR_DIRECTION_LEFT_TO_RIGHT => self::holdsLeftToRight($directions),
            default => false,
        };
    }

    /**
     * Conditions 2, 3 and 4
     *
     * @param list<int|null> $directions
     */
    private static function holdsRightToLeft(array $directions): bool
    {
        return (
            self::onlyOf($directions, self::IN_A_RIGHT_TO_LEFT_LABEL)
            && in_array(self::lastBeforeTheMarks($directions), self::ENDING_A_RIGHT_TO_LEFT_LABEL, true)
            && ! (in_array(IntlChar::CHAR_DIRECTION_EUROPEAN_NUMBER, $directions, true) && in_array(IntlChar::CHAR_DIRECTION_ARABIC_NUMBER, $directions, true))
        );
    }

    /**
     * Conditions 5 and 6
     *
     * @param list<int|null> $directions
     */
    private static function holdsLeftToRight(array $directions): bool
    {
        return (
            self::onlyOf($directions, self::IN_A_LEFT_TO_RIGHT_LABEL)
            && in_array(self::lastBeforeTheMarks($directions), self::ENDING_A_LEFT_TO_RIGHT_LABEL, true)
        );
    }

    /**
     * @param list<int|null> $directions
     * @param list<int> $allowed
     */
    private static function onlyOf(array $directions, array $allowed): bool
    {
        return ! array_any($directions, static fn (?int $direction): bool => ! in_array($direction, $allowed, true));
    }

    /**
     * The character the label ends with, followed by zero or more of the Bidi property NSM.
     *
     * @param list<int|null> $directions
     */
    private static function lastBeforeTheMarks(array $directions): ?int
    {
        foreach (array_reverse($directions) as $direction) {
            if ($direction !== IntlChar::CHAR_DIRECTION_DIR_NON_SPACING_MARK) {
                return $direction;
            }
        }

        return null;
    }
}
