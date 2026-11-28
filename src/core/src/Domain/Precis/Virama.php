<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use IntlChar;

/**
 * RFC 5892 Appendix A.1 and A.2: Canonical_Combining_Class(Before(cp)) .eq. Virama.
 */
final readonly class Virama
{
    private const int COMBINING_CLASS = 9;

    /**
     * @param list<int> $codePoints
     */
    public static function precedes(array $codePoints, int $position): bool
    {
        return $position > 0 && IntlChar::getCombiningClass($codePoints[$position - 1]) === self::COMBINING_CLASS;
    }
}
