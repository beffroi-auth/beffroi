<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use function array_any;

/**
 * RFC 5892 Appendix A.8 and A.9, the one rule read from either side: a digit of one of the two sets of Arabic digits
 * in a string that holds no digit of the other.
 */
final readonly class ArabicDigitsUnmixed implements WholeStringRuleInterface
{
    private const int ARABIC_INDIC_ZERO = 0x0660;

    private const int EXTENDED_ARABIC_INDIC_ZERO = 0x06F0;

    private function __construct(
        private int $zero,
        private int $otherZero,
    ) {
    }

    /**
     * RFC 5892 Appendix A.8
     */
    public static function arabicIndic(): self
    {
        return new self(self::ARABIC_INDIC_ZERO, self::EXTENDED_ARABIC_INDIC_ZERO);
    }

    /**
     * RFC 5892 Appendix A.9
     */
    public static function extendedArabicIndic(): self
    {
        return new self(self::EXTENDED_ARABIC_INDIC_ZERO, self::ARABIC_INDIC_ZERO);
    }

    public function appliesTo(int $codePoint): bool
    {
        return self::isDigitOf($codePoint, $this->zero);
    }

    public function allows(array $codePoints, int $position): bool
    {
        return ! array_any($codePoints, fn (int $codePoint): bool => self::isDigitOf($codePoint, $this->otherZero));
    }

    private static function isDigitOf(int $codePoint, int $zero): bool
    {
        return $codePoint >= $zero && $codePoint <= ($zero + 9);
    }
}
