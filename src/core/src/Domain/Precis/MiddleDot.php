<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 5892 Appendix A.3: the ela geminada of Catalan, between two "l".
 */
final readonly class MiddleDot implements ContextualRuleInterface
{
    private const int SMALL_L = 0x006C;

    public function appliesTo(int $codePoint): bool
    {
        return $codePoint === 0x00B7;
    }

    public function allows(array $codePoints, int $position): bool
    {
        return ($codePoints[$position - 1] ?? null) === self::SMALL_L && ($codePoints[$position + 1] ?? null) === self::SMALL_L;
    }
}
