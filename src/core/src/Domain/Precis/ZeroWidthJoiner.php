<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 5892 Appendix A.2
 */
final readonly class ZeroWidthJoiner implements ContextualRuleInterface
{
    public function appliesTo(int $codePoint): bool
    {
        return $codePoint === 0x200D;
    }

    public function allows(array $codePoints, int $position): bool
    {
        return Virama::precedes($codePoints, $position);
    }
}
