<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 5892 Appendix A.5 and A.6, one rule for both: preceded by a character of the Hebrew script.
 */
final readonly class HebrewGereshOrGershayim implements ContextualRuleInterface
{
    public function appliesTo(int $codePoint): bool
    {
        return $codePoint === 0x05F3 || $codePoint === 0x05F4;
    }

    public function allows(array $codePoints, int $position): bool
    {
        return $position > 0 && Script::of($codePoints[$position - 1]) === Script::named('Hebrew');
    }
}
