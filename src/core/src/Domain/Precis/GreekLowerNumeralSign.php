<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 5892 Appendix A.4: the keraia, followed by a character of the Greek script.
 */
final readonly class GreekLowerNumeralSign implements ContextualRuleInterface
{
    public function appliesTo(int $codePoint): bool
    {
        return $codePoint === 0x0375;
    }

    public function allows(array $codePoints, int $position): bool
    {
        return isset($codePoints[$position + 1]) && Script::of($codePoints[$position + 1]) === Script::named('Greek');
    }
}
