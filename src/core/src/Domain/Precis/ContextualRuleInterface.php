<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 5892 Appendix A, evaluated for each occurrence of its code point (erratum 3312).
 */
interface ContextualRuleInterface
{
    public function appliesTo(int $codePoint): bool;

    /**
     * Before the first and after the last code point is Undefined, which no rule allows.
     *
     * @param list<int> $codePoints the string, in network order
     */
    public function allows(array $codePoints, int $position): bool;
}
