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
        return BehavioralRules::firstRefused($codePoints, [DerivedPropertyValue::Pvalid]);
    }
}
