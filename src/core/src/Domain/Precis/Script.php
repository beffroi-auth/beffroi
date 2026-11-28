<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use IntlChar;
use SensitiveParameter;

/**
 * RFC 5892 Appendix A: Script(cp), the Script property of Scripts.txt, not its extensions.
 */
final readonly class Script
{
    public static function of(#[SensitiveParameter] int $codePoint): int
    {
        return IntlChar::getIntPropertyValue($codePoint, IntlChar::PROPERTY_SCRIPT);
    }

    /**
     * @param non-empty-string $name a value of the Script property as PropertyValueAliases.txt names it
     */
    public static function named(string $name): int
    {
        return IntlChar::getPropertyValueEnum(IntlChar::PROPERTY_SCRIPT, $name);
    }
}
