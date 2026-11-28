<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use function array_any;
use function in_array;

/**
 * RFC 5892 Appendix A.7: somewhere in the string, a character of the Hiragana, Katakana or Han script.
 */
final readonly class KatakanaMiddleDot implements WholeStringRuleInterface
{
    public function appliesTo(int $codePoint): bool
    {
        return $codePoint === 0x30FB;
    }

    public function allows(array $codePoints, int $position): bool
    {
        $scripts = [Script::named('Hiragana'), Script::named('Katakana'), Script::named('Han')];

        return array_any($codePoints, static fn (int $codePoint): bool => in_array(Script::of($codePoint), $scripts, true));
    }
}
