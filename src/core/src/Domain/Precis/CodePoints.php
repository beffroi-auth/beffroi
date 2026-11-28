<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use IntlChar;
use function mb_ord;
use function mb_str_split;
use SensitiveParameter;

/**
 * A string of UTF-8 read as the code points the rules of RFC 8264 apply to, and written back.
 */
final readonly class CodePoints
{
    /**
     * @return list<int>
     */
    public static function of(#[SensitiveParameter] string $text): array
    {
        $codePoints = [];
        foreach (mb_str_split($text) as $character) {
            $codePoints[] = mb_ord($character);
        }

        return $codePoints;
    }

    /**
     * @param list<int> $codePoints
     */
    public static function text(#[SensitiveParameter] array $codePoints): string
    {
        $text = '';
        foreach ($codePoints as $codePoint) {
            $text .= IntlChar::chr($codePoint);
        }

        return $text;
    }
}
