<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use Closure;
use SensitiveParameter;

/**
 * RFC 8264 §7: the rules of a profile applied again until the output is stable, at most three times after the first.
 */
final readonly class Reapplication
{
    private const int TIMES = 3;

    /**
     * @param Closure(string): string $rules which throw what the profile refuses
     *
     * @return string|null the stable output, null when it does not settle
     */
    public static function settled(#[SensitiveParameter] string $text, Closure $rules): ?string
    {
        $output = $rules($text);
        for ($reapplied = 0; $reapplied < self::TIMES; ++$reapplied) {
            $again = $rules($output);
            if ($again === $output) {
                return $output;
            }
            $output = $again;
        }

        return null;
    }
}
