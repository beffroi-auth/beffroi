<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

/**
 * The provider acting of itself, by its schedule or a purge, or at the order of its operator, by the console, whose
 * provenance names the user of the shell (decision 0038).
 */
final readonly class TheHost implements AuthorInterface
{
    public const string KIND = 'host';

    public function kind(): string
    {
        return self::KIND;
    }

    public function toDocument(): array
    {
        return [self::MEMBER => self::KIND];
    }
}
