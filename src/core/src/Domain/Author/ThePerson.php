<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

/**
 * The person the act concerns, acting themselves.
 */
final readonly class ThePerson implements AuthorInterface
{
    public const string KIND = 'person';

    public function kind(): string
    {
        return self::KIND;
    }

    public function toDocument(): array
    {
        return [self::MEMBER => self::KIND];
    }
}
