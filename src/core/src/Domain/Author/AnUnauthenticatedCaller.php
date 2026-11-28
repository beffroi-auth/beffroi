<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

/**
 * Whoever sent a request nobody had authenticated when it was refused, told by the provenance of that request alone: the
 * author of a refused attempt (decision 0066).
 */
final readonly class AnUnauthenticatedCaller implements AuthorInterface
{
    public const string KIND = 'unauthenticated';

    public function kind(): string
    {
        return self::KIND;
    }

    public function toDocument(): array
    {
        return [self::MEMBER => self::KIND];
    }
}
