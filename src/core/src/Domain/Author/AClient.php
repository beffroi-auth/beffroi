<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\PlainText;
use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * A client acting of itself, by the identifier it was registered under: it revokes a token (RFC 7009) or deletes its own
 * registration (RFC 7592).
 */
final readonly class AClient implements AuthorInterface
{
    public const string KIND = 'client';

    public const string CLIENT_ID = 'client_id';

    /**
     * @throws InvalidArgumentException when the identifier is empty, not plain text or longer than an author holds
     */
    public function __construct(
        public string $clientId,
    ) {
        if (! self::holds($clientId)) {
            throw new InvalidArgumentException('A client that acts is named by the identifier it was registered under, plain text of at most 255 characters.');
        }
    }

    /**
     * The rule a registration holds its identifier to, so that what the client does names it.
     */
    public static function holds(string $clientId): bool
    {
        return $clientId !== '' && PlainText::holds($clientId, PlainText::MAX_LENGTH);
    }

    public function kind(): string
    {
        return self::KIND;
    }

    public function toDocument(): array
    {
        return [self::MEMBER => self::KIND, self::CLIENT_ID => $this->clientId];
    }
}
