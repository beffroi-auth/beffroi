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
     * @throws InvalidArgumentException when the identifier is empty or not plain text
     */
    public function __construct(
        public string $clientId,
    ) {
        if ($clientId === '' || ! PlainText::holds($clientId, PlainText::MAX_LENGTH)) {
            throw new InvalidArgumentException('A client that acts is named by the identifier it was registered under.');
        }
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
