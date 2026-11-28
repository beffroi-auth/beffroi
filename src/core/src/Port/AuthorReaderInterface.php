<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Exception\InvalidArgumentException;

interface AuthorReaderInterface
{
    /**
     * @param array<array-key, mixed> $document what AuthorInterface::toDocument() wrote
     *
     * @throws InvalidArgumentException when the document names no kind that is wired, or not an author of its kind
     */
    public function fromDocument(array $document): AuthorInterface;
}
