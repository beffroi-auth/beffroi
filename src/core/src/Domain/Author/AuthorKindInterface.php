<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * A kind of author, which reads back the document an author of its kind wrote.
 */
interface AuthorKindInterface
{
    /**
     * @return non-empty-string
     */
    public function kind(): string;

    /**
     * @throws InvalidArgumentException when the document does not name an author of this kind
     */
    public function fromDocument(Document $document): AuthorInterface;
}
