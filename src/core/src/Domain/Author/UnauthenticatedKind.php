<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\Document;

final readonly class UnauthenticatedKind implements AuthorKindInterface
{
    public function kind(): string
    {
        return AnUnauthenticatedCaller::KIND;
    }

    public function fromDocument(Document $document): AuthorInterface
    {
        return new AnUnauthenticatedCaller();
    }
}
