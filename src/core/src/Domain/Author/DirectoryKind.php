<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;

final readonly class DirectoryKind implements AuthorKindInterface
{
    public function kind(): string
    {
        return ADirectory::KIND;
    }

    public function fromDocument(Document $document): AuthorInterface
    {
        return new ADirectory(
            $document->nullableString(ADirectory::NAME) ?? throw new InvalidArgumentException('A directory that acted is named by the name the deployment declares it under.'),
        );
    }
}
