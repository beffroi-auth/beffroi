<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;

final readonly class ClientKind implements AuthorKindInterface
{
    public function kind(): string
    {
        return AClient::KIND;
    }

    public function fromDocument(Document $document): AuthorInterface
    {
        return new AClient(
            $document->nullableString(AClient::CLIENT_ID) ?? throw new InvalidArgumentException('A client that acted is named by the identifier it was registered under.'),
        );
    }
}
