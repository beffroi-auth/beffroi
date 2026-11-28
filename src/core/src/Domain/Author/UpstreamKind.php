<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;

final readonly class UpstreamKind implements AuthorKindInterface
{
    public function kind(): string
    {
        return AnUpstreamProvider::KIND;
    }

    public function fromDocument(Document $document): AuthorInterface
    {
        return new AnUpstreamProvider(
            $document->nullableString(AnUpstreamProvider::NAME) ?? throw new InvalidArgumentException('An upstream provider that acted is named by the name the deployment declares it under.'),
        );
    }
}
