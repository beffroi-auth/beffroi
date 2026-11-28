<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

/**
 * Who did an act or made a change: the person, an administrator of the tenant, a client acting of itself, a directory or
 * the host (decision 0066).
 */
interface AuthorInterface
{
    /**
     * The member of its document that names the kind of an author.
     */
    public const string MEMBER = 'kind';

    /**
     * @return non-empty-string the name the kind gives itself, which its document and the pages of the person read
     */
    public function kind(): string;

    /**
     * @return non-empty-array<string, string> the kind under MEMBER, first, then what names the author among those of their kind
     */
    public function toDocument(): array;
}
