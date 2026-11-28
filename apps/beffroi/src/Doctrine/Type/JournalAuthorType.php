<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Author\AuthorInterface;

/**
 * An act written before acts named the kind of their author, and naming none, was the person's or the host's, which its
 * provenance tells apart.
 */
final class JournalAuthorType extends WrittenAuthorType
{
    public const string NAME = 'beffroi_journal_author';

    protected function unwritten(): ?AuthorInterface
    {
        return null;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
