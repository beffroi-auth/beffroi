<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ThePerson;

/**
 * A change written before changes named the kind of their author, and naming none, was the person's: nobody else made a
 * change without being named.
 */
final class ClaimChangeAuthorType extends WrittenAuthorType
{
    public const string NAME = 'beffroi_claim_change_author';

    protected function unwritten(): AuthorInterface
    {
        return new ThePerson();
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
