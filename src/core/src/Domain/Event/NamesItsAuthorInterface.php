<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Author\AuthorInterface;

/**
 * An act names who did it (decision 0066): the person, an administrator of the tenant through the administration API
 * (decision 0038), a client acting of itself, a directory, an upstream provider, an unauthenticated caller or the host.
 * The journal writes the author beside the person when there is one.
 */
interface NamesItsAuthorInterface
{
    public function author(): AuthorInterface;
}
