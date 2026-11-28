<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

/**
 * An author the person an act concerns is told of by their role alone: neither who they are, nor where they acted from,
 * nor the client they acted through (decision 0038).
 */
interface ToldByItsRoleInterface extends AuthorInterface
{
}
