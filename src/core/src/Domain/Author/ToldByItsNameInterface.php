<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

/**
 * An author the person an act concerns is told of by the name the deployment declares it under, in place of where the
 * act came from (decision 0066).
 */
interface ToldByItsNameInterface extends AuthorInterface
{
    public function name(): string;
}
