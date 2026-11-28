<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Scim;

use LogicException;
use Symfony\Component\HttpFoundation\Response;

final readonly class FailingController
{
    public const string MESSAGE = 'a value of the request the answer must not carry';

    public function __invoke(): Response
    {
        throw new LogicException(self::MESSAGE);
    }
}
