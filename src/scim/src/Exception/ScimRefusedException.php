<?php

declare(strict_types=1);

namespace Beffroi\Scim\Exception;

use Beffroi\Scim\Domain\Error\ScimError;
use RuntimeException;

/**
 * A request the module refuses, with the error it answers.
 */
final class ScimRefusedException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly ScimError $error,
    ) {
        parent::__construct($error->detail);
    }
}
