<?php

declare(strict_types=1);

namespace Beffroi\Core\Exception;

use Beffroi\Core\Domain\Precis\OpaqueStringRefusal;
use InvalidArgumentException as InvalidArgument;

/**
 * RFC 8265 §4.2.2: a string the OpaqueString profile does not enforce, which is no password.
 */
final class OpaqueStringRefusedException extends InvalidArgument implements ExceptionInterface
{
    public function __construct(
        public readonly OpaqueStringRefusal $refusal,
        string $message,
    ) {
        parent::__construct($message);
    }
}
