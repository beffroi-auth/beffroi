<?php

declare(strict_types=1);

namespace Beffroi\Core\Exception;

use InvalidArgumentException as InvalidArgument;

/**
 * RFC 8265 §3.3.3: a username the UsernameCaseMapped profile does not enforce, whichever door it came through.
 */
final class UsernameRefusedException extends InvalidArgument implements ExceptionInterface
{
}
