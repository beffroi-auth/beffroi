<?php

declare(strict_types=1);

namespace Beffroi\Scim\Exception;

use Throwable;

/**
 * Its message names the rule and never a value (P-19), so that it can be shown and logged as it is.
 */
interface ExceptionInterface extends Throwable
{
}
