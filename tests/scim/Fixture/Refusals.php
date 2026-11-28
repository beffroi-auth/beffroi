<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Fixture;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Exception\ScimRefusedException;
use Closure;
use PHPUnit\Framework\Assert;

/**
 * The error a refused call answers, for a test that reads its status and its keyword.
 */
final class Refusals
{
    /**
     * @param Closure(): mixed $call
     */
    public static function of(Closure $call): ScimError
    {
        try {
            $call();
        } catch (ScimRefusedException $refusal) {
            return $refusal->error;
        }

        Assert::fail('The call was not refused.');
    }
}
