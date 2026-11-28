<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Error;

/**
 * P-19: what no rule names, said without a word of what failed.
 */
final readonly class ProviderFailure
{
    public const int STATUS = 500;

    public const string DETAIL = 'The provider failed to serve this request.';

    public static function error(): ScimError
    {
        return new ScimError(self::STATUS, null, self::DETAIL);
    }
}
