<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Error;

/**
 * Section 8, RFC 7644 §3.12 Table 8: an operation the provider does not serve.
 */
final readonly class NotServed
{
    public const int STATUS = 501;

    public const string DETAIL = 'The provider does not serve this operation.';

    public static function error(): ScimError
    {
        return new ScimError(self::STATUS, null, self::DETAIL);
    }
}
