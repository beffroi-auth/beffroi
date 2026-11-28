<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Request;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Exception\ScimRefusedException;
use function strlen;

/**
 * Section 7, P-5: the bytes of a body counted before anything reads them, RFC 9110 §15.5.14 past their bound. Whoever
 * hands a body over reads one byte past the bound at most, which is enough to refuse it.
 */
final readonly class BodyLength
{
    public const int BYTES = 524_288;

    public const int STATUS = 413;

    public const string DETAIL = 'The body of the request is longer than the 524 288 bytes the provider reads.';

    /**
     * @throws ScimRefusedException
     */
    public static function assertWithinBound(string $bytes): void
    {
        if (strlen($bytes) > self::BYTES) {
            throw new ScimRefusedException(new ScimError(self::STATUS, null, self::DETAIL));
        }
    }
}
