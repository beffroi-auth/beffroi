<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Request;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Exception\ScimRefusedException;
use function array_shift;
use function explode;
use function in_array;
use function preg_match;
use function strtolower;
use function trim;

/**
 * Section 6.1 step 4, RFC 7644 §3.8, RFC 9110 §8.3.1, §5.6.6: the types a body may be sent as, its type and subtype
 * read without case, and "charset", the one parameter there is, once at most, its name and its value read without
 * case and its value UTF-8, quoted or not. A body sent without a type is read as the one RFC 7644 §3.8 defaults to.
 */
final readonly class MediaType
{
    public const int STATUS = 415;

    public const string DETAIL = 'The body of the request is not sent as application/scim+json or application/json in UTF-8.';

    private const array TYPES = ['application/scim+json', 'application/json'];

    private const string WHITESPACE = " \t";

    private const string CHARSET = '/^charset=(?:utf-8|"utf-8")$/iD';

    /**
     * @param string|null $contentType the Content-Type the request carries, null when it carries none
     *
     * @throws ScimRefusedException
     */
    public static function assertReadable(?string $contentType): void
    {
        if ($contentType === null) {
            return;
        }
        $parameters = explode(';', $contentType);
        $type = strtolower(trim(array_shift($parameters), self::WHITESPACE));
        if (! in_array($type, self::TYPES, true)) {
            throw self::refused();
        }
        $charsets = 0;
        foreach ($parameters as $parameter) {
            $parameter = trim($parameter, self::WHITESPACE);
            // RFC 9110 §5.6.6 lets a parameter be empty between two semicolons.
            if ($parameter === '') {
                continue;
            }
            if (preg_match(self::CHARSET, $parameter) !== 1 || ++$charsets > 1) {
                throw self::refused();
            }
        }
    }

    private static function refused(): ScimRefusedException
    {
        return new ScimRefusedException(new ScimError(self::STATUS, null, self::DETAIL));
    }
}
