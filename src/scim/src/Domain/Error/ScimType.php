<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Error;

/**
 * RFC 7644 §3.12, Table 9
 */
enum ScimType: string
{
    case InvalidSyntax = 'invalidSyntax';
    case InvalidValue = 'invalidValue';
}
