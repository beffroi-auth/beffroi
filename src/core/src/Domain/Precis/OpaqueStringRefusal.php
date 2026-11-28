<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 8265 §4.1, §4.2.1
 */
enum OpaqueStringRefusal: string
{
    case Empty = 'empty';

    case TooLong = 'too_long';

    /**
     * A code point the FreeformClass refuses, bytes that are no UTF-8, or a form that does not settle (RFC 8264 §4.3, §7).
     */
    case Disallowed = 'disallowed';
}
