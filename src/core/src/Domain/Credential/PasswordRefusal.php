<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Credential;

use Beffroi\Core\Domain\Precis\OpaqueStringRefusal;

/**
 * NIST SP 800-63B §3.1.1.2, RFC 8265 §4.1
 */
enum PasswordRefusal: string
{
    case TooShort = 'too_short';

    case TooLong = 'too_long';

    case TooWeak = 'too_weak';

    case Breached = 'breached';

    case NotChecked = 'not_checked';

    /**
     * A code point the FreeformClass refuses, bytes that are no UTF-8, or a form that does not settle (RFC 8264 §4.3, §7).
     */
    case DisallowedCharacter = 'disallowed_character';

    public static function of(OpaqueStringRefusal $refusal): self
    {
        return match ($refusal) {
            OpaqueStringRefusal::Empty => self::TooShort,
            OpaqueStringRefusal::TooLong => self::TooLong,
            OpaqueStringRefusal::Disallowed => self::DisallowedCharacter,
        };
    }
}
