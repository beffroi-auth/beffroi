<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Credential;

use Beffroi\Core\Domain\Precis\OpaqueString;
use Beffroi\Core\Exception\PasswordRefusedException;
use SensitiveParameter;
use function sprintf;

/**
 * NIST SP 800-63B §3.1.1.2, RFC 8265 §4.2
 *
 * The value is the form OpaqueString enforces, which the rules below measure and which is hashed. The upper bound, in
 * bytes, is where Symfony's password hashers stop (CVE-2013-1443). The breach lookup is BreachedPasswordRefusal's, run
 * by every use case that writes a password.
 */
final readonly class PlainPassword
{
    public const int MAXIMUM_BYTES = 4096;

    /**
     * The lowest rung: a higher one would be a length rule in disguise, which NIST SP 800-63B §3.1.1.2
     * asks verifiers not to impose.
     */
    public const int MINIMUM_STRENGTH = PasswordStrength::WEAK;

    public string $value;

    /**
     * @throws PasswordRefusedException
     */
    public function __construct(
        #[SensitiveParameter]
        string $value,
        PasswordLength $length,
    ) {
        $enforced = OpaqueString::enforce($value);
        if (! $length->reachedBy($enforced)) {
            throw new PasswordRefusedException(
                PasswordRefusal::TooShort,
                sprintf('A password is at least %d characters long.', $length->minimum),
            );
        }
        if (! PasswordStrength::of($enforced)->reaches(self::MINIMUM_STRENGTH)) {
            throw new PasswordRefusedException(
                PasswordRefusal::TooWeak,
                'A password this short of length and of alphabet is guessed: make it longer, or several words.',
            );
        }
        $this->value = $enforced;
    }
}
