<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Beffroi\Core\Domain\Precis\UsernameCaseMapped;
use Beffroi\Core\Exception\UsernameRefusedException;
use SensitiveParameter;
use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;

/**
 * RFC 8265 §3.3.4: the enforced form of the username. A value the profile refuses, which only a row written before it
 * holds, is indexed as written: enforcing a form gives that form back, so no enforced form equals a refused value.
 */
final class CaseMappedUsername implements ProjectionInterface
{
    public function project(#[SensitiveParameter] string $value): string
    {
        try {
            return UsernameCaseMapped::enforce($value);
        } catch (UsernameRefusedException) {
            return $value;
        }
    }
}
