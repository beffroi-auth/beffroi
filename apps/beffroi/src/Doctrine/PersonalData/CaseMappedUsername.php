<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Beffroi\Core\Domain\Precis\UsernameCaseMapped;
use SensitiveParameter;
use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;

/**
 * RFC 8265 §3.3.4: the enforced form of the username, under the version of Unicode the tenant records with its tags
 * (BlindIndexDerivations). A username the profile refuses, which a row written before it may hold, is indexed as
 * written until 1.0.0: under one version of Unicode, enforcing a form gives that form back, so no enforced form equals it.
 */
final class CaseMappedUsername implements ProjectionInterface
{
    public function project(#[SensitiveParameter] string $value): string
    {
        return UsernameCaseMapped::comparisonForm($value);
    }
}
