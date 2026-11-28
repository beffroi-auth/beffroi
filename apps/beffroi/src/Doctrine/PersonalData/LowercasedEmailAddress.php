<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use function mb_strtolower;
use SensitiveParameter;
use function strrpos;
use function substr;
use Symfony\Component\KeyManagement\BlindIndex\Projection\EmailDomain;
use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;
use function trim;

/**
 * The fold 0.1 indexed an address under, its local part lowercased without being brought to NFC, which a lookup tries
 * beside the fold of the column until beffroi:user:reindex derived every tag again.
 */
final class LowercasedEmailAddress implements ProjectionInterface
{
    public function project(#[SensitiveParameter] string $value): string
    {
        $value = trim($value);
        $at = strrpos($value, '@');
        if ($at === false) {
            return mb_strtolower($value);
        }

        return mb_strtolower(substr($value, 0, $at)) . '@' . new EmailDomain()->project(substr($value, $at + 1));
    }
}
