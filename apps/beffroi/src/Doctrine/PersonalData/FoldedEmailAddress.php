<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Beffroi\Core\Domain\Identity\EmailAddress;
use SensitiveParameter;
use function strrpos;
use function substr;
use Symfony\Component\KeyManagement\BlindIndex\Projection\EmailDomain;
use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;
use function trim;

/**
 * Folds the local part too, which RFC 5321 §2.4 leaves to the receiving server: told apart by case or by composition,
 * a second person could hold the mailbox of a first, verified by an upstream provider.
 */
final class FoldedEmailAddress implements ProjectionInterface
{
    public function project(#[SensitiveParameter] string $value): string
    {
        $value = trim($value);
        $at = strrpos($value, '@');
        if ($at === false) {
            return EmailAddress::foldedLocalPart($value);
        }

        return EmailAddress::foldedLocalPart(substr($value, 0, $at)) . '@' . new EmailDomain()->project(substr($value, $at + 1));
    }
}
