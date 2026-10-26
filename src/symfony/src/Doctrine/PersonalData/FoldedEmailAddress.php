<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use function mb_strtolower;
use SensitiveParameter;
use function strrpos;
use function substr;
use Symfony\Component\KeyManagement\BlindIndex\Projection\EmailDomain;
use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;
use function trim;

/**
 * An address folded whole, its local part as well as its domain (issue #781): `Bob@acme.example` and
 * `bob@acme.example` share a tag.
 *
 * RFC 5321 §2.4 leaves the case of a local part to the receiving server, and every server a person of a
 * tenant reads their mail on ignores it. An index that told the two apart would let a second person hold
 * `bob@acme.example` beside the `Bob@acme.example` of somebody else, and an upstream provider that names the
 * second would have this provider create them with a verified address that is the mailbox of the first.
 * So this provider counts one mailbox where the component, which follows the letter of the RFC, counts
 * two, and the component says that is a projection of one's own to write (`Email`).
 *
 * The domain is folded as the component folds it (`EmailDomain`), and the local part in lowercase, as
 * `EmailAddress::isTheSameMailboxAs()` folds it for the adapters in memory.
 */
final class FoldedEmailAddress implements ProjectionInterface
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
