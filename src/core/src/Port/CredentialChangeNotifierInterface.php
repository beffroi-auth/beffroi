<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Credential\CredentialChange;
use DateTimeImmutable;

/**
 * NIST SP 800-63B-4 §4.6
 */
interface CredentialChangeNotifierInterface
{
    /**
     * @param DateTimeImmutable|null $at when it is told, at once when null or past
     */
    public function tell(CredentialChange $change, ?DateTimeImmutable $at = null): void;
}
