<?php

declare(strict_types=1);

namespace App\Messenger;

use Symfony\Component\Messenger\Stamp\StampInterface;

/**
 * Decision 0020
 *
 * The stamps of a message that are not routing, written as their headers would be and sealed to the message key of a
 * tenant: a compact JWE, which travels in clear because it gives nothing away without that key.
 */
final readonly class SealedStamps implements StampInterface
{
    public function __construct(
        public string $jwe,
    ) {
    }
}
