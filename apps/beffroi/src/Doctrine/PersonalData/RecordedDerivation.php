<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use DateTimeImmutable;
use IntlChar;

/**
 * What the last beffroi:user:reindex of a tenant derived its tags under, and how many persons it named.
 */
final readonly class RecordedDerivation
{
    public function __construct(
        public int $derivation,
        public string $unicodeVersion,
        public int $refused,
        public int $joined,
        public DateTimeImmutable $derivedAt,
    ) {
    }

    /**
     * The tags were derived under the projections of this build, and the profile of a username read the version of
     * Unicode this build reads: an enforced form may differ under another.
     */
    public function isCurrent(): bool
    {
        return $this->derivation === BlindIndexedColumns::DERIVATION && $this->unicodeVersion === IntlChar::UNICODE_VERSION;
    }
}
