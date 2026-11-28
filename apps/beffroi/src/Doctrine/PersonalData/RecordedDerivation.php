<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use DateTimeImmutable;
use IntlChar;
use function in_array;

/**
 * What the last beffroi:user:reindex of a tenant derived its tags under, how many persons it named, and the tags of the
 * usernames it found held by several persons, reserved so that nobody takes the name they share.
 */
final readonly class RecordedDerivation
{
    /**
     * @param list<string> $reserved
     */
    public function __construct(
        public int $derivation,
        public string $unicodeVersion,
        public int $refused,
        public int $joined,
        public DateTimeImmutable $derivedAt,
        public array $reserved = [],
    ) {
    }

    public function reserves(string $tag): bool
    {
        return in_array($tag, $this->reserved, true);
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
