<?php

declare(strict_types=1);

namespace App\Message;

use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

final readonly class RaiseTheVersionOfAGroup implements Command
{
    /**
     * @param DateTimeImmutable $at the instant of the change of membership, which the last change of the group takes
     */
    public function __construct(
        public Uuid $group,
        public DateTimeImmutable $at,
    ) {
    }
}
