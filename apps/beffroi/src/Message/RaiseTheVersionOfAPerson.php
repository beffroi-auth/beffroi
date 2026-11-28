<?php

declare(strict_types=1);

namespace App\Message;

use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

final readonly class RaiseTheVersionOfAPerson implements Command
{
    /**
     * @param DateTimeImmutable $at the instant of the change of membership, which the last change of the person takes
     */
    public function __construct(
        public Uuid $user,
        public DateTimeImmutable $at,
    ) {
    }
}
