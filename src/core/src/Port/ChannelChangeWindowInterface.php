<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Identity\User;
use DateTimeImmutable;

/**
 * Decision 0049: the first change of a channel of a person opens a window and is told at once; the first change of
 * that channel after it in the window is told at its end, and the others with that one. A bound, not a setting.
 */
interface ChannelChangeWindowInterface
{
    /**
     * @param string $claim the claim of the channel, OIDC Core §5.1
     *
     * @return DateTimeImmutable|null when the change is told: $now for the change that opens a window, its end for the
     *                                first change after it, null for any other, which that notice tells
     */
    public function toldAt(User $user, string $claim, DateTimeImmutable $now): ?DateTimeImmutable;
}
