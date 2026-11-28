<?php

declare(strict_types=1);

namespace App\Credential;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ChannelChangeWindowInterface;
use DateTimeImmutable;
use function sprintf;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use function time;

/**
 * Decision 0049: a window of two changes, counted by tenant, by person and by channel, on the store of the limits of the
 * attempts and under the lock every process of a deployment takes. The second change of a window is told at its end, and
 * no third one is queued: a stolen token flipping an address costs two notices a window, whatever the number of writes.
 */
final readonly class RateLimitedChannelChangeWindow implements ChannelChangeWindowInterface
{
    public const string LIMITER = 'beffroi_channel_change_notices';

    public const int LIMIT = 2;

    public const string INTERVAL = '1 hour';

    public function __construct(
        private RateLimiterFactoryInterface $windows,
    ) {
    }

    public function toldAt(User $user, string $claim, DateTimeImmutable $now): ?DateTimeImmutable
    {
        $change = $this->windows->create(sprintf('%s|%s|%s', $user->tenant->id->toRfc4122(), $user->id->toRfc4122(), $claim))->consume();
        if (! $change->isAccepted()) {
            return null;
        }
        if ($change->getRemainingTokens() === (self::LIMIT - 1)) {
            return $now;
        }
        // The limiter keeps the time of the system, not the clock of the provider: what is carried over is the wait.
        return $now->modify(sprintf('+%d seconds', $change->getRetryAfter()->getTimestamp() - time()));
    }
}
