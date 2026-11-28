<?php

declare(strict_types=1);

namespace App\Load;

use App\Configuration\BoundedNumber;
use DateInterval;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use function max;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\RateLimiter\Storage\StorageInterface;
use function time;

/**
 * Counted on a sliding window, never a fixed one: a budget that forgets at a fixed hour has a hole at that hour.
 */
final readonly class LoadBudget
{
    public const string ORIGIN = 'origin';

    public const string CLIENT = 'client';

    private RateLimiterFactoryInterface $limiter;

    /**
     * Checked here as well as in the tree: a value from the environment is a number only here.
     *
     * @param non-empty-string $name
     *
     * @throws InvalidConfigurationException when the limit is below one
     */
    public function __construct(
        public string $name,
        int $limit,
        DateInterval $interval,
        StorageInterface $storage,
    ) {
        BoundedNumber::assertAtLeast($limit, 1, 'load.' . $name . '.limit', 'requests');
        $this->limiter = new RateLimiterFactory([
            'id' => 'beffroi_' . $name . '_load',
            'policy' => 'sliding_window',
            'limit' => $limit,
            'interval' => $interval,
        ], $storage);
    }

    /**
     * The delay is read on the clock of the limiter, the machine's, as RateLimitAttributeListener does, and is never
     * zero, which would invite a retry refused again.
     *
     * @param string $key never one a caller can choose for somebody else
     *
     * @throws LoadBudgetSpentException
     */
    public function consume(string $key, ?string $client = null): void
    {
        $limit = $this->limiter->create($key)->consume();
        if ($limit->isAccepted()) {
            return;
        }

        throw new LoadBudgetSpentException($this->name, max(1, $limit->getRetryAfter()->getTimestamp() - time()), $client);
    }
}
