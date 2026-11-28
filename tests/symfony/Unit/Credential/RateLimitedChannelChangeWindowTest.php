<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\RateLimitedChannelChangeWindow;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * Decision 0049
 */
final class RateLimitedChannelChangeWindowTest extends TestCase
{
    private RateLimitedChannelChangeWindow $window;

    private User $alice;

    protected function setUp(): void
    {
        $this->window = new RateLimitedChannelChangeWindow(new RateLimiterFactory(
            [
                'id' => RateLimitedChannelChangeWindow::LIMITER,
                'policy' => 'fixed_window',
                'limit' => RateLimitedChannelChangeWindow::LIMIT,
                'interval' => RateLimitedChannelChangeWindow::INTERVAL,
            ],
            new InMemoryStorage(),
        ));
        $this->alice = Fixtures::user();
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3
     */
    #[Test]
    public function theFirstChangeOfAChannelIsToldAtOnce(): void
    {
        // When
        $toldAt = $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $toldAt);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theSecondChangeOfAChannelIsToldAtTheEndOfTheWindowTheFirstOpened(): void
    {
        // Given
        $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // When
        $toldAt = $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // Then
        static::assertEqualsWithDelta(3_600, ($toldAt?->getTimestamp() ?? 0) - Fixtures::now()->getTimestamp(), 2);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aThirdChangeInTheWindowIsToldByTheNoticeAtItsEnd(): void
    {
        // Given
        $this->window->toldAt($this->alice, 'email', Fixtures::now());
        $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // When
        $toldAt = $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // Then
        static::assertNull($toldAt);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function anotherChannelOfThePersonOpensAWindowOfItsOwn(): void
    {
        // Given
        $this->window->toldAt($this->alice, 'email', Fixtures::now());
        $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // When
        $toldAt = $this->window->toldAt($this->alice, 'phone_number', Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $toldAt);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function anotherPersonOpensAWindowOfHerOwn(): void
    {
        // Given
        $this->window->toldAt($this->alice, 'email', Fixtures::now());
        $this->window->toldAt($this->alice, 'email', Fixtures::now());

        // When
        $toldAt = $this->window->toldAt(Fixtures::user($this->alice->tenant, 'bob', 'bob-subject'), 'email', Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $toldAt);
    }
}
