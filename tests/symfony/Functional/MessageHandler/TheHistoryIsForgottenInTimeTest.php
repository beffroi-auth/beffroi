<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Configuration\HistorySection;
use App\Key\FileChainCheckpoints;
use App\Message\ForgetTheChangesPastTheirRetention;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

final class TheHistoryIsForgottenInTimeTest extends DatabaseTestCase
{
    protected function tearDown(): void
    {
        new Filesystem()->remove(self::keyStorage() . '/default/' . FileChainCheckpoints::DIRECTORY);
        parent::tearDown();
    }

    #[Test]
    public function aChangePastTheRetentionIsForgotten(): void
    {
        // Given
        self::aChange(sprintf('-%d days', HistorySection::DEFAULT_RETENTION + 1));
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());

        // When
        self::tick();

        // Then
        static::assertSame(0, self::kept());
    }

    #[Test]
    public function aChangeInsideTheRetentionIsKept(): void
    {
        // Given
        self::aChange(sprintf('-%d days', HistorySection::DEFAULT_RETENTION - 1));

        // When
        self::tick();

        // Then
        static::assertSame(1, self::kept());
    }

    private static function tick(): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch(new ForgetTheChangesPastTheirRetention());
        self::reload();
    }

    private static function kept(): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne('SELECT COUNT(*) FROM beffroi_claim_change');
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function aChange(string $ago): void
    {
        $user = self::user();
        $at = self::service('clock', ClockInterface::class)->now()->modify($ago);
        self::service('test.beffroi.claim_history', ClaimHistoryInterface::class)
            ->record(new ClaimChange(Uuid::v7(), $user, 'nickname', 'Ada', 'Augusta', $at, self::context()));
        self::reload();
    }
}
