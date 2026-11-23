<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Configuration\JournalSection;
use App\Key\FileChainCheckpoints;
use App\Message\ForgetTheActsPastTheirRetention;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Doctrine\DBAL\Connection;
use Psr\Clock\ClockInterface;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

final class TheJournalIsForgottenInTimeTest extends DatabaseTestCase
{
    protected function tearDown(): void
    {
        new Filesystem()->remove(self::keyStorage() . '/default/' . FileChainCheckpoints::DIRECTORY);
        parent::tearDown();
    }

    #[Test]
    public function anActPastTheRetentionIsForgotten(): void
    {
        // Given
        self::anAct(sprintf('-%d days', JournalSection::DEFAULT_RETENTION + 1));
        self::aKeyToSignTheCutWith();

        // When
        self::tick();

        // Then
        static::assertSame(0, self::kept());
    }

    #[Test]
    public function anActInsideTheRetentionIsKept(): void
    {
        // Given
        self::anAct(sprintf('-%d days', JournalSection::DEFAULT_RETENTION - 1));

        // When
        self::tick();

        // Then
        static::assertSame(1, self::kept());
    }

    #[Test]
    public function whatAClientWasGivenPastTheRetentionIsForgottenWithTheActs(): void
    {
        // Given
        self::whatWasGiven(sprintf('-%d days', JournalSection::DEFAULT_RETENTION + 1));
        self::aKeyToSignTheCutWith();

        // When
        self::tick();

        // Then
        static::assertSame(0, self::keptOfWhatWasGiven());
    }

    #[Test]
    public function whatAClientWasGivenInsideTheRetentionIsKept(): void
    {
        // Given
        self::whatWasGiven(sprintf('-%d days', JournalSection::DEFAULT_RETENTION - 1));

        // When
        self::tick();

        // Then
        static::assertSame(1, self::keptOfWhatWasGiven());
    }

    private static function counted(string $sql): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne($sql);
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function tick(): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch(new ForgetTheActsPastTheirRetention());
        self::reload();
    }

    private static function kept(): int
    {
        return self::counted(sprintf("SELECT COUNT(*) FROM beffroi_journal WHERE act = '%s'", UserAuthenticated::NAME));
    }

    /**
     * Decision 0060: its activation is an act of the journal, written now.
     */
    private static function aKeyToSignTheCutWith(): void
    {
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    private static function keptOfWhatWasGiven(): int
    {
        return self::counted('SELECT COUNT(*) FROM beffroi_disclosure');
    }

    private static function whatWasGiven(string $ago): void
    {
        $user = self::user('alice');
        self::service('test.beffroi.disclosures', DisclosuresInterface::class)
            ->record(new Disclosure(
                Uuid::v7(),
                self::tenant(),
                $user->subject,
                'oidc-demo',
                TokensIssued::NAME,
                self::service('clock', ClockInterface::class)->now()->modify($ago),
                new Scopes([Scope::openid()]),
                null,
                null,
                'jwt',
            ));
    }

    private static function anAct(string $ago): void
    {
        $user = self::user('alice');
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(new JournalEntry(
                Uuid::v7(),
                self::tenant(),
                UserAuthenticated::NAME,
                self::service('clock', ClockInterface::class)->now()->modify($ago),
                self::context(),
                $user->subject,
            ));
    }
}
