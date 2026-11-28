<?php

declare(strict_types=1);

namespace App\Tests\Functional\Journal;

use App\Doctrine\Chain\DoctrineChains;
use App\Tests\Functional\BrowserTestCase;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\ClaimHistoryChain;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\RequestContext;
use function array_map;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Process\Process;
use const PHP_BINARY;
use function dirname;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0060 and 0066, on PostgreSQL: the journal and the history of claims the version before acts named the kind of
 * their author wrote, its administrators by their bare subject in columns of 255 characters, hold together once the
 * migration made those columns text, and read back as they were written.
 */
final class TheJournalWrittenBeforeAuthorsHadKindsTest extends BrowserTestCase
{
    private const string MIGRATION = 'DoctrineMigrations\Version20261128141800';

    protected function setUp(): void
    {
        parent::setUp();
        self::migrate('--down');
        try {
            $alice = self::user();
            foreach (['mallory-subject', null] as $written) {
                $act = new JournalEntry(Uuid::v7(), self::tenant(), 'person.disabled', self::now(), self::context(), $alice->subject, author: new TheHost());
                self::writtenBefore(new JournalChain(), $act->id, $act, 'beffroi_journal', $written);
                $change = new ClaimChange(Uuid::v7(), $alice, 'nickname', 'Ada', 'Augusta', self::now(), self::context(), new ThePerson());
                self::writtenBefore(new ClaimHistoryChain(), $change->id, $change, 'beffroi_claim_change', $written);
            }
            self::manager()->clear();
        } finally {
            self::migrate('--up');
        }
    }

    #[Test]
    public function theJournalWrittenBeforeHoldsTogether(): void
    {
        // When
        $verified = self::verification()->whole(self::tenant(), new JournalChain());

        // Then
        static::assertSame(2, $verified->end->position);
    }

    #[Test]
    public function theHistoryWrittenBeforeHoldsTogether(): void
    {
        // When
        $verified = self::verification()->whole(self::tenant(), new ClaimHistoryChain());

        // Then
        static::assertSame(2, $verified->end->position);
    }

    #[Test]
    public function theActsWrittenBeforeReadBackAsTheyWereWritten(): void
    {
        // When
        $acts = self::manager()->getRepository(JournalEntry::class)->findBy([], ['id' => 'ASC']);

        // Then
        static::assertEquals(
            [new AnAdministrator(new Subject('mallory-subject')), null],
            array_map(static fn (JournalEntry $act): ?AuthorInterface => $act->author, $acts),
        );
    }

    #[Test]
    public function theChangesWrittenBeforeReadBackAsTheyWereWritten(): void
    {
        // When
        $changes = self::manager()->getRepository(ClaimChange::class)->findBy([], ['id' => 'ASC']);

        // Then
        static::assertEquals(
            [new AnAdministrator(new Subject('mallory-subject')), new ThePerson()],
            array_map(static fn (ClaimChange $change): AuthorInterface => $change->author, $changes),
        );
    }

    /**
     * The migration itself, as a deployment plays it, in a process of its own: the migrations of a kernel are frozen
     * once one of them ran.
     */
    private static function migrate(string $direction): void
    {
        $console = new Process(
            [PHP_BINARY, 'bin/console', 'doctrine:migrations:execute', self::MIGRATION, $direction, '--no-interaction'],
            dirname(__DIR__, 3),
            ['APP_ENV' => 'test', 'APP_DEBUG' => '0'],
        );
        $console->run();
        static::assertTrue($console->isSuccessful(), $console->getErrorOutput() . $console->getOutput());
        self::manager()->clear();
    }

    /**
     * A row linked to its chain from the bytes the version before wrote: an administrator by a bare subject, or nobody.
     */
    private static function writtenBefore(ChainInterface $chain, Uuid $id, object $row, string $table, ?string $author): void
    {
        $manager = self::manager();
        self::service('test.beffroi.chains', DoctrineChains::class)->written(self::tenant(), $chain, $id, static function () use ($manager, $row, $table, $id, $author): void {
            $manager->persist($row);
            $manager->flush();
            $manager->getConnection()->update($table, ['author' => $author], ['id' => $id], ['id' => UuidType::NAME]);
        });
    }

    private static function verification(): ChainVerification
    {
        return self::service('test.beffroi.chain_verification', ChainVerification::class);
    }

    private static function manager(): EntityManagerInterface
    {
        return self::service('doctrine.orm.entity_manager', EntityManagerInterface::class);
    }

    private static function context(): RequestContext
    {
        return new RequestContext(self::now(), '203.0.113.7', 'the suite');
    }
}
