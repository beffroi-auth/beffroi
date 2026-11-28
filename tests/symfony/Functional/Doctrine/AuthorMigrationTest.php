<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\TheHost;
use function sprintf;
use PHPUnit\Framework\Attributes\DataProvider;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Event\PersonDisabled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\Exception\AbortMigration;
use DoctrineMigrations\Version20261128141800;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0060 and 0066: no row already written is rewritten, so a bare subject that would read as the document of an
 * author is refused, and so is going back once a document is written.
 */
final class AuthorMigrationTest extends DatabaseTestCase
{
    #[Test]
    #[DataProvider('provideRecords')]
    public function aRecordThatNamesAnAdministratorByASubjectBeginningWithABraceIsRefusedWithWhatToDo(string $record): void
    {
        // Given
        self::anAct(new TheHost());
        self::aChange();
        $connection = self::entityManager()->getConnection();
        $connection->executeStatement('UPDATE beffroi_journal SET author = NULL');
        $connection->executeStatement('UPDATE beffroi_claim_change SET author = NULL');
        $connection->executeStatement(sprintf("UPDATE %s SET author = '{mallory}'", $record));

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIs(sprintf(
            'The table %1$s names an administrator by a subject that begins with "{", which would read as the document of an author: rewrite the author of those rows (SELECT id FROM %1$s WHERE author LIKE \'{%%\'), then relink and sign their chain anew with beffroi:chain:sign-anew, and play the migrations again.',
            $record,
        ));

        // When
        self::migration()->preUp(new Schema());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRecords(): iterable
    {
        yield 'the journal' => ['beffroi_journal'];
        yield 'the history of claims' => ['beffroi_claim_change'];
    }

    #[Test]
    public function recordsOfBareSubjectsAndOfNobodyAreNotRefused(): void
    {
        // Given
        $user = self::user();
        self::anAct(new TheHost(), $user);
        self::anAct(new TheHost(), $user);
        self::aChange();
        $connection = self::entityManager()->getConnection();
        $connection->executeStatement("UPDATE beffroi_journal SET author = 'mallory-subject'");
        $connection->executeStatement('UPDATE beffroi_journal SET author = NULL WHERE id = (SELECT MIN(id) FROM beffroi_journal)');
        $connection->executeStatement('UPDATE beffroi_claim_change SET author = NULL');
        $migration = self::migration();

        // When
        $migration->preUp(new Schema());

        // Then
        static::assertSame([], $migration->getSql());
    }

    #[Test]
    #[DataProvider('provideRecords')]
    public function goingBackOnceAnAuthorIsNamedByTheirKindIsRefused(string $record): void
    {
        // Given
        self::anAct(new ADirectory('Entra ID'));
        self::aChange();
        self::entityManager()
            ->getConnection()
            ->executeStatement(sprintf('UPDATE %s SET author = NULL', $record === 'beffroi_journal' ? 'beffroi_claim_change' : 'beffroi_journal'));

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIs(sprintf(
            'The table %s holds authors named by their kind, which the previous version would read as the subjects of administrators: from the first of them the migration goes one way, and only a backup of the database taken before it goes back.',
            $record,
        ));

        // When
        self::migration()->preDown(new Schema());
    }

    private static function anAct(TheHost|ADirectory $author, ?User $user = null): void
    {
        $user ??= self::user('carol', 'carol-subject');
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(
                new JournalEntry(Uuid::v7(), $user->tenant, PersonDisabled::NAME, self::now(), self::context(), $user->subject, author: $author),
            );
        self::reload();
    }

    private static function aChange(): void
    {
        self::service('test.beffroi.claim_history', ClaimHistoryInterface::class)
            ->record(
                new ClaimChange(Uuid::v7(), self::user('bob', 'bob-subject'), 'nickname', 'Ada', 'Augusta', self::now(), self::context(), new ThePerson()),
            );
        self::reload();
    }

    private static function migration(): Version20261128141800
    {
        return new Version20261128141800(self::entityManager()->getConnection(), new NullLogger());
    }
}
