<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\TheHost;
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
    public function aRecordThatNamesAnAdministratorByASubjectBeginningWithABraceIsRefused(): void
    {
        // Given
        self::anAct(new TheHost());
        self::entityManager()->getConnection()->executeStatement("UPDATE beffroi_journal SET author = '{mallory}'");

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIs('The table beffroi_journal names an administrator by a subject that begins with "{", which would read as the document of an author.');

        // When
        self::migration()->preUp(new Schema());
    }

    #[Test]
    public function aRecordOfBareSubjectsAndOfNobodyIsMigrated(): void
    {
        // Given
        $user = self::user();
        self::anAct(new TheHost(), $user);
        self::anAct(new TheHost(), $user);
        self::entityManager()->getConnection()->executeStatement("UPDATE beffroi_journal SET author = 'mallory-subject'");
        self::entityManager()->getConnection()->executeStatement('UPDATE beffroi_journal SET author = NULL WHERE id = (SELECT MIN(id) FROM beffroi_journal)');
        $migration = self::migration();

        // When
        $migration->preUp(new Schema());

        // Then
        static::assertSame([], $migration->getSql());
    }

    #[Test]
    public function goingBackOnceAnAuthorIsNamedByTheirKindIsRefused(): void
    {
        // Given
        self::anAct(new ADirectory('Entra ID'));

        // Then
        $this->expectException(AbortMigration::class);
        $this->expectExceptionMessageIs('The table beffroi_journal holds authors named by their kind, which the previous version would read as administrators.');

        // When
        self::migration()->preDown(new Schema());
    }

    private static function anAct(TheHost|ADirectory $author, ?User $user = null): void
    {
        $user ??= self::user();
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(
                new JournalEntry(Uuid::v7(), $user->tenant, PersonDisabled::NAME, self::now(), self::context(), $user->subject, author: $author),
            );
        self::reload();
    }

    private static function migration(): Version20261128141800
    {
        return new Version20261128141800(self::entityManager()->getConnection(), new NullLogger());
    }
}
