<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function is_numeric;
use function sprintf;

/**
 * The author of an act and of a change becomes the document it writes, longer than a subject. No row already written is
 * rewritten: the journal and the history of claims are chains whose head the provider signed (decision 0060), so a row
 * keeps the bare subject of the administrator it named, or NULL, and the types read it back as written. A bare subject
 * that begins with a brace would read as a document: such a record is refused, and so is going back once a document is
 * written, which the previous version would read as the subject of an administrator.
 */
final class Version20261128141800 extends AbstractMigration
{
    private const array RECORDS = ['beffroi_journal', 'beffroi_claim_change'];

    public function getDescription(): string
    {
        return 'The author of an act and of a change named by its kind: the person, an administrator, a client, a directory or the host (decision 0066, issue #1418).';
    }

    public function preUp(Schema $schema): void
    {
        foreach (self::RECORDS as $record) {
            $this->abortIf(
                $this->authorsBeginningWithABrace($record) > 0,
                sprintf(
                    'The table %1$s names an administrator by a subject that begins with "{", which would read as the document of an author: rewrite the author of those rows (SELECT id FROM %1$s WHERE author LIKE \'{%%\'), then relink and sign their chain anew with beffroi:chain:sign-anew, and play the migrations again.',
                    $record,
                ),
            );
        }
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_journal ALTER author TYPE TEXT');
        $this->addSql('ALTER TABLE beffroi_claim_change ALTER author TYPE TEXT');
    }

    public function preDown(Schema $schema): void
    {
        foreach (self::RECORDS as $record) {
            $this->abortIf(
                $this->authorsBeginningWithABrace($record) > 0,
                sprintf(
                    'The table %s holds authors named by their kind, which the previous version would read as the subjects of administrators: from the first of them the migration goes one way, and only a backup of the database taken before it goes back.',
                    $record,
                ),
            );
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_journal ALTER author TYPE VARCHAR(255)');
        $this->addSql('ALTER TABLE beffroi_claim_change ALTER author TYPE VARCHAR(255)');
    }

    private function authorsBeginningWithABrace(string $record): int
    {
        $count = $this->connection->fetchOne(sprintf("SELECT COUNT(*) FROM %s WHERE author LIKE '{%%'", $record));

        return is_numeric($count) ? (int) $count : 0;
    }
}
