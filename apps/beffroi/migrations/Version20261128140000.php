<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * A person and a group already there are at their first version, and a group was last changed when it was created
 * (RFC 7643 §3.1). A default on a new column rewrites no row of beffroi_user, none of its sealed columns included, and
 * serves the processes that still write without the column while a deployment replaces them, or after it rolls back.
 * Each lock is waited for five seconds at most, the requests queued behind a lock that waits waiting with it: past
 * them, the migration fails whole, nothing written, and the server that plays it does not start.
 */
final class Version20261128140000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The version of a person and of a group, and the last change of a group (RFC 7644 §3.14, issue #1422).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql("SET LOCAL lock_timeout = '5s'");
        $this->addSql('ALTER TABLE beffroi_user ADD version INT DEFAULT 1 NOT NULL');
        $this->addSql('ALTER TABLE beffroi_group ADD version INT DEFAULT 1 NOT NULL');
        $this->addSql('ALTER TABLE beffroi_group ADD updated_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL');
        $this->addSql('UPDATE beffroi_group SET updated_at = created_at');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_user DROP version');
        $this->addSql('ALTER TABLE beffroi_group DROP version');
        $this->addSql('ALTER TABLE beffroi_group DROP updated_at');
    }
}
