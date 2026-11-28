<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * A person and a group already there are at their first version, and a group was last changed when it was created
 * (RFC 7643 §3.1). A default on a new column rewrites no row of beffroi_user, none of its sealed columns included. The
 * processes that still write without the columns while a deployment replaces them, or after it rolls back, write a
 * group at its first version, the trigger giving its last change the creation. Each lock is waited for five seconds at
 * most, the requests queued behind a lock that waits waiting with it: past them, the migration fails whole, nothing
 * written, and the server that plays it does not start.
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
        $this->addSql('ALTER TABLE beffroi_group ADD updated_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('UPDATE beffroi_group SET updated_at = created_at');
        $this->addSql('ALTER TABLE beffroi_group ALTER updated_at SET NOT NULL');
    }

    /**
     * Not addSql(): a trigger is no part of the schema the mappings describe. A default cannot name another column, and
     * the mapping of a datetime takes no expression for one.
     */
    public function postUp(Schema $schema): void
    {
        $this->connection->executeStatement(<<<'SQL'
            CREATE OR REPLACE FUNCTION beffroi_group_last_changed_when_created() RETURNS TRIGGER
            LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.updated_at IS NULL THEN
                    NEW.updated_at := NEW.created_at;
                END IF;
                RETURN NEW;
            END
            $$
            SQL);
        $this->connection->executeStatement('CREATE TRIGGER beffroi_group_last_changed_when_created BEFORE INSERT ON beffroi_group FOR EACH ROW EXECUTE FUNCTION beffroi_group_last_changed_when_created()');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TRIGGER IF EXISTS beffroi_group_last_changed_when_created ON beffroi_group');
        $this->addSql('DROP FUNCTION IF EXISTS beffroi_group_last_changed_when_created()');
        $this->addSql('ALTER TABLE beffroi_user DROP version');
        $this->addSql('ALTER TABLE beffroi_group DROP version');
        $this->addSql('ALTER TABLE beffroi_group DROP updated_at');
    }
}
