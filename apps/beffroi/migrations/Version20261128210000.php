<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Every password hash written before the provider enforced the OpaqueString profile was computed over the bytes as they
 * were typed (decision 0065): the default of the column says so of each of them, and of a row a process of the version
 * before still inserts while a deployment rolls.
 */
final class Version20261128210000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Whether a password hash was computed over the bytes as typed, true for every hash written before the OpaqueString profile (decision 0065, issue #1442).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_password_credential ADD hashed_as_typed BOOLEAN DEFAULT true NOT NULL');
        $this->addSql('CREATE INDEX beffroi_password_credential_hashed_as_typed ON beffroi_password_credential (hashed_as_typed, tenant_id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP INDEX beffroi_password_credential_hashed_as_typed');
        $this->addSql('ALTER TABLE beffroi_password_credential DROP hashed_as_typed');
    }
}
