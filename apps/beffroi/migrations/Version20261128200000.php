<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261128200000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'That the tokens the end of a session stopped were announced, so that a revocation of the session run again announces nothing (issue #767).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_announced_session_end (session_id UUID NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (session_id))');
        $this->addSql('CREATE INDEX IDX_5C684C2C9033212A ON beffroi_announced_session_end (tenant_id)');
        $this->addSql('ALTER TABLE beffroi_announced_session_end ADD CONSTRAINT FK_5C684C2C613FECDF FOREIGN KEY (session_id) REFERENCES beffroi_authentication_session (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE beffroi_announced_session_end ADD CONSTRAINT FK_5C684C2C9033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_announced_session_end');
    }
}
