<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * No row is written here: a tag is a keyed digest, and the key of the tags of a tenant is in the custody of its KMS,
 * which a migration does not open. beffroi:user:reindex derives the tags and writes the row.
 */
final class Version20261128200000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'What the blind indexes of the persons of a tenant were last derived under, so that a username is compared by its enforced form once they all are (RFC 8265 §3.3.4, decision 0065, issue #1423).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_blind_index_derivation (tenant_id UUID NOT NULL, derivation INT NOT NULL, unicode_version VARCHAR(16) NOT NULL, refused INT NOT NULL, joined INT NOT NULL, derived_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, PRIMARY KEY (tenant_id))');
        $this->addSql('ALTER TABLE beffroi_blind_index_derivation ADD CONSTRAINT beffroi_blind_index_derivation_tenant FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_blind_index_derivation');
    }
}
