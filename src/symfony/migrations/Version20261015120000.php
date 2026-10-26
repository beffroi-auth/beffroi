<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The newest metadata document accepted for each service provider of a tenant (beffroi/saml, issue #729): one table,
 * one row per service provider, unique under its tenant by its entity ID.
 *
 * The document is sealed under the data key of its tenant, in the family of its own table (decisions 0011 and 0018),
 * so its column is the ciphertext and not the XML: an `md:ContactPerson` names people. The table is new, so it holds
 * no row to seal first.
 */
final class Version20261015120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The newest metadata document accepted for each service provider of a tenant, sealed (issue #729).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_saml_service_provider (id UUID NOT NULL, tenant_id UUID NOT NULL, entity_id VARCHAR(1024) NOT NULL, document BYTEA NOT NULL, valid_until TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, accepted_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_897820209033212A ON beffroi_saml_service_provider (tenant_id)');
        $this->addSql('CREATE UNIQUE INDEX beffroi_saml_service_provider_entity ON beffroi_saml_service_provider (tenant_id, entity_id)');
        $this->addSql('ALTER TABLE beffroi_saml_service_provider ADD CONSTRAINT FK_897820209033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_saml_service_provider');
    }
}
