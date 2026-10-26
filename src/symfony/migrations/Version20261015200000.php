<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Single Logout started by the identity provider (beffroi/saml, issue #735): the chains of logout it plays through the
 * browser, one row per chain under the SHA-256 of its reference, found too by the ID of the request whose answer it
 * waits for, open ten minutes from its last step (spec/saml.md S-32).
 *
 * Nothing in it names a person: a digest, an ID drawn at random, and a document of session identifiers, service
 * providers and where the chain ends, read whole by one object and queried by nobody, so one JSON column. The table
 * is new, so it holds no row to seal or to fill.
 */
final class Version20261015200000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The chains of logout the SAML identity provider plays (issue #735).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_saml_logout_chain (reference CHAR(64) NOT NULL, awaiting_request VARCHAR(128) DEFAULT NULL, progress JSON NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (reference))');
        $this->addSql('CREATE INDEX IDX_6E55941F9033212A ON beffroi_saml_logout_chain (tenant_id)');
        $this->addSql('CREATE INDEX beffroi_saml_logout_chain_expiry ON beffroi_saml_logout_chain (expires_at)');
        $this->addSql('CREATE UNIQUE INDEX beffroi_saml_logout_chain_awaiting ON beffroi_saml_logout_chain (awaiting_request)');
        $this->addSql('ALTER TABLE beffroi_saml_logout_chain ADD CONSTRAINT FK_6E55941F9033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_saml_logout_chain');
    }
}
