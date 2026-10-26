<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Single Logout started by a service provider (beffroi/saml, issue #734): the logout messages the model accepted,
 * remembered by every worker until their window closes (spec/saml.md S-23), and each service provider's part in a
 * session of the core, one row per session and service provider, deleted with the session (S-26).
 *
 * Nothing in either names a person: a digest of a message and an entity ID of an application, joined to a session by
 * its identifier. Both tables are new, so they hold no row to seal or to fill.
 */
final class Version20261015173400 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The logout messages accepted and the service providers of a session (issue #734).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_saml_logout_message (message_key CHAR(64) NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (message_key))');
        $this->addSql('CREATE INDEX IDX_AEFC11799033212A ON beffroi_saml_logout_message (tenant_id)');
        $this->addSql('CREATE INDEX beffroi_saml_logout_message_expiry ON beffroi_saml_logout_message (expires_at)');
        $this->addSql('ALTER TABLE beffroi_saml_logout_message ADD CONSTRAINT FK_AEFC11799033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');

        $this->addSql('CREATE TABLE beffroi_saml_session_participant (id UUID NOT NULL, service_provider VARCHAR(1024) NOT NULL, signed_in_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, tenant_id UUID NOT NULL, session_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_7859A5959033212A ON beffroi_saml_session_participant (tenant_id)');
        $this->addSql('CREATE INDEX IDX_7859A595613FECDF ON beffroi_saml_session_participant (session_id)');
        $this->addSql('CREATE UNIQUE INDEX beffroi_saml_session_participant_once ON beffroi_saml_session_participant (session_id, service_provider)');
        $this->addSql('ALTER TABLE beffroi_saml_session_participant ADD CONSTRAINT FK_7859A5959033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
        $this->addSql('ALTER TABLE beffroi_saml_session_participant ADD CONSTRAINT FK_7859A595613FECDF FOREIGN KEY (session_id) REFERENCES beffroi_authentication_session (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_saml_session_participant');
        $this->addSql('DROP TABLE beffroi_saml_logout_message');
    }
}
