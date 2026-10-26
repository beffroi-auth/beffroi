<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The browser a chain of logout is bound to (beffroi/saml, issue #735, spec/saml.md S-32): beside the SHA-256 of its
 * reference, the SHA-256 of the secret the browser that began the chain holds in a cookie of the provider, without
 * which no step of the chain is played, so that neither the server of a service provider answering for the browser nor
 * a reference read in an access log plays it.
 *
 * The rows the table already holds are bound to no browser, and a chain lives ten minutes from its last step, so they
 * are deleted and the column is mandatory from the start rather than nullable for ever: the sessions of those chains
 * have ended already (S-29), and the service providers they had left to tell are not told, as when a chain closes.
 */
final class Version20261020153500 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The browser a chain of logout of the SAML identity provider is bound to (issue #735).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DELETE FROM beffroi_saml_logout_chain');
        $this->addSql('ALTER TABLE beffroi_saml_logout_chain ADD secret CHAR(64) NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_saml_logout_chain DROP secret');
    }
}
