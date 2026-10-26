<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The replay store of beffroi/saml named for what it holds (issue #784): the assertions of the upstream identity
 * providers are remembered in it beside the logout messages, so the table, its index, its key and its constraint take
 * the name of a remembered message. Renamed, not created again: a row is the window in which a message would be
 * accepted again, and a table emptied by an upgrade would accept every message of that window a second time.
 */
final class Version20261023120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The replay store of beffroi/saml named for the assertions and the logout messages it holds (issue #784).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_saml_logout_message RENAME TO beffroi_saml_remembered_message');
        $this->addSql('ALTER INDEX beffroi_saml_logout_message_pkey RENAME TO beffroi_saml_remembered_message_pkey');
        $this->addSql('ALTER INDEX IDX_AEFC11799033212A RENAME TO IDX_93BC0DFA9033212A');
        $this->addSql('ALTER INDEX beffroi_saml_logout_message_expiry RENAME TO beffroi_saml_remembered_message_expiry');
        $this->addSql('ALTER TABLE beffroi_saml_remembered_message RENAME CONSTRAINT FK_AEFC11799033212A TO FK_93BC0DFA9033212A');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_saml_remembered_message RENAME CONSTRAINT FK_93BC0DFA9033212A TO FK_AEFC11799033212A');
        $this->addSql('ALTER INDEX beffroi_saml_remembered_message_expiry RENAME TO beffroi_saml_logout_message_expiry');
        $this->addSql('ALTER INDEX IDX_93BC0DFA9033212A RENAME TO IDX_AEFC11799033212A');
        $this->addSql('ALTER INDEX beffroi_saml_remembered_message_pkey RENAME TO beffroi_saml_logout_message_pkey');
        $this->addSql('ALTER TABLE beffroi_saml_remembered_message RENAME TO beffroi_saml_logout_message');
    }
}
