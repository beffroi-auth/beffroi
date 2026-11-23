<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use App\Doctrine\Chain\ClaimHistoryTable;
use App\Doctrine\Chain\DisclosureTable;
use App\Doctrine\Chain\DoctrineChains;
use App\Doctrine\Chain\JournalTable;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function is_string;
use Symfony\Component\Uid\Uuid;

/**
 * The rows the three records already hold are chained in the order of their identifiers, a UUIDv7, so that the first
 * signature of each chain finds every row in it.
 */
final class Version20261124003000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The chains of the journal, of the history of claims and of what clients were given, one per tenant, and their heads (decision 0060, issue #1331).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_chain_head (position BIGINT NOT NULL, hash VARCHAR(64) NOT NULL, chain VARCHAR(32) NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (chain, tenant_id))');
        $this->addSql('CREATE INDEX IDX_A56A8FFA9033212A ON beffroi_chain_head (tenant_id)');
        $this->addSql('CREATE TABLE beffroi_chain_link (position BIGINT NOT NULL, previous VARCHAR(64) NOT NULL, hash VARCHAR(64) NOT NULL, chain VARCHAR(32) NOT NULL, row_id UUID NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (chain, row_id))');
        $this->addSql('CREATE UNIQUE INDEX beffroi_chain_link_position ON beffroi_chain_link (tenant_id, chain, position)');
        $this->addSql('CREATE INDEX IDX_3435E0979033212A ON beffroi_chain_link (tenant_id)');
        $this->addSql('ALTER TABLE beffroi_chain_head ADD CONSTRAINT FK_A56A8FFA9033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE beffroi_chain_link ADD CONSTRAINT FK_3435E0979033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
        $this->addSql('DROP TABLE beffroi_journal_link');
        $this->addSql('DROP TABLE beffroi_journal_head');
    }

    public function postUp(Schema $schema): void
    {
        foreach ($this->connection->fetchFirstColumn('SELECT id FROM beffroi_tenant') as $tenant) {
            if (! is_string($tenant)) {
                continue;
            }
            foreach ([new JournalTable(), new ClaimHistoryTable(), new DisclosureTable()] as $table) {
                DoctrineChains::relinkRows($this->connection, $table, Uuid::fromString($tenant));
            }
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_journal_head (position BIGINT NOT NULL, hash VARCHAR(64) NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (tenant_id))');
        $this->addSql('CREATE TABLE beffroi_journal_link (position BIGINT NOT NULL, previous VARCHAR(64) NOT NULL, hash VARCHAR(64) NOT NULL, act_id UUID NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (act_id))');
        $this->addSql('CREATE UNIQUE INDEX beffroi_journal_link_position ON beffroi_journal_link (tenant_id, position)');
        $this->addSql('CREATE INDEX IDX_353F7B769033212A ON beffroi_journal_link (tenant_id)');
        $this->addSql('ALTER TABLE beffroi_journal_head ADD CONSTRAINT FK_A460141B9033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE beffroi_journal_link ADD CONSTRAINT FK_353F7B76D1A55B28 FOREIGN KEY (act_id) REFERENCES beffroi_journal (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE beffroi_journal_link ADD CONSTRAINT FK_353F7B769033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
        $this->addSql('DROP TABLE beffroi_chain_link');
        $this->addSql('DROP TABLE beffroi_chain_head');
    }
}
