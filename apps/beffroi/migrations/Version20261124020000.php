<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The retention of a chain deletes its oldest rows through a function that runs as the owner of the tables, so that
 * a role of the database granted no deletion on a chained record still forgets in the order of the chain, and
 * nothing else (decision 0060, beffroi:database:grant).
 */
final class Version20261124020000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The function the retention of a chain forgets its oldest rows through, as the owner of the tables (decision 0060, issue #1331).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');
    }

    /**
     * Not addSql(): the statement is no part of the schema the mappings describe.
     */
    public function postUp(Schema $schema): void
    {
        $this->connection->executeStatement(<<<'SQL'
            CREATE OR REPLACE FUNCTION beffroi_forget_chained_rows(p_tenant UUID, p_chain VARCHAR, p_up_to BIGINT) RETURNS BIGINT
            LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
            DECLARE
                rows_table TEXT;
                forgotten BIGINT;
            BEGIN
                rows_table := CASE p_chain
                    WHEN 'journal' THEN 'beffroi_journal'
                    WHEN 'claim_history' THEN 'beffroi_claim_change'
                    WHEN 'disclosures' THEN 'beffroi_disclosure'
                END;
                IF rows_table IS NULL THEN
                    RAISE EXCEPTION 'No chain is named %', p_chain;
                END IF;
                EXECUTE format('DELETE FROM %I WHERE id IN (SELECT row_id FROM beffroi_chain_link WHERE tenant_id = $1 AND chain = $2 AND position <= $3)', rows_table)
                    USING p_tenant, p_chain, p_up_to;
                GET DIAGNOSTICS forgotten = ROW_COUNT;
                DELETE FROM beffroi_chain_link WHERE tenant_id = p_tenant AND chain = p_chain AND position <= p_up_to;
                RETURN forgotten;
            END
            $$
            SQL);
        $this->connection->executeStatement('REVOKE ALL ON FUNCTION beffroi_forget_chained_rows(UUID, VARCHAR, BIGINT) FROM PUBLIC');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP FUNCTION beffroi_forget_chained_rows(UUID, VARCHAR, BIGINT)');
    }
}
