<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The source that created a person and the claims it holds (decision 0002, issue #780): local, or an upstream
 * provider, sealed under the data key of the tenant in the "user" family like the rest of the row (decision 0011),
 * the provider that created a person saying which organisation that person is of.
 *
 * Nullable, and null is a local source: the rows the table holds were all created by a console, a fixture or an
 * import, and that is said without the data key of their tenant, which a migration does not have and which sealing
 * a value would need. A local source holds nothing, so there is nothing to seal for it afterwards either.
 */
final class Version20261022120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The source that created a person and the claims it holds (issue #780).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_user ADD source BYTEA DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_user DROP source');
    }
}
