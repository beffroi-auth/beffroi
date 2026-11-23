<?php

declare(strict_types=1);

namespace App\Doctrine\Role;

use App\Doctrine\Chain\ChainedTableInterface;
use App\Doctrine\Chain\DoctrineChains;
use App\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use function implode;
use function preg_match;
use function sprintf;

/**
 * Decision 0060: the role the processes of a deployment run as reads and writes what they serve, appends to the
 * chained records and their links, and forgets them only through the function the retention calls; the role that
 * plays the migrations owns the tables and is the only one to rewrite them.
 */
final readonly class RuntimeRoleGrants
{
    /**
     * @param iterable<ChainedTableInterface> $tables
     */
    public function __construct(
        private EntityManagers $managers,
        private iterable $tables,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the role is no role name, or is the one that owns the tables
     *
     * @return list<string> the statements played, in their order
     */
    public function grant(string $role): array
    {
        if (preg_match('/^[a-z_][a-z0-9_]{0,62}$/D', $role) !== 1) {
            throw new InvalidArgumentException(sprintf('"%s" is no role this command grants to: lowercase letters, digits and underscores.', $role));
        }
        $connection = $this->managers->forClass(Tenant::class)->getConnection();
        if (! $connection->getDatabasePlatform() instanceof PostgreSQLPlatform) {
            throw new InvalidArgumentException('Roles are granted on PostgreSQL alone.');
        }
        if ($connection->fetchOne('SELECT current_user') === $role) {
            throw new InvalidArgumentException(sprintf('"%s" is the role that owns the tables: the processes run as another one.', $role));
        }
        $chained = [DoctrineChains::LINKS];
        foreach ($this->tables as $table) {
            $chained[] = $table->table();
        }
        $statements = [
            sprintf('GRANT USAGE ON SCHEMA public TO %s', $role),
            sprintf('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s', $role),
            sprintf('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %s', $role),
            sprintf('REVOKE UPDATE, DELETE, TRUNCATE ON %s FROM %s', implode(', ', $chained), $role),
            sprintf('REVOKE DELETE, TRUNCATE ON beffroi_tenant FROM %s', $role),
            sprintf('GRANT EXECUTE ON FUNCTION beffroi_forget_chained_rows(UUID, VARCHAR, BIGINT) TO %s', $role),
        ];
        $connection->transactional(static function () use ($connection, $statements): void {
            foreach ($statements as $statement) {
                $connection->executeStatement($statement);
            }
        });

        return $statements;
    }
}
