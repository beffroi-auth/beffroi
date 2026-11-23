<?php

declare(strict_types=1);

namespace App\Doctrine\Chain;

use App\Doctrine\EntityManagers;
use function array_map;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Chain\ChainLink;
use Beffroi\Core\Domain\Chain\Link;
use Beffroi\Core\Domain\Chain\LinkedRow;
use Beffroi\Core\Domain\Chain\RelinkedChain;
use Beffroi\Core\Domain\Chain\WrittenRow;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\ChainOfRowsInterface;
use Beffroi\Core\Port\RelinkableChainsInterface;
use Closure;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Types;
use function implode;
use function is_numeric;
use function is_resource;
use function is_scalar;
use function is_string;
use function sprintf;
use function stream_get_contents;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Through DBAL and never the manager: a link is computed from the row as the database holds it, its sealed columns as
 * the bytes of their seals, which the manager never hands back.
 */
final readonly class DoctrineChains implements ChainOfRowsInterface, RelinkableChainsInterface
{
    public const string HEADS = 'beffroi_chain_head';

    public const string LINKS = 'beffroi_chain_link';

    /**
     * @param iterable<ChainedTableInterface> $tables
     */
    public function __construct(
        private EntityManagers $managers,
        private iterable $tables,
    ) {
    }

    /**
     * The row, its link and the head it moves are one transaction, under the lock of the head: two writers at once take
     * two positions that follow each other.
     *
     * @param Closure(): void $write writes the row, through the manager or not
     */
    public function written(Tenant $tenant, ChainInterface $chain, Uuid $row, Closure $write): void
    {
        $this->connection()->transactional(function () use ($tenant, $chain, $row, $write): void {
            $head = $this->lockedHead($tenant, $chain);
            $write();
            $this->append($tenant, $chain, $row, $head);
        });
    }

    /**
     * An upsert takes the lock of the row and answers the head as the last writer left it, the same statement on
     * PostgreSQL and SQLite.
     */
    public function lockedHead(Tenant $tenant, ChainInterface $chain): Link
    {
        $row = $this->connection()->fetchAssociative(
            sprintf(
                'INSERT INTO %1$s (tenant_id, chain, position, hash) VALUES (:tenant, :chain, 0, :hash) ON CONFLICT (tenant_id, chain) DO UPDATE SET position = %1$s.position RETURNING position, hash',
                self::HEADS,
            ),
            ['tenant' => $tenant->id, 'chain' => $chain->name(), 'hash' => Link::beforeTheFirst()->hash],
            ['tenant' => UuidType::NAME],
        );
        if ($row === false) {
            throw new RuntimeException(sprintf('The head of the chain "%s" of the tenant "%s" cannot be locked.', $chain->name(), $tenant->slug));
        }

        return self::link($row['position'] ?? null, $row['hash'] ?? null);
    }

    public function head(Tenant $tenant, ChainInterface $chain): Link
    {
        $row = $this->connection()->fetchAssociative(
            sprintf('SELECT position, hash FROM %s WHERE tenant_id = :tenant AND chain = :chain', self::HEADS),
            ['tenant' => $tenant->id, 'chain' => $chain->name()],
            ['tenant' => UuidType::NAME],
        );

        return $row === false ? Link::beforeTheFirst() : self::link($row['position'] ?? null, $row['hash'] ?? null);
    }

    public function linkedAfter(Tenant $tenant, ChainInterface $chain, int $position, int $howMany): array
    {
        $table = $this->table($chain);
        $connection = $this->connection();
        $rows = $connection
            ->createQueryBuilder()
            ->select(self::columns($table), 'l.position', 'l.previous', 'l.hash')
            ->from(self::LINKS, 'l')
            ->innerJoin('l', $table->table(), 'r', 'r.id = l.row_id')
            ->where('l.tenant_id = :tenant')
            ->andWhere('l.chain = :chain')
            ->andWhere('l.position > :position')
            ->orderBy('l.position', 'ASC')
            ->setMaxResults($howMany)
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->setParameter('chain', $chain->name())
            ->setParameter('position', $position)
            ->fetchAllAssociative();
        $linked = [];
        foreach ($rows as $row) {
            $at = $row['position'] ?? null;
            $previous = $row['previous'] ?? null;
            $hash = $row['hash'] ?? null;
            if (! is_numeric($at) || ! is_string($previous) || ! is_string($hash)) {
                throw new RuntimeException(sprintf('A link of the chain "%s" does not read as a position and two hashes.', $chain->name()));
            }
            $linked[] = new LinkedRow(self::writtenRow($connection, $table, $row), (int) $at, $previous, $hash);
        }

        return $linked;
    }

    public function rowsOutsideTheChain(Tenant $tenant, ChainInterface $chain, int $keptAfter): int
    {
        $count = $this->connection()->fetchOne(
            sprintf(
                'SELECT COUNT(*) FROM %s r LEFT JOIN %s l ON l.chain = :chain AND l.row_id = r.id WHERE r.tenant_id = :tenant AND (l.row_id IS NULL OR l.position <= :keptAfter)',
                $this->table($chain)->table(),
                self::LINKS,
            ),
            ['tenant' => $tenant->id, 'chain' => $chain->name(), 'keptAfter' => $keptAfter],
            ['tenant' => UuidType::NAME],
        );

        return is_numeric($count) ? (int) $count : 0;
    }

    public function forgetUpTo(Tenant $tenant, ChainInterface $chain, int $position): int
    {
        $connection = $this->connection();
        $parameters = ['tenant' => $tenant->id, 'chain' => $chain->name(), 'position' => $position];
        $types = ['tenant' => UuidType::NAME];
        $forgotten = $connection->executeStatement(
            sprintf(
                'DELETE FROM %s WHERE id IN (SELECT row_id FROM %s WHERE tenant_id = :tenant AND chain = :chain AND position <= :position)',
                $this->table($chain)->table(),
                self::LINKS,
            ),
            $parameters,
            $types,
        );
        $connection->executeStatement(
            sprintf('DELETE FROM %s WHERE tenant_id = :tenant AND chain = :chain AND position <= :position', self::LINKS),
            $parameters,
            $types,
        );

        return (int) $forgotten;
    }

    public function relink(Tenant $tenant, ChainInterface $chain): RelinkedChain
    {
        return self::relinkRows($this->connection(), $this->table($chain), $tenant->id);
    }

    /**
     * What relink() does, for a migration that has the connection and no container.
     */
    public static function relinkRows(Connection $connection, ChainedTableInterface $table, Uuid $tenant): RelinkedChain
    {
        $rows = $connection->fetchAllAssociative(
            sprintf(
                'SELECT %s, l.position, l.previous FROM %s r LEFT JOIN %s l ON l.chain = :chain AND l.row_id = r.id WHERE r.tenant_id = :tenant ORDER BY CASE WHEN l.position IS NULL THEN 1 ELSE 0 END, l.position, r.id',
                self::columns($table),
                $table->table(),
                self::LINKS,
            ),
            ['tenant' => $tenant, 'chain' => $table->chain()],
            ['tenant' => UuidType::NAME],
        );
        $start = self::startOf($rows[0] ?? null);
        $connection->executeStatement(
            sprintf('DELETE FROM %s WHERE tenant_id = :tenant AND chain = :chain', self::LINKS),
            ['tenant' => $tenant, 'chain' => $table->chain()],
            ['tenant' => UuidType::NAME],
        );
        $head = $start;
        foreach ($rows as $row) {
            $link = $head->then(self::writtenRow($connection, $table, $row));
            self::insertLink($connection, $table->chain(), self::identifier($connection, $row['id'] ?? null, $table), $tenant, $head, $link);
            $head = $link;
        }
        $connection->executeStatement(
            sprintf('DELETE FROM %s WHERE tenant_id = :tenant AND chain = :chain', self::HEADS),
            ['tenant' => $tenant, 'chain' => $table->chain()],
            ['tenant' => UuidType::NAME],
        );
        $connection->insert(
            self::HEADS,
            ['tenant_id' => $tenant, 'chain' => $table->chain(), 'position' => $head->position, 'hash' => $head->hash],
            ['tenant_id' => UuidType::NAME, 'position' => Types::BIGINT],
        );

        return new RelinkedChain($start, $head);
    }

    /**
     * @throws LogicException
     */
    public function table(ChainInterface $chain): ChainedTableInterface
    {
        foreach ($this->tables as $table) {
            if ($table->chain() === $chain->name()) {
                return $table;
            }
        }

        throw new LogicException(sprintf('No table of the application holds the chain "%s".', $chain->name()));
    }

    private function append(Tenant $tenant, ChainInterface $chain, Uuid $row, Link $head): void
    {
        $table = $this->table($chain);
        $connection = $this->connection();
        $written = $connection->fetchAssociative(
            sprintf('SELECT %s FROM %s r WHERE r.id = :id', self::columns($table), $table->table()),
            ['id' => $row],
            ['id' => UuidType::NAME],
        );
        if ($written === false) {
            throw new RuntimeException(sprintf('A row of the chain "%s" cannot be linked before it is written.', $chain->name()));
        }
        $link = $head->then(self::writtenRow($connection, $table, $written));
        self::insertLink($connection, $chain->name(), $row, $tenant->id, $head, $link);
        $connection->update(
            self::HEADS,
            ['position' => $link->position, 'hash' => $link->hash],
            ['tenant_id' => $tenant->id, 'chain' => $chain->name()],
            ['position' => Types::BIGINT, 'tenant_id' => UuidType::NAME],
        );
    }

    private static function insertLink(Connection $connection, string $chain, Uuid $row, Uuid $tenant, Link $previous, Link $link): void
    {
        $connection->insert(
            self::LINKS,
            [
                'chain' => $chain,
                'row_id' => $row,
                'tenant_id' => $tenant,
                'position' => $link->position,
                'previous' => $previous->hash,
                'hash' => $link->hash,
            ],
            ['tenant_id' => UuidType::NAME, 'position' => Types::BIGINT, 'row_id' => UuidType::NAME],
        );
    }

    /**
     * The link the first row names before it, or the start of a chain when it names none that reads as one.
     *
     * @param array<string, mixed>|null $first
     */
    private static function startOf(?array $first): Link
    {
        $position = $first['position'] ?? null;
        $previous = $first['previous'] ?? null;
        if (! is_numeric($position) || ! is_string($previous)) {
            return Link::beforeTheFirst();
        }
        try {
            return new Link((int) $position - 1, $previous);
        } catch (InvalidArgumentException) {
            return Link::beforeTheFirst();
        }
    }

    private static function identifier(Connection $connection, mixed $raw, ChainedTableInterface $table): Uuid
    {
        $id = $connection->convertToPHPValue($raw, UuidType::NAME);
        if (! $id instanceof Uuid) {
            throw new RuntimeException(sprintf('A row of the chain "%s" has no identifier.', $table->chain()));
        }

        return $id;
    }

    private static function columns(ChainedTableInterface $table): string
    {
        return implode(', ', array_map(
            static fn (string $column): string => 'r.' . $column,
            ['id', 'tenant_id', $table->momentColumn(), ...$table->chainedColumns()],
        ));
    }

    /**
     * Each column as the bytes the database answers, a sealed one included: the same database reads them back alike.
     *
     * @param array<string, mixed> $row
     *
     * @throws RuntimeException
     */
    private static function writtenRow(Connection $connection, ChainedTableInterface $table, array $row): WrittenRow
    {
        $id = $connection->convertToPHPValue($row['id'] ?? null, UuidType::NAME);
        $tenant = $connection->convertToPHPValue($row['tenant_id'] ?? null, UuidType::NAME);
        $moment = $connection->convertToPHPValue($row[$table->momentColumn()] ?? null, Types::DATETIME_IMMUTABLE);
        if (! $id instanceof Uuid || ! $tenant instanceof Uuid || ! $moment instanceof DateTimeImmutable) {
            throw new RuntimeException(sprintf('A row of the chain "%s" does not read as a row of it.', $table->chain()));
        }
        $columns = [];
        foreach ($table->chainedColumns() as $column) {
            $columns[] = self::bytes($row[$column] ?? null, $table);
        }

        return new WrittenRow($id->toRfc4122(), $tenant->toRfc4122(), $moment, $columns);
    }

    private static function bytes(mixed $value, ChainedTableInterface $table): ?string
    {
        if ($value === null) {
            return null;
        }
        if (is_resource($value)) {
            $value = stream_get_contents($value);
        }
        if (! is_scalar($value) || $value === false) {
            throw new RuntimeException(sprintf('A row of the chain "%s" holds a column that does not read as bytes.', $table->chain()));
        }

        return (string) $value;
    }

    private function connection(): Connection
    {
        return $this->managers->forClass(ChainLink::class)->getConnection();
    }

    private static function link(mixed $position, mixed $hash): Link
    {
        if (! is_numeric($position) || ! is_string($hash)) {
            throw new RuntimeException('A link of a chain does not read as a position and a hash.');
        }

        return new Link((int) $position, $hash);
    }
}
