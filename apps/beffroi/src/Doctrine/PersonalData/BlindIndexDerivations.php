<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\Tenant\Tenant;
use Closure;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\ForeignKeyConstraint;
use Doctrine\DBAL\Schema\PrimaryKeyConstraint;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;
use IntlChar;
use function is_numeric;
use function is_string;
use Psr\Clock\ClockInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * A row per tenant: what beffroi:user:reindex last derived the tags of its persons under. A tenant created by this
 * build has no person, and is recorded at its creation.
 */
final readonly class BlindIndexDerivations implements ClassifiedFieldsInterface
{
    public const string TABLE = 'beffroi_blind_index_derivation';

    public function __construct(
        private Connection $connection,
        private ClockInterface $clock,
    ) {
    }

    public function isCurrent(Tenant $tenant): bool
    {
        return $this->recorded($tenant)?->isCurrent() === true;
    }

    public function recorded(Tenant $tenant): ?RecordedDerivation
    {
        $row = $this->connection
            ->createQueryBuilder()
            ->select('derivation', 'unicode_version', 'refused', 'joined', 'derived_at')
            ->from(self::TABLE)
            ->where('tenant_id = :tenant')
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->fetchAssociative();
        if ($row === false) {
            return null;
        }

        return new RecordedDerivation(
            self::integer($row['derivation']),
            is_string($row['unicode_version']) ? $row['unicode_version'] : '',
            self::integer($row['refused']),
            self::integer($row['joined']),
            new DateTimeImmutable(is_string($row['derived_at']) ? $row['derived_at'] : '@0'),
        );
    }

    /**
     * @param int $refused the persons whose username the profile refuses
     * @param int $joined the persons whose usernames it compares as the username of another
     */
    public function record(Tenant $tenant, int $refused, int $joined): void
    {
        $this->connection->transactional(function (Connection $connection) use ($tenant, $refused, $joined): void {
            $connection->delete(
                self::TABLE,
                [
                    'tenant_id' => $tenant->id,
                ],
                [
                    'tenant_id' => UuidType::NAME,
                ],
            );
            $connection->insert(
                self::TABLE,
                [
                    'tenant_id' => $tenant->id,
                    'derivation' => BlindIndexedColumns::DERIVATION,
                    'unicode_version' => IntlChar::UNICODE_VERSION,
                    'refused' => $refused,
                    'joined' => $joined,
                    'derived_at' => $this->clock->now(),
                ],
                [
                    'tenant_id' => UuidType::NAME,
                    'derivation' => Types::INTEGER,
                    'unicode_version' => Types::STRING,
                    'refused' => Types::INTEGER,
                    'joined' => Types::INTEGER,
                    'derived_at' => Types::DATETIME_IMMUTABLE,
                ],
            );
        });
    }

    /**
     * @param Closure(Closure(string): mixed): bool $isSameDatabase
     */
    public function configureSchema(Schema $schema, Closure $isSameDatabase): Schema
    {
        if ($schema->hasTable(self::TABLE) || ! $isSameDatabase($this->connection->executeStatement(...))) {
            return $schema;
        }

        return $schema->edit()->addTable(self::table())->create();
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'tenant_id' => new NoPersonalDatum(Reason::THE_TENANT),
            'derivation' => new NoPersonalDatum('the version of the projections the tags of the tenant were derived under'),
            'unicode_version' => new NoPersonalDatum('the version of Unicode the profile of a username read when they were'),
            'refused' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'joined' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'derived_at' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }

    private static function table(): Table
    {
        return Table::editor()
            ->setUnquotedName(self::TABLE)
            ->addColumn(Column::editor()->setUnquotedName('tenant_id')->setTypeName(UuidType::NAME)->create())
            ->addColumn(Column::editor()->setUnquotedName('derivation')->setTypeName(Types::INTEGER)->create())
            ->addColumn(Column::editor()->setUnquotedName('unicode_version')->setTypeName(Types::STRING)->setLength(16)->create())
            ->addColumn(Column::editor()->setUnquotedName('refused')->setTypeName(Types::INTEGER)->create())
            ->addColumn(Column::editor()->setUnquotedName('joined')->setTypeName(Types::INTEGER)->create())
            ->addColumn(Column::editor()->setUnquotedName('derived_at')->setTypeName(Types::DATETIME_IMMUTABLE)->create())
            ->addPrimaryKeyConstraint(PrimaryKeyConstraint::editor()->setUnquotedColumnNames('tenant_id')->create())
            ->addForeignKeyConstraint(
                ForeignKeyConstraint::editor()
                    ->setUnquotedName(self::TABLE . '_tenant')
                    ->setUnquotedReferencingColumnNames('tenant_id')
                    ->setUnquotedReferencedTableName('beffroi_tenant')
                    ->setUnquotedReferencedColumnNames('id')
                    ->create(),
            )
            ->create();
    }

    private static function integer(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }
}
