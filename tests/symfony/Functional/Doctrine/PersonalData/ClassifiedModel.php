<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use function array_key_exists;
use function array_keys;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Doctrine\PersonalData\DataKeyColumns;
use App\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use function count;
use Doctrine\ORM\EntityManagerInterface;
use function is_a;
use function ksort;
use function sort;
use function sprintf;

final readonly class ClassifiedModel
{
    /**
     * @param array<string, array<string, FieldClassificationInterface>> $columns table, then column
     * @param array<string, string> $unclassified the field behind every column no line names, by "table.column"
     * @param list<string> $linesWithNoColumn the lines no column carries, as "Class::$field"
     */
    public function __construct(
        private array $columns,
        private array $unclassified = [],
        private array $linesWithNoColumn = [],
    ) {
    }

    public static function of(EntityManagerInterface $entityManager): self
    {
        $columns = [];
        $unclassified = [];
        $linesWithNoColumn = [];
        foreach ($entityManager->getMetadataFactory()->getAllMetadata() as $metadata) {
            $class = $metadata->getName();
            if (is_a($class, ClassifiedFieldsInterface::class, true)) {
                foreach (array_keys($class::classifiedFields()) as $field) {
                    if (! array_key_exists($field, $metadata->fieldMappings) && ! array_key_exists($field, $metadata->associationMappings)) {
                        $linesWithNoColumn[] = self::name($class, $field);
                    }
                }
            }
            if ($metadata->isMappedSuperclass || $metadata->isEmbeddedClass) {
                continue;
            }
            $table = $metadata->getTableName();
            foreach ($metadata->fieldMappings as $field => $mapping) {
                self::read(
                    $mapping->originalClass ?? $class,
                    $mapping->originalField ?? $field,
                    $table,
                    $metadata->getColumnName($field),
                    $columns,
                    $unclassified,
                );
            }
            foreach (array_keys($metadata->associationMappings) as $field) {
                if (! $metadata->isAssociationWithSingleJoinColumn($field)) {
                    continue;
                }
                self::read($class, $field, $table, $metadata->getSingleAssociationJoinColumnName($field), $columns, $unclassified);
            }
        }
        foreach (DataKeyColumns::classifiedFields() as $column => $line) {
            $columns[TenantDataKeyStores::TABLE][$column] = $line;
        }
        foreach (BlindIndexDerivations::classifiedFields() as $column => $line) {
            $columns[BlindIndexDerivations::TABLE][$column] = $line;
        }

        return new self($columns, $unclassified, $linesWithNoColumn);
    }

    /**
     * @return array<string, array<string, FieldClassificationInterface>> table, then column
     */
    public function columns(): array
    {
        return $this->columns;
    }

    /**
     * @return array<string, FieldClassificationInterface> by column
     */
    public function linesOf(string $table): array
    {
        $lines = $this->columns[$table] ?? [];
        ksort($lines);

        return $lines;
    }

    public function fieldBehind(string $table, string $column): ?string
    {
        return $this->unclassified[sprintf('%s.%s', $table, $column)] ?? null;
    }

    /**
     * @return list<string> as "Class::$field"
     */
    public function linesWithNoColumn(): array
    {
        return $this->linesWithNoColumn;
    }

    /**
     * @return list<string> in alphabetical order
     */
    public function tables(): array
    {
        $tables = array_keys($this->columns);
        sort($tables);

        return $tables;
    }

    public function columnCount(): int
    {
        $total = 0;
        foreach ($this->columns as $columns) {
            $total += count($columns);
        }

        return $total;
    }

    /**
     * @param class-string $class
     * @param array<string, array<string, FieldClassificationInterface>> $columns
     * @param array<string, string> $unclassified
     */
    private static function read(string $class, string $field, string $table, string $column, array &$columns, array &$unclassified): void
    {
        $line = is_a($class, ClassifiedFieldsInterface::class, true) ? $class::classifiedFields()[$field] ?? null : null;
        if ($line === null) {
            $unclassified[sprintf('%s.%s', $table, $column)] = self::name($class, $field);

            return;
        }
        $columns[$table][$column] = $line;
    }

    private static function name(string $class, string $field): string
    {
        return sprintf('%s::$%s', $class, $field);
    }
}
