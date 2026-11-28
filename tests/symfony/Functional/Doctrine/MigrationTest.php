<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_filter;
use function basename;
use function glob;
use function array_map;
use function array_values;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\Exception\AbortMigration;
use Doctrine\Migrations\Query\Query;
use Doctrine\ORM\Tools\SchemaTool;
use DoctrineMigrations\Version20260915171732;
use DoctrineMigrations\Version20260917180000;
use DoctrineMigrations\Version20260919150000;
use DoctrineMigrations\Version20260920120000;
use DoctrineMigrations\Version20260920180000;
use DoctrineMigrations\Version20260922120000;
use DoctrineMigrations\Version20260922180000;
use DoctrineMigrations\Version20260923090000;
use DoctrineMigrations\Version20260923170000;
use DoctrineMigrations\Version20260923190000;
use DoctrineMigrations\Version20260925120000;
use DoctrineMigrations\Version20260925180000;
use DoctrineMigrations\Version20260926090000;
use DoctrineMigrations\Version20260926210000;
use DoctrineMigrations\Version20260926220000;
use DoctrineMigrations\Version20260927090000;
use DoctrineMigrations\Version20260927100000;
use DoctrineMigrations\Version20260927140000;
use DoctrineMigrations\Version20260927180000;
use DoctrineMigrations\Version20260928120000;
use DoctrineMigrations\Version20260929120000;
use DoctrineMigrations\Version20260929180000;
use DoctrineMigrations\Version20260930120000;
use DoctrineMigrations\Version20260930180000;
use DoctrineMigrations\Version20261001120000;
use DoctrineMigrations\Version20261001180000;
use DoctrineMigrations\Version20261002120000;
use DoctrineMigrations\Version20261002180000;
use DoctrineMigrations\Version20261003120000;
use DoctrineMigrations\Version20261003180000;
use DoctrineMigrations\Version20261004120000;
use DoctrineMigrations\Version20261005120000;
use DoctrineMigrations\Version20261006120000;
use DoctrineMigrations\Version20261007120000;
use DoctrineMigrations\Version20261008120000;
use DoctrineMigrations\Version20261009120000;
use DoctrineMigrations\Version20261009130000;
use DoctrineMigrations\Version20261010120000;
use DoctrineMigrations\Version20261010180000;
use DoctrineMigrations\Version20261011120000;
use DoctrineMigrations\Version20261011150000;
use DoctrineMigrations\Version20261011160000;
use DoctrineMigrations\Version20261011170000;
use DoctrineMigrations\Version20261015120000;
use DoctrineMigrations\Version20261015173400;
use DoctrineMigrations\Version20261015200000;
use DoctrineMigrations\Version20261020153500;
use DoctrineMigrations\Version20261022120000;
use DoctrineMigrations\Version20261022150000;
use DoctrineMigrations\Version20261022180000;
use DoctrineMigrations\Version20261023120000;
use DoctrineMigrations\Version20261030120000;
use DoctrineMigrations\Version20261030150000;
use DoctrineMigrations\Version20261104100000;
use DoctrineMigrations\Version20261104140000;
use DoctrineMigrations\Version20261106200000;
use DoctrineMigrations\Version20261116120000;
use DoctrineMigrations\Version20261117120000;
use DoctrineMigrations\Version20261117180000;
use DoctrineMigrations\Version20261117220000;
use DoctrineMigrations\Version20261122120000;
use DoctrineMigrations\Version20261122200000;
use DoctrineMigrations\Version20261122210500;
use DoctrineMigrations\Version20261123110900;
use DoctrineMigrations\Version20261123200600;
use DoctrineMigrations\Version20261124090000;
use DoctrineMigrations\Version20261124100000;
use DoctrineMigrations\Version20261124100500;
use DoctrineMigrations\Version20261124110000;
use DoctrineMigrations\Version20261128200000;
use function implode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function preg_quote;
use function preg_replace;
use Psr\Log\NullLogger;
use function sort;
use function str_contains;
use function str_split;
use function str_starts_with;
use function substr;
use function trim;

/**
 * Architecture §5.3
 */
final class MigrationTest extends DatabaseTestCase
{
    /**
     * @var list<class-string<AbstractMigration>> in the order they are applied
     */
    private const array MIGRATIONS = [
        Version20260915171732::class,
        Version20260917180000::class,
        Version20260919150000::class,
        Version20260920120000::class,
        Version20260920180000::class,
        Version20260922120000::class,
        Version20260922180000::class,
        Version20260923090000::class,
        Version20260923170000::class,
        Version20260923190000::class,
        Version20260925120000::class,
        Version20260925180000::class,
        Version20260926090000::class,
        Version20260926210000::class,
        Version20260926220000::class,
        Version20260927090000::class,
        Version20260927100000::class,
        Version20260927140000::class,
        Version20260927180000::class,
        Version20260928120000::class,
        Version20260929120000::class,
        Version20260929180000::class,
        Version20260930120000::class,
        Version20260930180000::class,
        Version20261001120000::class,
        Version20261001180000::class,
        Version20261002120000::class,
        Version20261002180000::class,
        Version20261003120000::class,
        Version20261003180000::class,
        Version20261004120000::class,
        Version20261005120000::class,
        Version20261006120000::class,
        Version20261007120000::class,
        Version20261008120000::class,
        Version20261009120000::class,
        Version20261009130000::class,
        Version20261010120000::class,
        Version20261010180000::class,
        Version20261011120000::class,
        Version20261011150000::class,
        Version20261011160000::class,
        Version20261011170000::class,
        Version20261015120000::class,
        Version20261015173400::class,
        Version20261015200000::class,
        Version20261020153500::class,
        Version20261022120000::class,
        Version20261022150000::class,
        Version20261022180000::class,
        Version20261023120000::class,
        Version20261030120000::class,
        Version20261030150000::class,
        Version20261104100000::class,
        Version20261104140000::class,
        Version20261106200000::class,
        Version20261116120000::class,
        Version20261117120000::class,
        Version20261117180000::class,
        Version20261117220000::class,
        Version20261122120000::class,
        Version20261122200000::class,
        Version20261122210500::class,
        Version20261123110900::class,
        Version20261123200600::class,
        Version20261124090000::class,
        Version20261124100000::class,
        Version20261124100500::class,
        Version20261124110000::class,
        Version20261128200000::class,
    ];

    #[Test]
    public function theMigrationsCreateWhatTheMappingsDescribeOnPostgreSql(): void
    {
        // Given
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ], new Configuration()->setTypeProvider(self::typesOfTheConnection()));
        $platform = $connection->getDatabasePlatform();
        static::assertInstanceOf(PostgreSQLPlatform::class, $platform);
        $entityManager = self::entityManager();
        $expected = array_values(array_filter(
            new SchemaTool($entityManager)
                ->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata())
                ->toSql($platform),
            static fn (string $statement): bool => ! str_contains($statement, 'app_user'),
        ));

        // When
        $actual = self::statements($connection);

        // Then
        $expected = array_map(self::withColumnsSorted(...), $expected);
        $actual = array_map(self::withColumnsSorted(...), $actual);
        sort($expected);
        sort($actual);
        static::assertSame($expected, $actual);
    }

    #[Test]
    public function theDirectoryOfTheMigrationsHoldsVersionFilesAndNothingElse(): void
    {
        // Given
        $directory = \dirname(__DIR__, 4) . '/apps/beffroi/migrations';

        // When
        $files = glob($directory . '/*.php');

        // Then
        static::assertIsArray($files);
        static::assertNotSame([], $files);
        foreach ($files as $file) {
            static::assertStringStartsWith(
                'Version',
                basename($file),
                sprintf('%s is in the directory of the migrations, which no package autoloads: move it under src/.', basename($file)),
            );
        }
    }

    #[Test]
    public function theMigrationsCreateTheFortyTwoTablesOfTheProvider(): void
    {
        // Given
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]);

        // When
        $statements = self::statements($connection);

        // Then
        static::assertCount(42, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    /**
     * RFC 8628 §3.4
     */
    #[Test]
    public function theLastMigrationAddsTheDeviceTableAndRenamesTheFamilyOrigin(): void
    {
        // Given
        $migration = new Version20260926090000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
        static::assertContains('ALTER TABLE beffroi_refresh_token RENAME COLUMN family_authorization_code_hash TO family_granting_record_hash', $statements);
    }

    #[Test]
    public function theSecondMigrationAddsTheAccessTokenTableAlone(): void
    {
        // Given
        $migration = new Version20260917180000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        foreach ($statements as $statement) {
            static::assertStringContainsString('beffroi_access_token', $statement);
        }
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    #[Test]
    public function theThirdMigrationAddsThePasskeyTableAlone(): void
    {
        // Given
        $migration = new Version20260919150000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        foreach ($statements as $statement) {
            static::assertStringContainsString('beffroi_passkey_credential', $statement);
        }
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    #[Test]
    public function theFourthMigrationAddsThePolicyColumnOfTheTenantAlone(): void
    {
        // Given
        $migration = new Version20260920120000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        static::assertCount(1, $statements);
        static::assertStringStartsWith(
            'ALTER TABLE beffroi_tenant ADD authentication_context_policy JSON DEFAULT \'{"classes":[{"name":"phrh"',
            $statements[0],
        );
        static::assertStringEndsWith('NOT NULL', $statements[0]);
    }

    #[Test]
    public function theFifthMigrationAddsTheTotpTableAlone(): void
    {
        // Given
        $migration = new Version20260920180000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        foreach ($statements as $statement) {
            static::assertStringContainsString('beffroi_totp_credential', $statement);
        }
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    #[Test]
    public function theSeventhMigrationAddsThePushedAuthorizationRequestTableAlone(): void
    {
        // Given
        $migration = new Version20260922180000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        foreach ($statements as $statement) {
            static::assertStringContainsString('beffroi_pushed_authorization_request', $statement);
        }
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    /**
     * @param class-string<AbstractMigration> $migration
     */
    #[Test]
    #[DataProvider('provideMigrations')]
    public function everyMigrationRefusesAnotherPlatform(string $migration): void
    {
        // Given
        $migration = new $migration(self::entityManager()->getConnection(), new NullLogger());

        // Then
        $this->expectException(AbortMigration::class);

        // When
        $migration->up(new Schema());
    }

    /**
     * @return iterable<string, array{class-string<AbstractMigration>}>
     */
    public static function provideMigrations(): iterable
    {
        foreach (self::MIGRATIONS as $migration) {
            yield $migration => [$migration];
        }
    }

    private static function withColumnsSorted(string $statement): string
    {
        if (preg_match('/^(CREATE TABLE \S+ \()(.*)(\))$/', $statement, $matches) !== 1) {
            return $statement;
        }
        $definitions = self::definitions($matches[2]);
        sort($definitions);

        return $matches[1] . implode(', ', $definitions) . $matches[3];
    }

    private static function withoutColumn(string $statement, string $column): string
    {
        if (preg_match('/^(CREATE TABLE \S+ \()(.*)(\))$/', $statement, $matches) !== 1) {
            return $statement;
        }
        $definitions = array_values(array_filter(
            self::definitions($matches[2]),
            static fn (string $definition): bool => ! str_starts_with($definition, $column . ' '),
        ));

        return $matches[1] . implode(', ', $definitions) . $matches[3];
    }

    /**
     * @return list<string>
     */
    private static function definitions(string $body): array
    {
        $definitions = [];
        $depth = 0;
        $quoted = false;
        $current = '';
        foreach (str_split($body) as $character) {
            if ($character === "'") {
                $quoted = ! $quoted;
            } elseif (! $quoted && $character === '(') {
                ++$depth;
            } elseif (! $quoted && $character === ')') {
                --$depth;
            }
            if ($character === ',' && $depth === 0 && ! $quoted) {
                $definitions[] = trim($current);
                $current = '';

                continue;
            }
            $current .= $character;
        }
        $definitions[] = trim($current);

        return $definitions;
    }

    /**
     * The statements of every migration, what a later one changes folded into the CREATE TABLE it changes.
     *
     * @return list<string>
     */
    private static function statements(Connection $connection): array
    {
        $statements = [];
        foreach (self::MIGRATIONS as $class) {
            $migration = new $class($connection, new NullLogger());
            $migration->up(new Schema());
            foreach ($migration->getSql() as $query) {
                $statement = $query->getStatement();
                if (preg_match('/^ALTER TABLE (\S+) ADD (?!CONSTRAINT )(.+)$/', $statement, $matches) === 1) {
                    $statements = array_map(
                        static fn (string $earlier): string => str_starts_with($earlier, 'CREATE TABLE ' . $matches[1] . ' (')
                            ? substr($earlier, 0, -1) . ', ' . $matches[2] . ')'
                            : $earlier,
                        $statements,
                    );

                    continue;
                }
                if (preg_match('/^ALTER TABLE (\S+) RENAME COLUMN (\S+) TO (\S+)$/', $statement, $matches) === 1) {
                    $statements = array_map(
                        static fn (string $earlier): string => str_contains($earlier, $matches[1])
                            ? self::renamed($earlier, $matches[2], $matches[3])
                            : $earlier,
                        $statements,
                    );

                    continue;
                }
                if (
                    preg_match('/^ALTER TABLE (\S+) RENAME TO (\S+)$/', $statement, $matches) === 1
                    || preg_match('/^ALTER TABLE \S+ RENAME CONSTRAINT (\S+) TO (\S+)$/', $statement, $matches) === 1
                ) {
                    $statements = array_map(
                        static fn (string $earlier): string => self::renamed($earlier, $matches[1], $matches[2]),
                        $statements,
                    );

                    continue;
                }
                if (preg_match('/^ALTER INDEX (\S+) RENAME TO (\S+)$/', $statement, $matches) === 1) {
                    $statements = array_map(
                        static fn (string $earlier): string => self::renamed($earlier, $matches[1], $matches[2]),
                        $statements,
                    );

                    continue;
                }
                if (preg_match('/^ALTER TABLE (\S+) DROP (?!CONSTRAINT )(\S+)$/', $statement, $matches) === 1) {
                    $statements = array_map(
                        static fn (string $earlier): string => str_starts_with($earlier, 'CREATE TABLE ' . $matches[1] . ' (')
                            ? self::withoutColumn($earlier, $matches[2])
                            : $earlier,
                        $statements,
                    );

                    continue;
                }
                if (preg_match('/^DROP INDEX (\S+)$/', $statement, $matches) === 1) {
                    $statements = array_values(array_filter(
                        $statements,
                        static fn (string $earlier): bool => preg_match('/^CREATE (UNIQUE )?INDEX ' . preg_quote($matches[1], '/') . ' /', $earlier) !== 1,
                    ));

                    continue;
                }
                if (preg_match('/^DROP TABLE (\S+)$/', $statement, $matches) === 1) {
                    $statements = array_values(array_filter(
                        $statements,
                        static fn (string $earlier): bool => (
                            preg_match('/^(CREATE TABLE |ALTER TABLE |CREATE (UNIQUE )?INDEX \S+ ON )' . preg_quote($matches[1], '/') . '[ (]/', $earlier) !== 1
                        ),
                    ));

                    continue;
                }
                if (str_starts_with($statement, 'DELETE FROM ')) {
                    continue;
                }
                $statements[] = $statement;
            }
        }

        return $statements;
    }

    private static function renamed(string $statement, string $from, string $to): string
    {
        return (string) preg_replace('/\b' . preg_quote($from, '/') . '\b/', $to, $statement);
    }
}
