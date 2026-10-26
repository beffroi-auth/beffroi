<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use function array_filter;
use function basename;
use function glob;
use function array_map;
use function array_values;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\Exception\AbortMigration;
use Doctrine\Migrations\Query\Query;
use Doctrine\ORM\Tools\SchemaTool;
use Beffroi\Bundle\Migrations\Version20260915171732;
use Beffroi\Bundle\Migrations\Version20260917180000;
use Beffroi\Bundle\Migrations\Version20260919150000;
use Beffroi\Bundle\Migrations\Version20260920120000;
use Beffroi\Bundle\Migrations\Version20260920180000;
use Beffroi\Bundle\Migrations\Version20260922120000;
use Beffroi\Bundle\Migrations\Version20260922180000;
use Beffroi\Bundle\Migrations\Version20260923090000;
use Beffroi\Bundle\Migrations\Version20260923170000;
use Beffroi\Bundle\Migrations\Version20260923190000;
use Beffroi\Bundle\Migrations\Version20260925120000;
use Beffroi\Bundle\Migrations\Version20260925180000;
use Beffroi\Bundle\Migrations\Version20260926090000;
use Beffroi\Bundle\Migrations\Version20260926210000;
use Beffroi\Bundle\Migrations\Version20260926220000;
use Beffroi\Bundle\Migrations\Version20260927090000;
use Beffroi\Bundle\Migrations\Version20260927100000;
use Beffroi\Bundle\Migrations\Version20260927140000;
use Beffroi\Bundle\Migrations\Version20260927180000;
use Beffroi\Bundle\Migrations\Version20260928120000;
use Beffroi\Bundle\Migrations\Version20260929120000;
use Beffroi\Bundle\Migrations\Version20260929180000;
use Beffroi\Bundle\Migrations\Version20260930120000;
use Beffroi\Bundle\Migrations\Version20260930180000;
use Beffroi\Bundle\Migrations\Version20261001120000;
use Beffroi\Bundle\Migrations\Version20261001180000;
use Beffroi\Bundle\Migrations\Version20261002120000;
use Beffroi\Bundle\Migrations\Version20261002180000;
use Beffroi\Bundle\Migrations\Version20261003120000;
use Beffroi\Bundle\Migrations\Version20261003180000;
use Beffroi\Bundle\Migrations\Version20261004120000;
use Beffroi\Bundle\Migrations\Version20261005120000;
use Beffroi\Bundle\Migrations\Version20261006120000;
use Beffroi\Bundle\Migrations\Version20261007120000;
use Beffroi\Bundle\Migrations\Version20261008120000;
use Beffroi\Bundle\Migrations\Version20261009120000;
use Beffroi\Bundle\Migrations\Version20261009130000;
use Beffroi\Bundle\Migrations\Version20261010120000;
use Beffroi\Bundle\Migrations\Version20261010180000;
use Beffroi\Bundle\Migrations\Version20261011120000;
use Beffroi\Bundle\Migrations\Version20261011150000;
use Beffroi\Bundle\Migrations\Version20261011160000;
use Beffroi\Bundle\Migrations\Version20261011170000;
use Beffroi\Bundle\Migrations\Version20261015120000;
use Beffroi\Bundle\Migrations\Version20261015173400;
use Beffroi\Bundle\Migrations\Version20261015200000;
use Beffroi\Bundle\Migrations\Version20261020153500;
use Beffroi\Bundle\Migrations\Version20261022120000;
use Beffroi\Bundle\Migrations\Version20261022150000;
use Beffroi\Bundle\Migrations\Version20261022180000;
use Beffroi\Bundle\Migrations\Version20261023120000;
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
 * Architecture §5.3: the migrations the bundle ships create on PostgreSQL exactly what the mappings
 * describe, no more, no less. The platform is built from a declared server version, so that no
 * PostgreSQL is needed to check it; the application ran them against a real one.
 */
final class MigrationTest extends DatabaseTestCase
{
    /**
     * The migrations, in the order they are applied.
     *
     * @return list<class-string<AbstractMigration>>
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
    ];

    #[Test]
    public function theMigrationsCreateWhatTheMappingsDescribeOnPostgreSql(): void
    {
        // Given
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]);
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

    /**
     * The directory of the migrations holds version files and nothing else, because it is in the `autoload`
     * of no package: the bundle declares it to Doctrine Migrations, which loads the version files it finds
     * there, and only the `autoload-dev` of the monorepo maps the namespace. So a class placed there
     * resolves in this suite and not in a deployment, which is what this refuses. Anything several
     * migrations share lives under `src/`, where `Beffroi\Bundle\` autoloads it.
     */
    #[Test]
    public function theDirectoryOfTheMigrationsHoldsVersionFilesAndNothingElse(): void
    {
        // Given
        $directory = \dirname(__DIR__, 4) . '/src/symfony/migrations';

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
    public function theMigrationsCreateTheThirtyFiveTablesOfTheBundle(): void
    {
        // Given
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]);

        // When
        $statements = self::statements($connection);

        // Then
        static::assertCount(35, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    /**
     * The second migration adds the one table of the opaque access tokens and nothing else, so that a
     * deployment of spike 1 upgrades by one table.
     */
    /**
     * The last migration adds the one table of the device authorization requests, and renames what a
     * refresh token family descends from, there being two kinds of record it can descend from now
     * (RFC 8628 §3.4).
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

    /**
     * The third migration adds the one table of the passkeys and nothing else, so that a deployment of
     * spike 2 upgrades by one table.
     */
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

    /**
     * The fourth migration adds the policy column to the tenant table and nothing else, with the default
     * policy as its default, so that the tenant of a deployment of spike 2 keeps the vocabulary it had.
     */
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

    /**
     * The fifth migration adds the one table of the TOTP credentials and nothing else, so that a
     * deployment of the first days of spike 3 upgrades by one table.
     */
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

    /**
     * The seventh migration adds the one table of the pushed authorization requests and nothing else, so
     * that a deployment of the first days of spike 5 upgrades by one table.
     */
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

    /**
     * A CREATE TABLE with its column definitions in name order: the schema tool writes the columns of an
     * embeddable after the identifier, a migration wrote them where the mapping had them, and PostgreSQL
     * gives the order no meaning. The definitions themselves are compared byte for byte; a comma inside a
     * quoted default splits nothing.
     */
    private static function withColumnsSorted(string $statement): string
    {
        if (preg_match('/^(CREATE TABLE \S+ \()(.*)(\))$/', $statement, $matches) !== 1) {
            return $statement;
        }
        $definitions = self::definitions($matches[2]);
        sort($definitions);

        return $matches[1] . implode(', ', $definitions) . $matches[3];
    }

    /**
     * The same CREATE TABLE without one of its columns, which is what a migration that replaces a column
     * leaves behind: the column is dropped and added again with another type, and what the mappings
     * describe is the one that was added.
     */
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
     * The column definitions of a CREATE TABLE, one per element. A comma inside a quoted default or inside
     * a type of its own splits nothing.
     *
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
     * The statements of every migration, applied in order; a column a later migration adds to a table is
     * folded into the CREATE TABLE of that table, which is what the schema tool describes.
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
                // a column a later migration renames is the column the mappings describe, wherever an
                // earlier statement about that table named it
                if (preg_match('/^ALTER TABLE (\S+) RENAME COLUMN (\S+) TO (\S+)$/', $statement, $matches) === 1) {
                    $statements = array_map(
                        static fn (string $earlier): string => str_contains($earlier, $matches[1])
                            ? self::renamed($earlier, $matches[2], $matches[3])
                            : $earlier,
                        $statements,
                    );

                    continue;
                }
                // a table a later migration renames, and the constraint of one, are those the mappings describe,
                // wherever an earlier statement named them
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
                // a column a later migration drops leaves the CREATE TABLE of that table without it, the
                // schema the mappings describe holding only what is there at the end
                if (preg_match('/^ALTER TABLE (\S+) DROP (?!CONSTRAINT )(\S+)$/', $statement, $matches) === 1) {
                    $statements = array_map(
                        static fn (string $earlier): string => str_starts_with($earlier, 'CREATE TABLE ' . $matches[1] . ' (')
                            ? self::withoutColumn($earlier, $matches[2])
                            : $earlier,
                        $statements,
                    );

                    continue;
                }
                // and an index a later migration drops is an index the mappings no longer declare, so the
                // statement that created it goes with it
                if (preg_match('/^DROP INDEX (\S+)$/', $statement, $matches) === 1) {
                    $statements = array_values(array_filter(
                        $statements,
                        static fn (string $earlier): bool => preg_match('/^CREATE (UNIQUE )?INDEX ' . preg_quote($matches[1], '/') . ' /', $earlier) !== 1,
                    ));

                    continue;
                }
                // what a migration does to the rows is not what the mappings describe: a column made
                // mandatory on a table of records that live minutes empties it first
                if (str_starts_with($statement, 'DELETE FROM ')) {
                    continue;
                }
                $statements[] = $statement;
            }
        }

        return $statements;
    }

    /**
     * One identifier for another, on its own and never inside a longer one.
     */
    private static function renamed(string $statement, string $from, string $to): string
    {
        return (string) preg_replace('/\b' . preg_quote($from, '/') . '\b/', $to, $statement);
    }
}
