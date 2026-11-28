<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\DependencyFactory;
use Doctrine\Migrations\Version\Version;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Each test plays the migration back and forth inside a transaction it rolls back, so the schema it leaves is the one
 * it found.
 */
final class RowsBeforeTheVersionTest extends KernelTestCase
{
    private const string MIGRATION = 'DoctrineMigrations\\Version20261128140000';

    private const string CREATED_AT = '2026-09-15 10:00:00';

    protected function setUp(): void
    {
        $synchronizer = self::getContainer()->get('test.beffroi.tenant_synchronizer');
        static::assertInstanceOf(TenantSynchronizer::class, $synchronizer);
        $synchronizer->synchronize();
        self::database()->beginTransaction();
    }

    protected function tearDown(): void
    {
        self::database()->rollBack();
        parent::tearDown();
    }

    /**
     * RFC 7644 §3.14
     */
    #[Test]
    public function aPersonTheTableHeldBeforeIsAtTheFirstVersion(): void
    {
        // Given
        $drawn = Uuid::v7()->toRfc4122();
        $user = User::create(Uuid::v7(), self::tenant(), new Subject($drawn), $drawn, new DateTimeImmutable(self::CREATED_AT));
        $users = self::getContainer()->get('test.beffroi.users');
        static::assertInstanceOf(UserRepositoryInterface::class, $users);
        $users->save($user);
        self::migrateDown();

        // When
        self::migrateUp();

        // Then
        static::assertSame(1, self::database()->fetchOne('SELECT version FROM beffroi_user WHERE id = ?', [$user->id->toRfc4122()]));
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §3.1
     */
    #[Test]
    public function aGroupTheTableHeldBeforeIsAtTheFirstVersionLastChangedWhenCreated(): void
    {
        // Given
        self::migrateDown();
        $id = Uuid::v7()->toRfc4122();
        self::database()->insert('beffroi_group', [
            'id' => $id,
            'tenant_id' => self::tenant()->id->toRfc4122(),
            'name' => 'admins',
            'source' => 'local',
            'created_at' => self::CREATED_AT,
        ]);

        // When
        self::migrateUp();

        // Then
        static::assertSame(
            ['version' => 1, 'updated_at' => self::CREATED_AT],
            self::database()->fetchAssociative('SELECT version, updated_at FROM beffroi_group WHERE id = ?', [$id]),
        );
    }

    /**
     * RFC 7643 §3.1: a server of the previous code still writes groups while the next one migrates, and after it rolls
     * back.
     */
    #[Test]
    public function aGroupAProcessThatKnowsNoVersionWritesTakesTheFirstVersionAndALastChange(): void
    {
        // Given
        $id = Uuid::v7()->toRfc4122();

        // When
        self::database()->insert('beffroi_group', [
            'id' => $id,
            'tenant_id' => self::tenant()->id->toRfc4122(),
            'name' => 'admins',
            'source' => 'local',
            'created_at' => self::CREATED_AT,
        ]);

        // Then
        static::assertSame(
            [1, true],
            [
                self::database()->fetchOne('SELECT version FROM beffroi_group WHERE id = ?', [$id]),
                self::database()->fetchOne('SELECT updated_at IS NOT NULL FROM beffroi_group WHERE id = ?', [$id]),
            ],
        );
    }

    #[Test]
    public function theMigrationWaitsFiveSecondsAtMostForALock(): void
    {
        // Given
        $migration = self::migration();

        // When
        $migration->up(new Schema());

        // Then
        static::assertSame("SET LOCAL lock_timeout = '5s'", $migration->getSql()[0]->getStatement());
    }

    private static function migrateDown(): void
    {
        $migration = self::migration();
        $migration->down(new Schema());
        self::execute($migration);
    }

    private static function migrateUp(): void
    {
        $migration = self::migration();
        $migration->up(new Schema());
        self::execute($migration);
    }

    /**
     * A new one each time, since a migration keeps the statements it planned; its class is loaded from the directory
     * of the migrations, which no autoloader of the application maps.
     */
    private static function migration(): AbstractMigration
    {
        $migrations = self::getContainer()->get('doctrine.migrations.dependency_factory');
        static::assertInstanceOf(DependencyFactory::class, $migrations);
        $class = $migrations->getMigrationRepository()->getMigration(new Version(self::MIGRATION))->getMigration()::class;

        return new $class(self::database(), new NullLogger());
    }

    private static function execute(AbstractMigration $migration): void
    {
        foreach ($migration->getSql() as $query) {
            self::database()->executeStatement($query->getStatement());
        }
    }

    private static function tenant(): Tenant
    {
        $provider = self::getContainer()->get('test.beffroi.tenant_provider');
        static::assertInstanceOf(TenantProvider::class, $provider);

        return $provider->provide();
    }

    private static function database(): Connection
    {
        $connection = self::getContainer()->get('doctrine.dbal.default_connection');
        static::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
