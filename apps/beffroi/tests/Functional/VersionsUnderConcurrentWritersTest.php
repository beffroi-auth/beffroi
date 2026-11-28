<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use const PHP_BINARY;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Process\Process;
use Symfony\Component\Uid\Uuid;

/**
 * Writers of one row on connections of their own, as the servers and the worker of a deployment are: a version is
 * raised from what the row holds, so no raise is lost nor rewound, and no two of them wait on each other in a circle.
 */
final class VersionsUnderConcurrentWritersTest extends KernelTestCase
{
    private const int CHANGES_EACH = 20;

    private const int SIGN_INS_EACH = 100;

    /**
     * @var list<Uuid>
     */
    private array $persons = [];

    /**
     * @var list<Uuid>
     */
    private array $groups = [];

    /**
     * A manager of its own on a connection of its own, as another process holds, with the listeners of the first.
     */
    private EntityManagerInterface $another;

    protected function setUp(): void
    {
        $synchronizer = self::getContainer()->get('test.beffroi.tenant_synchronizer');
        static::assertInstanceOf(TenantSynchronizer::class, $synchronizer);
        $synchronizer->synchronize();
        $connection = self::database();
        $this->another = new EntityManager(
            DriverManager::getConnection($connection->getParams(), $connection->getConfiguration()),
            self::manager()->getConfiguration(),
            self::manager()->getEventManager(),
        );
    }

    protected function tearDown(): void
    {
        foreach ($this->groups as $group) {
            self::database()->executeStatement('DELETE FROM beffroi_group WHERE id = ?', [$group->toRfc4122()]);
        }
        foreach ($this->persons as $person) {
            self::database()->executeStatement('DELETE FROM beffroi_group_membership WHERE user_id = ?', [$person->toRfc4122()]);
            self::database()->executeStatement('DELETE FROM beffroi_user WHERE id = ?', [$person->toRfc4122()]);
        }
        $this->another->getConnection()->close();
        parent::tearDown();
    }

    /**
     * RFC 7644 §3.14, RFC 9110 §13.1.1
     */
    #[Test]
    public function twoWritersThatLoadedOneVersionRaiseItTwice(): void
    {
        // Given
        $id = $this->aPerson();
        $first = self::manager()->find(User::class, $id) ?? static::fail('The person was not stored.');
        $second = $this->another->find(User::class, $id) ?? static::fail('The person was not stored.');

        // When
        self::changed($first, self::manager(), '+1 hour');
        self::changed($second, $this->another, '+2 hours');

        // Then
        static::assertSame([2, 3, 3], [$first->version, $second->version, self::versionInTheRow($id)]);
    }

    /**
     * RFC 7644 §3.14, RFC 9110 §13.1.1
     */
    #[Test]
    public function aWriterThatLoadedBeforeTwoOthersRaisesTheVersionAboveTheirs(): void
    {
        // Given
        $id = $this->aPerson();
        $late = self::manager()->find(User::class, $id) ?? static::fail('The person was not stored.');
        $others = $this->another->find(User::class, $id) ?? static::fail('The person was not stored.');
        self::changed($others, $this->another, '+1 hour');
        self::changed($others, $this->another, '+2 hours');

        // When
        self::changed($late, self::manager(), '+3 hours');

        // Then
        static::assertSame([4, 4], [$late->version, self::versionInTheRow($id)]);
    }

    /**
     * RFC 7643 §3.1
     */
    #[Test]
    public function aWriterThatChangesAtAnEarlierInstantLeavesTheLastChangeWhereItWas(): void
    {
        // Given
        $id = $this->aPerson();
        $earlier = self::manager()->find(User::class, $id) ?? static::fail('The person was not stored.');
        $later = $this->another->find(User::class, $id) ?? static::fail('The person was not stored.');
        self::changed($later, $this->another, '+2 hours');

        // When
        self::changed($earlier, self::manager(), '+1 hour');

        // Then
        static::assertSame('2026-09-15 12:00:00', self::database()->fetchOne('SELECT updated_at FROM beffroi_user WHERE id = ?', [$id->toRfc4122()]));
    }

    /**
     * RFC 7644 §3.14, RFC 9110 §13.1.1
     */
    #[Test]
    public function twoProcessesChangingOnePersonRaiseItOnceForEachChange(): void
    {
        // Given
        $id = $this->aPerson();
        $writers = [];
        for ($started = 0; $started < 2; ++$started) {
            $writers[] = self::started('change-a-person.php', [$id->toRfc4122(), (string) self::CHANGES_EACH]);
        }

        // When
        self::waitFor($writers);

        // Then
        static::assertSame(1 + (2 * self::CHANGES_EACH), self::versionInTheRow($id));
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §4.1.2 and §4.2
     */
    #[Test]
    public function twoSignInsThatCrossTwoGroupsNeverWaitOnEachOtherAndRaiseEveryVersion(): void
    {
        // Given
        $alice = $this->aPerson();
        $bob = $this->aPerson();
        [$first, $second] = [$this->aGroup(), $this->aGroup()];
        $signIns = [
            self::started('cross-groups.php', [$alice->toRfc4122(), $first->toRfc4122(), $second->toRfc4122(), (string) self::SIGN_INS_EACH]),
            self::started('cross-groups.php', [$bob->toRfc4122(), $second->toRfc4122(), $first->toRfc4122(), (string) self::SIGN_INS_EACH]),
        ];

        // When
        self::waitFor($signIns);

        // Then
        $raised = 2 * self::SIGN_INS_EACH;
        static::assertSame(
            [1 + $raised, 1 + $raised, 1 + (2 * $raised), 1 + (2 * $raised)],
            [self::versionInTheRow($alice), self::versionInTheRow($bob), self::versionInTheRow($first, 'beffroi_group'), self::versionInTheRow($second, 'beffroi_group')],
        );
    }

    private function aPerson(): Uuid
    {
        $drawn = Uuid::v7();
        $user = User::create($drawn, self::tenant(), new Subject($drawn->toRfc4122()), $drawn->toRfc4122(), new DateTimeImmutable('2026-09-15 10:00:00'));
        self::manager()->persist($user);
        self::manager()->flush();
        self::manager()->clear();
        $this->persons[] = $drawn;

        return $drawn;
    }

    private function aGroup(): Uuid
    {
        $drawn = Uuid::v7();
        self::manager()->persist(new Group($drawn, self::tenant(), $drawn->toRfc4122(), GroupSource::Local, new DateTimeImmutable('2026-09-15 10:00:00')));
        self::manager()->flush();
        self::manager()->clear();
        $this->groups[] = $drawn;

        return $drawn;
    }

    private static function changed(User $user, EntityManagerInterface $manager, string $later): void
    {
        $user->updateProfile(new Profile(name: $later), new DateTimeImmutable('2026-09-15 10:00:00')->modify($later));
        $manager->flush();
    }

    private static function versionInTheRow(Uuid $id, string $table = 'beffroi_user'): int
    {
        $version = self::database()->fetchOne('SELECT version FROM ' . $table . ' WHERE id = ?', [$id->toRfc4122()]);
        static::assertIsInt($version);

        return $version;
    }

    /**
     * @param list<string> $arguments
     */
    private static function started(string $script, array $arguments): Process
    {
        $writer = new Process([PHP_BINARY, __DIR__ . '/Versions/' . $script, ...$arguments]);
        $writer->setTimeout(120);
        $writer->start();

        return $writer;
    }

    /**
     * @param list<Process> $writers
     */
    private static function waitFor(array $writers): void
    {
        foreach ($writers as $writer) {
            $writer->wait();
            static::assertTrue($writer->isSuccessful(), $writer->getErrorOutput() . $writer->getOutput());
        }
    }

    private static function tenant(): Tenant
    {
        $tenants = self::getContainer()->get('test.beffroi.tenant_provider');
        static::assertInstanceOf(TenantProvider::class, $tenants);

        return $tenants->provide();
    }

    private static function manager(): EntityManagerInterface
    {
        $manager = self::getContainer()->get('doctrine.orm.entity_manager');
        static::assertInstanceOf(EntityManagerInterface::class, $manager);

        return $manager;
    }

    private static function database(): Connection
    {
        $connection = self::getContainer()->get('doctrine.dbal.default_connection');
        static::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
