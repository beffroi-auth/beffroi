<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Doctrine\Role\RuntimeRoleGrants;
use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\ChainOfRowsInterface;
use Beffroi\Core\Port\JournalInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\DriverException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0060: the role the processes run as appends to the chained records and forgets them through the
 * retention alone; the role that plays the migrations is the only one to rewrite them.
 */
final class TheRoleOfTheProcessesTest extends KernelTestCase
{
    private const string ROLE = 'beffroi_runtime_of_the_suite';

    protected function setUp(): void
    {
        $synchronizer = self::getContainer()->get('test.beffroi.tenant_synchronizer');
        static::assertInstanceOf(TenantSynchronizer::class, $synchronizer);
        $synchronizer->synchronize();
        self::forgetTheJournal();
        self::database()
            ->executeStatement(sprintf(
                "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%1\$s') THEN CREATE ROLE %1\$s NOLOGIN; END IF; END $$",
                self::ROLE,
            ));
        $grants = self::getContainer()->get('test.beffroi.runtime_role_grants');
        static::assertInstanceOf(RuntimeRoleGrants::class, $grants);
        $grants->grant(self::ROLE);
    }

    protected function tearDown(): void
    {
        self::database()->executeStatement('RESET ROLE');
        self::forgetTheJournal();
        parent::tearDown();
    }

    #[Test]
    public function theRoleOfTheProcessesWritesAnActDown(): void
    {
        // Given
        self::database()->executeStatement('SET ROLE ' . self::ROLE);

        // When
        self::anAct(new DateTimeImmutable());

        // Then
        static::assertSame(1, self::chains()->head(self::tenant(), new JournalChain())->position);
    }

    #[Test]
    #[DataProvider('provideRewrites')]
    public function theRoleOfTheProcessesRewritesNoRowOfAChain(string $rewrite): void
    {
        // Given
        self::anAct(new DateTimeImmutable());
        self::database()->executeStatement('SET ROLE ' . self::ROLE);

        // Then
        $this->expectException(DriverException::class);
        $this->expectExceptionMessageIsOrContains('permission denied');

        // When
        self::database()->executeStatement($rewrite);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRewrites(): iterable
    {
        yield 'an act changed' => ["UPDATE beffroi_journal SET act = 'user.signed_out'"];
        yield 'an act removed' => ['DELETE FROM beffroi_journal'];
        yield 'the journal emptied' => ['TRUNCATE beffroi_journal'];
        yield 'a link changed' => ['UPDATE beffroi_chain_link SET hash = previous'];
        yield 'a link removed' => ['DELETE FROM beffroi_chain_link'];
        yield 'a change of a claim removed' => ['DELETE FROM beffroi_claim_change'];
        yield 'what a client was given removed' => ['DELETE FROM beffroi_disclosure'];
        yield 'the tenant removed with its chains' => ['DELETE FROM beffroi_tenant'];
    }

    #[Test]
    public function theRoleOfTheProcessesForgetsTheOldestActsThroughTheRetention(): void
    {
        // Given
        self::anAct(new DateTimeImmutable('-400 days'));
        self::anAct(new DateTimeImmutable());
        self::database()->executeStatement('SET ROLE ' . self::ROLE);

        // When
        $forgotten = self::chains()->forgetUpTo(self::tenant(), new JournalChain(), 1);

        // Then
        static::assertSame(1, $forgotten);
    }

    private static function anAct(DateTimeImmutable $at): void
    {
        $journal = self::getContainer()->get('test.beffroi.journal');
        static::assertInstanceOf(JournalInterface::class, $journal);
        $journal->record(new JournalEntry(Uuid::v7(), self::tenant(), 'user.authenticated', $at, new RequestContext($at, '203.0.113.7', 'the suite')));
    }

    private static function chains(): ChainOfRowsInterface
    {
        $chains = self::getContainer()->get('test.beffroi.chains');
        static::assertInstanceOf(ChainOfRowsInterface::class, $chains);

        return $chains;
    }

    private static function tenant(): Tenant
    {
        $tenants = self::getContainer()->get('test.beffroi.tenant_provider');
        static::assertInstanceOf(TenantProvider::class, $tenants);

        return $tenants->provide();
    }

    private static function forgetTheJournal(): void
    {
        self::database()->executeStatement("DELETE FROM beffroi_chain_link WHERE chain = 'journal'");
        self::database()->executeStatement("DELETE FROM beffroi_chain_head WHERE chain = 'journal'");
        self::database()->executeStatement('DELETE FROM beffroi_journal');
    }

    private static function database(): Connection
    {
        $connection = self::getContainer()->get('doctrine.dbal.default_connection');
        static::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
