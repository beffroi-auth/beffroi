<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use function array_map;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\JournalInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use const PHP_BINARY;
use PHPUnit\Framework\Attributes\Test;
use function range;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Process\Process;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0060, with the processes of decision 0053: two servers and a worker write the journal at once, each on a
 * connection of its own, and the head of the chain they lock orders their acts.
 */
final class TheJournalUnderConcurrentWritersTest extends KernelTestCase
{
    private const int WRITERS = 4;

    private const int ACTS_EACH = 25;

    protected function setUp(): void
    {
        $synchronizer = self::getContainer()->get('test.beffroi.tenant_synchronizer');
        static::assertInstanceOf(TenantSynchronizer::class, $synchronizer);
        $synchronizer->synchronize();
        self::forgetTheJournal();
    }

    protected function tearDown(): void
    {
        self::forgetTheJournal();
        parent::tearDown();
    }

    #[Test]
    public function writersAtOnceTakePositionsThatFollowOneAnother(): void
    {
        // Given
        $writers = self::writersStarted();

        // When
        self::waitFor($writers);

        // Then
        static::assertSame(
            range(1, 1 + (self::WRITERS * self::ACTS_EACH)),
            array_map(intval(...), self::database()->fetchFirstColumn("SELECT position FROM beffroi_chain_link WHERE chain = 'journal' ORDER BY position")),
        );
    }

    #[Test]
    public function theChainWritersAtOnceWroteHoldsTogether(): void
    {
        // Given
        self::waitFor(self::writersStarted());
        $verification = self::getContainer()->get('test.beffroi.chain_verification');
        static::assertInstanceOf(ChainVerification::class, $verification);

        // When
        $verified = $verification->whole(self::tenant(), new JournalChain());

        // Then
        static::assertSame(1 + (self::WRITERS * self::ACTS_EACH), $verified->end->position);
    }

    /**
     * One act first, so that the data key its provenance is sealed under exists before the writers start.
     *
     * @return list<Process>
     */
    private static function writersStarted(): array
    {
        $journal = self::getContainer()->get('test.beffroi.journal');
        static::assertInstanceOf(JournalInterface::class, $journal);
        $now = new DateTimeImmutable();
        $journal->record(new JournalEntry(Uuid::v7(), self::tenant(), 'user.authenticated', $now, new RequestContext($now, '203.0.113.7', 'the suite')));
        $writers = [];
        for ($started = 0; $started < self::WRITERS; ++$started) {
            $writer = new Process([PHP_BINARY, __DIR__ . '/Journal/write-acts.php', (string) self::ACTS_EACH]);
            $writer->setTimeout(120);
            $writer->start();
            $writers[] = $writer;
        }

        return $writers;
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
