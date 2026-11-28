<?php

declare(strict_types=1);

namespace App\Tests\Functional\Journal;

use App\Doctrine\Chain\DoctrineChains;
use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use function array_map;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0060 and 0066, on PostgreSQL: the journal a version before acts named the kind of their author wrote, its
 * administrators by their bare subject in a column of 255 characters, holds together once the column holds text, and
 * reads back as it was written.
 */
final class TheJournalWrittenBeforeAuthorsHadKindsTest extends KernelTestCase
{
    protected function setUp(): void
    {
        $synchronizer = self::getContainer()->get('test.beffroi.tenant_synchronizer');
        static::assertInstanceOf(TenantSynchronizer::class, $synchronizer);
        $synchronizer->synchronize();
        self::forgetTheJournal();
        self::database()->executeStatement('ALTER TABLE beffroi_journal ALTER author TYPE VARCHAR(255)');
        self::actWrittenBefore('mallory-subject');
        self::actWrittenBefore(null);
        // What Version20261128141800 plays.
        self::database()->executeStatement('ALTER TABLE beffroi_journal ALTER author TYPE TEXT');
    }

    protected function tearDown(): void
    {
        self::database()->executeStatement('ALTER TABLE beffroi_journal ALTER author TYPE TEXT');
        self::forgetTheJournal();
        parent::tearDown();
    }

    #[Test]
    public function theChainOfTheJournalWrittenBeforeHoldsTogether(): void
    {
        // Given
        $verification = self::getContainer()->get('test.beffroi.chain_verification');
        static::assertInstanceOf(ChainVerification::class, $verification);

        // When
        $verified = $verification->whole(self::tenant(), new JournalChain());

        // Then
        static::assertSame(2, $verified->end->position);
    }

    #[Test]
    public function theActsWrittenBeforeReadBackAsTheyWereWritten(): void
    {
        // When
        $acts = self::entityManager()->getRepository(JournalEntry::class)->findBy([], ['id' => 'ASC']);

        // Then
        static::assertEquals(
            [new AnAdministrator(new Subject('mallory-subject')), null],
            array_map(static fn (JournalEntry $act): ?AuthorInterface => $act->author, $acts),
        );
    }

    /**
     * Linked to the chain from the bytes that version wrote: its administrator by a bare subject, or nobody.
     */
    private static function actWrittenBefore(?string $author): void
    {
        $now = new DateTimeImmutable();
        $entry = new JournalEntry(Uuid::v7(), self::tenant(), 'person.disabled', $now, new RequestContext($now, '203.0.113.7', 'the suite'), author: new TheHost());
        $manager = self::entityManager();
        $chains = self::getContainer()->get('test.beffroi.chains');
        static::assertInstanceOf(DoctrineChains::class, $chains);
        $chains->written(self::tenant(), new JournalChain(), $entry->id, static function () use ($manager, $entry, $author): void {
            $manager->persist($entry);
            $manager->flush();
            $manager->getConnection()->update('beffroi_journal', ['author' => $author], ['id' => $entry->id], ['id' => UuidType::NAME]);
        });
        $manager->clear();
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

    private static function entityManager(): EntityManagerInterface
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
