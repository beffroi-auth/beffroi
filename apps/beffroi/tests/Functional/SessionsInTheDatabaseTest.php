<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Doctrine\TenantSynchronizer;
use App\Http\DatabaseSessions;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use function json_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * Decision 0053: the session a server writes is the one another server of the deployment reads, in the database
 * of the deployment, under the hash of its identifier and sealed under a data key of the tenant.
 */
final class SessionsInTheDatabaseTest extends KernelTestCase
{
    private const string COOKIE = 'w3Fz9LpQ0dXn7Ty2';

    protected function setUp(): void
    {
        $synchronizer = self::getContainer()->get('test.beffroi.tenant_synchronizer');
        static::assertInstanceOf(TenantSynchronizer::class, $synchronizer);
        $synchronizer->synchronize();
    }

    protected function tearDown(): void
    {
        self::database()->executeStatement('DELETE FROM beffroi_session');
        parent::tearDown();
    }

    #[Test]
    public function aSessionAServerWroteIsReadByAnother(): void
    {
        // Given
        $written = self::sessions();
        $written->open('', 'beffroi');
        $written->read(self::COOKIE);
        $written->write(self::COOKIE, 'the data of the browser');
        $written->close();
        $another = new DatabaseSessions(self::database(), self::sealer());

        // When
        $another->open('', 'beffroi');
        $read = $another->read(self::COOKIE);
        $another->close();

        // Then
        static::assertSame('the data of the browser', $read);
    }

    #[Test]
    public function eachNewSessionIsGivenAnIdentifierOfItsOwn(): void
    {
        // Given
        $sessions = self::sessions();

        // When
        $first = $sessions->create_sid();
        $second = $sessions->create_sid();

        // Then
        static::assertMatchesRegularExpression('/^[0-9a-zA-Z,-]{22,256}$/', $first);
        static::assertNotSame($first, $second);
    }

    #[Test]
    public function theTableHoldsNeitherTheIdentifierOfTheCookieNorTheData(): void
    {
        // Given
        $sessions = self::sessions();

        // When
        $sessions->open('', 'beffroi');
        $sessions->read(self::COOKIE);
        $sessions->write(self::COOKIE, 'the data of the browser');
        $sessions->close();

        // Then
        $dump = self::database()->fetchAllAssociative("SELECT sess_id, encode(sess_data, 'escape') AS sess_data FROM beffroi_session");
        static::assertCount(1, $dump);
        static::assertStringNotContainsString(self::COOKIE, (string) json_encode($dump));
        static::assertStringNotContainsString('the data of the browser', (string) json_encode($dump));
    }

    /**
     * A worker serves every request with the same handler, while Doctrine closes its connection once
     * idle_connection_ttl has passed and the network drops one left idle.
     */
    #[Test]
    public function aSessionOpensOnTheConnectionDoctrineHoldsOnceTheOneOfThePreviousSessionWasDropped(): void
    {
        // Given
        $sessions = self::sessions();
        $sessions->open('', 'beffroi');
        $sessions->read(self::COOKIE);
        $sessions->write(self::COOKIE, 'the data of the browser');
        $sessions->close();
        self::dropTheConnectionOfDoctrine();

        // When
        $sessions->open('', 'beffroi');
        $read = $sessions->read(self::COOKIE);
        $sessions->close();

        // Then
        static::assertSame('the data of the browser', $read);
    }

    private static function sessions(): DatabaseSessions
    {
        $sessions = self::getContainer()->get(DatabaseSessions::class);
        static::assertInstanceOf(DatabaseSessions::class, $sessions);

        return $sessions;
    }

    private static function database(): Connection
    {
        $connection = self::getContainer()->get('doctrine.dbal.default_connection');
        static::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }

    /**
     * The server ends the backend, as a restart or a dropped idle connection does, then Doctrine lets the connection
     * go, as its idle connection listener does.
     */
    private static function dropTheConnectionOfDoctrine(): void
    {
        $doctrine = self::database();
        $backend = $doctrine->fetchOne('SELECT pg_backend_pid()');
        $administrator = DriverManager::getConnection($doctrine->getParams());
        $administrator->fetchOne('SELECT pg_terminate_backend(?, 5000)', [$backend]);
        $administrator->close();
        $doctrine->close();
    }

    private static function sealer(): TenantScopedEncrypter
    {
        $sealer = self::getContainer()->get('beffroi.personal_data.encrypter');
        static::assertInstanceOf(TenantScopedEncrypter::class, $sealer);

        return $sealer;
    }
}
