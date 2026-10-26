<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\PersonalData;

use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Bundle\Doctrine\PersonalData\TenantScopedDataKeyStore;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\KeyManagement\Command\RewrapDataKeysCommand;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;
use Symfony\Component\KeyManagement\Test\InMemoryKms;

/**
 * The secrets the stores of the tenants bind a row with (`StoredDataKey::bindingFor()`): the first one binds
 * a new row and every one is accepted when a row is read, which is what lets a deployment rotate the secret
 * without losing what it sealed, a rewrap binding each row again under the first.
 */
final class TenantDataKeyStoresTest extends TestCase
{
    private const string SCOPE = 'acme.user';

    private const string MASTER_KEY = 'beffroi-{tenant}';

    private Connection $connection;

    /**
     * @var ServiceLocator<InMemoryKms>
     */
    private ServiceLocator $clients;

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ]);
        $kms = new InMemoryKms('op');
        $this->clients = new ServiceLocator([
            'op' => static fn (): InMemoryKms => $kms,
        ]);
        $this->stores(['current'])->reader()->createTable();
    }

    /**
     * A row whose secret the deployment no longer lists opens nothing: whoever wrote the table could have
     * wrapped its key themselves, and only a listed secret tells them apart.
     */
    #[Test]
    public function aRowBoundUnderASecretNoLongerListedOpensNothing(): void
    {
        // Given
        $reference = $this->stores(['retired'])->current(self::SCOPE)->reference;

        // Then
        $this->expectException(DecryptionFailedException::class);

        // When
        $this->stores(['current'])->get($reference);
    }

    /**
     * Every listed secret is accepted when a row is read, so a secret written second still opens the rows it
     * bound while it was the first.
     */
    #[Test]
    public function aRowBoundUnderASecretListedSecondStillOpens(): void
    {
        // Given
        $reference = $this->stores(['retired'])->current(self::SCOPE)->reference;

        // When
        $handle = $this->stores(['current', 'retired'])->get($reference);

        // Then
        static::assertSame($reference, $handle->reference);
    }

    /**
     * A rewrap towards the client that already wraps the keys binds each row again under the first secret,
     * after which the retired one is no longer needed: the rotation the configuration describes.
     */
    #[Test]
    public function aRewrapBindsTheRowsAgainUnderTheFirstSecret(): void
    {
        // Given
        $reference = $this->stores(['retired'])->current(self::SCOPE)->reference;
        new RewrapDataKeysCommand(new TenantScopedDataKeyStore($this->stores(['current', 'retired']), Fixtures::tenant('acme')), $this->clients)->__invoke(
            new SymfonyStyle(new ArrayInput([]), new BufferedOutput()),
            to: 'op',
            keyId: 'beffroi-acme',
        );

        // When
        $handle = $this->stores(['current'])->get($reference);

        // Then
        static::assertSame($reference, $handle->reference);
    }

    /**
     * The stores of the tenants under these secrets, built afresh so that nothing a previous one opened is
     * held: what a row is read with is the table and the secrets, as in a process that just started.
     *
     * @param non-empty-list<string> $secrets
     */
    private function stores(array $secrets): TenantDataKeyStores
    {
        return new TenantDataKeyStores($this->connection, $this->clients, 'op', self::MASTER_KEY, $secrets, TenantDataKeyStores::TABLE);
    }
}
