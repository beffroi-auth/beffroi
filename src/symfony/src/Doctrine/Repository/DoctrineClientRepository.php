<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Doctrine\DBAL\Types\Types;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Domain\Client\Registration\ClientRetention;
use Beffroi\Oidc\Port\ClientInventoryInterface;
use Beffroi\Oidc\Port\ClientSourceInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Port\UnusedClientsInterface;
use function is_string;
use Psr\Log\LoggerInterface;
use function sprintf;

/**
 * The clients this provider registered itself, in beffroi_client (RFC 7591 §3.2.1): a source of clients
 * like the configuration of the deployment, and the store the registration endpoint writes to. Nothing
 * downstream learns that a client came from a row rather than from a declaration.
 *
 * A row keeps the metadata as the client registered it, so it is read back by the reader every registration
 * goes through, behind the defaults of RFC 7591 §2 and never those of a deployment: what the client did not
 * ask for is what the specification says it gets. Beside it the row keeps what the registration policy of
 * the tenant wrote on that registration (decision 0017), read in front of it. The secret is the one thing
 * neither carries: the provider assigned it, and the row says by holding one that the registration
 * declares one.
 *
 * @extends DoctrineRepository<ClientRecord>
 */
final readonly class DoctrineClientRepository extends DoctrineRepository implements
    ClientInventoryInterface,
    ClientSourceInterface,
    ClientStoreInterface,
    UnusedClientsInterface
{
    /**
     * What this source calls itself where a person is shown where a client came from: these are the
     * clients that registered themselves, and one goes away when its row does.
     */
    public const string SOURCE = 'registration';

    public function __construct(
        EntityManagers $managers,
        private ClientMetadataReader $reader,
        private LoggerInterface $logger,
    ) {
        parent::__construct($managers, ClientRecord::class);
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        $record = $this->record($tenant, $clientId);
        $registration = $record === null ? null : $this->registrationOf($record);

        return $record === null || $registration === null ? null : new Client($tenant, $registration, $record->secret);
    }

    public function registrationsIn(Tenant $tenant): iterable
    {
        foreach ($this->recordsIn($tenant) as $record) {
            $registration = $this->registrationOf($record);
            if ($registration !== null) {
                yield $registration;
            }
        }
    }

    /**
     * Decision 0009: the two dates a client that registered itself has, read from the row and not from the
     * registration, because neither is anything the client sent. The name is the one it registered
     * (OIDC Registration §2), read from the members as it sent them rather than through the reader: a list
     * of clients is a list of rows and does not need every rule of every one of them to be read again.
     */
    public function inventoryIn(Tenant $tenant): iterable
    {
        foreach ($this->recordsIn($tenant) as $record) {
            yield new InventoriedClient(
                self::SOURCE,
                $record->clientId,
                self::registeredName($record),
                $record->issuedAt,
                $record->lastUsedAt,
            );
        }
    }

    public function save(ClientRecord $record): void
    {
        $this->store($record);
    }

    public function findRecord(Tenant $tenant, string $clientId): ?ClientRecord
    {
        return $this->record($tenant, $clientId);
    }

    /**
     * Decision 0009: the clients of that tenant nobody uses any more, in one query on the two dates the
     * retention names rather than a read of the table: a client used before the first, and a client that was
     * never used and drawn before the second. The ones that have waited longest come first, so that a
     * bounded run takes those and the next run takes the rest.
     */
    public function unusedIn(Tenant $tenant, ClientRetention $retention, int $limit): array
    {
        if ($limit < 1) {
            return [];
        }

        /** @var list<ClientRecord> $unused */
        $unused = $this->queryBuilder('c')
            ->andWhere('c.tenant = :tenant')
            ->andWhere('(c.lastUsedAt IS NOT NULL AND c.lastUsedAt < :usedSince) OR (c.lastUsedAt IS NULL AND c.issuedAt < :registeredSince)')
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->setParameter('usedSince', $retention->usedSince, Types::DATETIME_IMMUTABLE)
            ->setParameter('registeredSince', $retention->registeredSince, Types::DATETIME_IMMUTABLE)
            ->addOrderBy('c.lastUsedAt', 'ASC')
            ->addOrderBy('c.issuedAt', 'ASC')
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();

        return $unused;
    }

    /**
     * RFC 7592 §2.3: the row is gone. What names it elsewhere is left where it is, a record whose client
     * no longer resolves being a record nobody finds.
     */
    public function remove(ClientRecord $record): void
    {
        $this->discard($record);
    }

    /**
     * OIDC Registration §2: what a client called itself, or null for one that registered no name. A member
     * of another shape is a row this provider will refuse when it resolves it, and is not named here.
     */
    private static function registeredName(ClientRecord $record): ?string
    {
        $name = $record->metadata['client_name'] ?? null;

        return is_string($name) && $name !== '' ? $name : null;
    }

    private function record(Tenant $tenant, string $clientId): ?ClientRecord
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'clientId' => $clientId,
        ]);
    }

    /**
     * @return list<ClientRecord>
     */
    private function recordsIn(Tenant $tenant): array
    {
        return $this->repository()->findBy([
            'tenant' => $tenant,
        ], [
            'issuedAt' => 'ASC',
        ]);
    }

    /**
     * The metadata read as a declaration is read, strictly and by the same reader: a member this
     * provider does not understand is refused here as it is there, so a row written by a version that
     * read more than this one, or before a rule this one holds its members to (the host of a URI it
     * registered, RFC 3986 §3.2.2), says so instead of serving a client nobody can account for. It says
     * so in the log, as an error, and names no client: the row is a client no longer registered, so that
     * what it holds stops at its own requests, answered as those of a client nobody knows, and never
     * reaches the pages of the sessions it took part in, which load its grants (ClientResolver), nor the
     * questions about the set of clients of the tenant (RegisteredClients).
     *
     * What the registration policy of the tenant wrote is read in front of what the client sent
     * (decision 0017), from the row and never from the policy: a policy is read where a registration is
     * written, at the creation of RFC 7591 §3.1 and at the replacement of RFC 7592 §2.2, and never at
     * the authorization request that looks this client up.
     */
    private function registrationOf(ClientRecord $record): ?ClientRegistration
    {
        try {
            return $this->reader->read($record->clientId, $record->asRegistered(), $record->secret !== null);
        } catch (UnreadableClientMetadataException $refusal) {
            $this->logger->error(sprintf(
                'The client "%s" registered metadata this provider refuses now, and is served as no client: %s',
                $record->clientId,
                $refusal->getMessage(),
            ));

            return null;
        }
    }
}
