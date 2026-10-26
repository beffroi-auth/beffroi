<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Replay\RememberedMessage;
use Beffroi\Saml\Port\ReplayStoreInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * The assertions and the logout messages the model accepted, in beffroi_saml_remembered_message (beffroi/saml,
 * spec/saml.md S-23, S-53, model.md M-11): the store every worker of the deployment shares, written atomically.
 *
 * Two statements through the connection and not the unit of work: the rows whose window has closed are deleted, then
 * the message is inserted with ON CONFLICT DO NOTHING, the database telling how many rows the insertion wrote. Two
 * workers handed the same message at the same instant race into the primary key, and one only is told it wrote a row,
 * which is the atomicity a pool of cache, which tells a hit from a miss and not an insertion from a replacement, does
 * not give (SeenOnce). A row deleted while its window is open would accept the message again; none is, the deletion
 * reading the clock the validator reads.
 *
 * @extends DoctrineRepository<RememberedMessage>
 */
final readonly class DoctrineReplayStore extends DoctrineRepository implements ReplayStoreInterface
{
    public function __construct(
        EntityManagers $managers,
        private ClockInterface $clock,
    ) {
        parent::__construct($managers, RememberedMessage::class);
    }

    public function remember(Tenant $tenant, string $issuer, string $id, DateTimeImmutable $expiresAt): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(RememberedMessage::class);
        $connection = $manager->getConnection();
        $table = $metadata->getTableName();
        $expiry = $metadata->getColumnName('expiresAt');
        $connection->executeStatement(
            sprintf('DELETE FROM %s WHERE %s <= :now', $table, $expiry),
            ['now' => $this->clock->now()],
            ['now' => Types::DATETIME_IMMUTABLE],
        );
        $written = $connection->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s, %s) VALUES (:key, :tenant, :expiresAt) ON CONFLICT DO NOTHING',
                $table,
                $metadata->getColumnName('key'),
                $metadata->getSingleAssociationJoinColumnName('tenant'),
                $expiry,
            ),
            [
                'key' => RememberedMessage::keyOf($tenant, $issuer, $id),
                'tenant' => $tenant->id,
                'expiresAt' => $expiresAt,
            ],
            [
                'key' => Types::STRING,
                'tenant' => 'uuid',
                'expiresAt' => Types::DATETIME_IMMUTABLE,
            ],
        );

        return $written === 1;
    }
}
