<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Type\LogoutProgressType;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Port\LogoutChainRepositoryInterface;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Query;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * The chains of logout the SAML identity provider plays, in beffroi_saml_logout_chain (beffroi/saml, spec/saml.md
 * S-32): the store every worker of the deployment shares.
 *
 * Written and taken through the connection and not the unit of work. A step takes its chain by a deletion whose count
 * the database gives, so that of two requests presenting the same reference, or the answer to the same request, one
 * only is told it deleted the row; the next step then inserts the chain again under the same reference, which the
 * unit of work, still holding the row it read, would take for a second entity of one identifier. The rows whose ten
 * minutes have passed are deleted before each insertion, with the clock the steps read.
 *
 * @extends DoctrineRepository<LogoutChain>
 */
final readonly class DoctrineLogoutChainRepository extends DoctrineRepository implements LogoutChainRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private ClockInterface $clock,
    ) {
        parent::__construct($managers, LogoutChain::class);
    }

    public function save(LogoutChain $chain): void
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(LogoutChain::class);
        $connection = $manager->getConnection();
        $table = $metadata->getTableName();
        $expiry = $metadata->getColumnName('expiresAt');
        $connection->executeStatement(
            sprintf('DELETE FROM %s WHERE %s <= :now', $table, $expiry),
            ['now' => $this->clock->now()],
            ['now' => Types::DATETIME_IMMUTABLE],
        );
        $connection->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (:reference, :secret, :tenant, :awaiting, :progress, :expiresAt)',
                $table,
                $metadata->getColumnName('reference'),
                $metadata->getColumnName('secret'),
                $metadata->getSingleAssociationJoinColumnName('tenant'),
                $metadata->getColumnName('awaitingRequest'),
                $metadata->getColumnName('progress'),
                $expiry,
            ),
            [
                'reference' => $chain->reference,
                'secret' => $chain->secret,
                'tenant' => $chain->tenant->id,
                'awaiting' => $chain->awaitingRequest,
                'progress' => $chain->progress,
                'expiresAt' => $chain->expiresAt,
            ],
            [
                'reference' => Types::STRING,
                'secret' => Types::STRING,
                'tenant' => 'uuid',
                'awaiting' => Types::STRING,
                'progress' => LogoutProgressType::NAME,
                'expiresAt' => Types::DATETIME_IMMUTABLE,
            ],
        );
    }

    public function ofReference(Tenant $tenant, string $reference): ?LogoutChain
    {
        return $this->one($tenant, 'reference', LogoutChain::digestOf($reference));
    }

    public function awaiting(Tenant $tenant, string $requestId): ?LogoutChain
    {
        return $this->one($tenant, 'awaitingRequest', $requestId);
    }

    public function take(LogoutChain $chain): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(LogoutChain::class);
        $awaiting = $metadata->getColumnName('awaitingRequest');
        $parameters = [
            'reference' => $chain->reference,
            'tenant' => $chain->tenant->id,
        ];
        $types = [
            'reference' => Types::STRING,
            'tenant' => 'uuid',
        ];
        if ($chain->awaitingRequest === null) {
            $condition = sprintf('%s IS NULL', $awaiting);
        } else {
            $condition = sprintf('%s = :awaiting', $awaiting);
            $parameters['awaiting'] = $chain->awaitingRequest;
            $types['awaiting'] = Types::STRING;
        }
        $deleted = $manager->getConnection()->executeStatement(
            sprintf(
                'DELETE FROM %s WHERE %s = :reference AND %s = :tenant AND %s',
                $metadata->getTableName(),
                $metadata->getColumnName('reference'),
                $metadata->getSingleAssociationJoinColumnName('tenant'),
                $condition,
            ),
            $parameters,
            $types,
        );
        if ($manager->contains($chain)) {
            $manager->detach($chain);
        }

        return $deleted === 1;
    }

    /**
     * The chain of the tenant whose $field is $value, read again from the database whatever the unit of work holds.
     */
    private function one(Tenant $tenant, string $field, string $value): ?LogoutChain
    {
        $chain = $this->queryBuilder('chain')
            ->where(sprintf('chain.%s = :value', $field))
            ->andWhere('IDENTITY(chain.tenant) = :tenant')
            ->setParameter('value', $value)
            ->setParameter('tenant', $tenant->id, 'uuid')
            ->getQuery()
            ->setHint(Query::HINT_REFRESH, true)
            ->getOneOrNullResult();

        return $chain instanceof LogoutChain ? $chain : null;
    }
}
