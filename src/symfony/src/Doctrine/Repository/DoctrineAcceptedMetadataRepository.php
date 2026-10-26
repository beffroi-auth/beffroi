<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;
use Doctrine\ORM\Mapping\ClassMetadata;
use LogicException;
use function sprintf;

/**
 * The newest metadata document accepted for each peer of one role of a tenant (beffroi/saml, spec/saml.md S-6, S-8,
 * S-42), in the table of that role, the document sealed by its type, and the row an operator forgets (section 6.2):
 * beffroi_saml_service_provider for the service providers, beffroi_saml_upstream_identity_provider for the upstream
 * identity providers, one instance per role, each built with the entity of its role and handed the rows of that role
 * only.
 *
 * @extends DoctrineRepository<AcceptedMetadata>
 */
final readonly class DoctrineAcceptedMetadataRepository extends DoctrineRepository implements
    AcceptedMetadataRepositoryInterface,
    CanForgetAcceptedMetadataInterface
{
    /**
     * @param class-string<AcceptedMetadata> $entity the row of the role, AcceptedServiceProviderMetadata or
     *                                              AcceptedUpstreamMetadata
     */
    public function __construct(
        EntityManagers $managers,
        private string $entity,
    ) {
        parent::__construct($managers, $entity);
    }

    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'entityId' => $entityId,
        ]);
    }

    /**
     * One INSERT through the connection and not the unit of work, as a pairwise subject is recorded: the console and
     * the hourly step registering the same peer at the same minute both find no row and race into the unique index of
     * the tenant and the entity ID, where one of them writes nothing and neither fails. A flush could not promise that:
     * the violation would close the unit of work for every peer read after it. The table, the columns and their types
     * are read from the mapping of the role, the document sealed by the type it maps to (S-8).
     *
     * @throws LogicException when the row is another role's: a programming error of the wiring
     */
    public function register(AcceptedMetadata $metadata): bool
    {
        $this->assertOwn($metadata);
        $manager = $this->manager();
        $class = $manager->getClassMetadata($this->entity);
        $tenant = $class->getSingleAssociationJoinColumnName('tenant');
        $entityId = $class->getColumnName('entityId');

        return $manager->getConnection()->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (:id, :tenant, :entityId, :document, :validUntil, :acceptedAt) ON CONFLICT (%s, %s) DO NOTHING',
                $class->getTableName(),
                $class->getColumnName('id'),
                $tenant,
                $entityId,
                $class->getColumnName('document'),
                $class->getColumnName('validUntil'),
                $class->getColumnName('acceptedAt'),
                $tenant,
                $entityId,
            ),
            [
                'id' => $metadata->id,
                'tenant' => $metadata->tenant->id,
                'entityId' => $metadata->entityId,
                'document' => $metadata->document,
                'validUntil' => $metadata->validUntil,
                'acceptedAt' => $metadata->acceptedAt,
            ],
            [
                'id' => self::type($class, 'id'),
                'tenant' => 'uuid',
                'entityId' => self::type($class, 'entityId'),
                'document' => self::type($class, 'document'),
                'validUntil' => self::type($class, 'validUntil'),
                'acceptedAt' => self::type($class, 'acceptedAt'),
            ],
        ) === 1;
    }

    public function save(AcceptedMetadata $metadata): void
    {
        $this->assertOwn($metadata);
        $this->store($metadata);
    }

    public function forget(AcceptedMetadata $metadata): void
    {
        $this->assertOwn($metadata);
        $this->discard($metadata);
    }

    /**
     * @throws LogicException
     */
    private function assertOwn(AcceptedMetadata $metadata): void
    {
        if (! $metadata instanceof $this->entity) {
            throw new LogicException(sprintf('The repository of %s is handed a %s, the row of another role.', $this->entity, $metadata::class));
        }
    }

    /**
     * @param ClassMetadata<AcceptedMetadata> $class
     */
    private static function type(ClassMetadata $class, string $field): string
    {
        return $class->getTypeOfField($field) ?? throw new LogicException(sprintf('The mapping of %s gives "%s" no type.', $class->getName(), $field));
    }
}
