<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Doctrine\DBAL\Types\Types;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Each service provider's part in a session, in beffroi_saml_session_participant (beffroi/saml, spec/saml.md S-26).
 *
 * @extends DoctrineRepository<SessionParticipation>
 */
final readonly class DoctrineSessionParticipationRepository extends DoctrineRepository implements SessionParticipationRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, SessionParticipation::class);
    }

    /**
     * One INSERT through the connection and not the unit of work, as a pairwise subject is recorded: the same session
     * signing in twice to the same service provider, or two workers recording it at once, race into the unique index,
     * where the second write does nothing and none fails.
     */
    public function record(SessionParticipation $participation): void
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(SessionParticipation::class);
        $manager->getConnection()->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s, %s, %s, %s) VALUES (:id, :tenant, :session, :serviceProvider, :signedInAt) ON CONFLICT DO NOTHING',
                $metadata->getTableName(),
                $metadata->getColumnName('id'),
                $metadata->getSingleAssociationJoinColumnName('tenant'),
                $metadata->getSingleAssociationJoinColumnName('session'),
                $metadata->getColumnName('serviceProvider'),
                $metadata->getColumnName('signedInAt'),
            ),
            [
                'id' => $participation->id,
                'tenant' => $participation->tenant->id,
                'session' => $participation->session->id,
                'serviceProvider' => $participation->serviceProvider,
                'signedInAt' => $participation->signedInAt,
            ],
            [
                'id' => 'uuid',
                'tenant' => 'uuid',
                'session' => 'uuid',
                'serviceProvider' => Types::STRING,
                'signedInAt' => Types::DATETIME_IMMUTABLE,
            ],
        );
    }

    public function ofSession(Uuid $sessionId): array
    {
        /** @var list<SessionParticipation> */
        return $this->queryBuilder('participation')
            ->where('IDENTITY(participation.session) = :session')
            ->setParameter('session', $sessionId, 'uuid')
            ->orderBy('participation.signedInAt', 'ASC')
            ->addOrderBy('participation.id', 'ASC')
            ->getQuery()
            ->getResult();
    }
}
