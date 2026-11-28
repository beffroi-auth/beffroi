<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use App\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\EndSession\AnnouncedSessionEnd;
use Beffroi\Oidc\Port\AnnouncedSessionEndsInterface;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Through the connection: an insertion's count names the one run that announces, in the transaction of its writes.
 *
 * @extends DoctrineRepository<AnnouncedSessionEnd>
 */
final readonly class DoctrineAnnouncedSessionEnds extends DoctrineRepository implements AnnouncedSessionEndsInterface
{
    public function __construct(
        EntityManagers $managers,
    ) {
        parent::__construct($managers, AnnouncedSessionEnd::class);
    }

    public function announceOnce(Tenant $tenant, Uuid $session): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(AnnouncedSessionEnd::class);

        return $manager->getConnection()->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s) VALUES (:session, :tenant) ON CONFLICT DO NOTHING',
                $metadata->getTableName(),
                $metadata->getSingleAssociationJoinColumnName('session'),
                $metadata->getSingleAssociationJoinColumnName('tenant'),
            ),
            [
                'session' => $session,
                'tenant' => $tenant->id,
            ],
            [
                'session' => 'uuid',
                'tenant' => 'uuid',
            ],
        ) === 1;
    }
}
