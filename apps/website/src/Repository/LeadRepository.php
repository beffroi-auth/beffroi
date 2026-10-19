<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\Lead;
use DateTimeImmutable;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Lead>
 */
final class LeadRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Lead::class);
    }

    public function findOneByEmail(string $email): ?Lead
    {
        return $this->findOneBy(['email' => $email]);
    }

    /**
     * Deletes the leads whose last consent is older than the given date, and says how many.
     */
    public function deleteConsentedBefore(DateTimeImmutable $limit): int
    {
        return $this->createQueryBuilder('lead')
            ->delete()
            ->where('lead.consentedAt < :limit')
            ->setParameter('limit', $limit)
            ->getQuery()
            ->execute();
    }

    /**
     * @return iterable<Lead> every lead, the most recent first, loaded one at a time
     */
    public function streamNewestFirst(): iterable
    {
        return $this->createQueryBuilder('lead')
            ->orderBy('lead.createdAt', 'DESC')
            ->getQuery()
            ->toIterable();
    }
}
