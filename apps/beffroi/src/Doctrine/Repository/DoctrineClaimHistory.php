<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\AnAdministrator;
use App\Doctrine\Type\ClaimChangeAuthorType;
use App\Doctrine\Chain\DoctrineChains;
use App\Doctrine\EntityManagers;
use App\Doctrine\PageOfRows;
use App\Doctrine\SelectionWithinAPeriod;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\ClaimChangeQuestion;
use Beffroi\Core\Domain\Identity\ClaimHistoryChain;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Port\CanPageChangesOfAPersonInterface;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use SortDirection;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * @extends DoctrineRepository<ClaimChange>
 */
final readonly class DoctrineClaimHistory extends DoctrineRepository implements
    CanPageChangesOfAPersonInterface,
    ChangesOfAPersonInterface,
    ClaimHistoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private PageOfRows $rows,
        private DoctrineChains $chains,
    ) {
        parent::__construct($managers, ClaimChange::class);
    }

    public function record(ClaimChange $change): void
    {
        $this->chains->written($change->tenant, new ClaimHistoryChain(), $change->id, fn () => $this->store($change));
    }

    /**
     * @return Listing<ClaimChange>
     */
    public function pageOfChanges(User $user, ClaimChangeQuestion $question, Pagination $pagination): Listing
    {
        $changes = $this->queryBuilder('c')->where('c.user = :user')->setParameter('user', $user->id, UuidType::NAME);
        if ($question->claim !== null) {
            $changes->andWhere('c.claim = :claim')->setParameter('claim', $question->claim);
        }
        // A change written before changes named the kind of their author names an administrator by a bare subject, and the person by NULL.
        if ($question->byAnAdministrator === true) {
            $changes
                ->andWhere($changes->expr()->orX('c.author LIKE :administrators', $changes->expr()->andX(
                    'c.author IS NOT NULL',
                    'c.author NOT LIKE :documents',
                )))
                ->setParameter('administrators', ClaimChangeAuthorType::documentsOfKind(AnAdministrator::KIND))
                ->setParameter('documents', ClaimChangeAuthorType::documents());
        }
        if ($question->byAnAdministrator === false) {
            $changes->andWhere($changes->expr()->orX('c.author IS NULL', 'c.author LIKE :persons'))->setParameter(
                'persons',
                ClaimChangeAuthorType::documentsOfKind(ThePerson::KIND),
            );
        }

        return $this->rows->of(ClaimChange::class, SelectionWithinAPeriod::narrow($changes, 'c.changedAt', $question->period), 'c.id', $pagination);
    }

    public function claimsChangedOf(User $user): array
    {
        /** @var list<string> */
        return $this->queryBuilder('c')
            ->select('c.claim')
            ->distinct()
            ->where('c.user = :user')
            ->orderBy('c.claim', SortDirection::Ascending)
            ->setParameter('user', $user->id, UuidType::NAME)
            ->getQuery()
            ->getSingleColumnResult();
    }

    public function lastOf(User $user, int $howMany): array
    {
        if ($howMany < 1) {
            return [];
        }

        /** @var list<ClaimChange> $last */
        $last = $this->queryBuilder('c')
            ->where('c.user = :user')
            ->orderBy('c.id', SortDirection::Descending)
            ->setMaxResults($howMany)
            ->setParameter('user', $user->id, UuidType::NAME)
            ->getQuery()
            ->getResult();

        return $last;
    }

    public function everyChangeOf(User $user, int $howMany, ?Uuid $after = null): array
    {
        if ($howMany < 1) {
            return [];
        }
        $query = $this->queryBuilder('c')
            ->where('c.user = :user')
            ->orderBy('c.id', SortDirection::Ascending)
            ->setMaxResults($howMany)
            ->setParameter('user', $user->id, UuidType::NAME);
        if ($after !== null) {
            $query->andWhere('c.id > :after')->setParameter('after', $after, UuidType::NAME);
        }

        /** @var list<ClaimChange> $page */
        $page = $query->getQuery()->getResult();

        return $page;
    }
}
