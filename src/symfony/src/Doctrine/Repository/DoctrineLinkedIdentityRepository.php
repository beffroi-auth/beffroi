<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Bundle\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Application\Identity\IdentityAlreadyLinkedException;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\LinkedIdentitiesOfAPersonInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * The identities of a user at an upstream provider, in beffroi_linked_identity (architecture §3.1); a lookup is
 * scoped by the tenant and exact, as the unique constraint of the table is.
 *
 * Both columns of the pair are sealed, so neither matches: the format seals every value under a random
 * initialisation vector, and two writes of one subject give two ciphertexts. What the lookup matches is the
 * two blind indexes, in the sibling columns the write filled in the same statement, and those are the
 * columns the unique constraint is held on (decision 0011).
 *
 * @extends DoctrineRepository<LinkedIdentity>
 */
final readonly class DoctrineLinkedIdentityRepository extends DoctrineRepository implements
    LinkedIdentitiesOfAPersonInterface,
    LinkedIdentityRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private TenantBlindIndexes $indexes,
    ) {
        parent::__construct($managers, LinkedIdentity::class);
    }

    /**
     * The projections the tags are derived under are the ones the write used, there being one declaration
     * for both sides.
     */
    public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
    {
        $providerColumn = BlindIndexedColumns::of(LinkedIdentity::class, 'provider');
        $subjectColumn = BlindIndexedColumns::of(LinkedIdentity::class, 'subject');

        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            $providerColumn->tag => $this->indexes->of($providerColumn)->of($provider),
            $subjectColumn->tag => $this->indexes->of($subjectColumn)->of($subject),
        ]);
    }

    /**
     * The identities of one person, which is a walk of their rows and matches nothing: it asks for the
     * person and not for a value, so no blind index is in it.
     */
    public function of(User $user): array
    {
        /** @var list<LinkedIdentity> $identities */
        $identities = $this->queryBuilder('i')
            ->where('i.user = :user')
            ->orderBy('i.linkedAt', 'DESC')
            ->setParameter('user', $user->id, UuidType::NAME)
            ->getQuery()
            ->getResult();

        return $identities;
    }

    /**
     * The unique constraint on the pair is what refuses an identity another request linked between the lookup and
     * this write, a first sign-in through an upstream provider racing another (beffroi/saml S-56): the violation
     * becomes the exception of the core the unit answers, naming nothing. The failed flush closes the manager, which
     * the registry replaces (EntityManagers).
     *
     * @throws IdentityAlreadyLinkedException when the table refuses the identity at its unique constraint
     */
    public function save(LinkedIdentity $identity): void
    {
        try {
            $this->store($identity);
        } catch (UniqueConstraintViolationException $exception) {
            throw IdentityAlreadyLinkedException::linkedMeanwhile($exception);
        }
    }
}
