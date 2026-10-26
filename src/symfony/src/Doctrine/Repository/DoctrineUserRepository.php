<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Bundle\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use function array_values;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Symfony\Component\Uid\Uuid;

/**
 * Users in beffroi_user (architecture §3.4); a lookup is scoped by the tenant and exact.
 *
 * The username and the address are sealed, so no lookup matches either: the format seals every value under a
 * random initialisation vector, and two writes of one username give two ciphertexts. What a lookup matches
 * is the blind index, in the sibling column the write filled in the same statement (decision 0011).
 *
 * @extends DoctrineRepository<User>
 */
final readonly class DoctrineUserRepository extends DoctrineRepository implements UserRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private TenantBlindIndexes $indexes,
    ) {
        parent::__construct($managers, User::class);
    }

    public function find(Uuid $id): ?User
    {
        return $this->repository()->findOneBy([
            'id' => $id,
        ]);
    }

    public function findBySubject(Tenant $tenant, Subject $subject): ?User
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'subject' => $subject,
        ]);
    }

    /**
     * The projection the tag is derived under is the one the write used, there being one declaration for
     * both sides: a lookup that folded what a write did not, or the other way round, would silently match
     * nothing, which is the failure the whole arrangement exists to avoid.
     */
    public function findByUsername(Tenant $tenant, string $username): ?User
    {
        $column = BlindIndexedColumns::of(User::class, 'username');

        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            $column->tag => $this->indexes->of($column)->of($username),
        ]);
    }

    /**
     * On the blind index of the address, as the username is found, under the projection the write used: the
     * address folded whole. No constraint holds the column unique, so every row that matches is the answer.
     */
    public function findAllByEmail(Tenant $tenant, EmailAddress $email): array
    {
        $column = BlindIndexedColumns::of(User::class, 'email');

        return array_values($this->repository()->findBy([
            'tenant' => $tenant,
            $column->tag => $this->indexes->of($column)->of($email->value),
        ]));
    }

    /**
     * The unique constraints on the subject and on the name are what refuse a person another request wrote between the
     * checks of a use case and this write, a first sign-in through an upstream provider racing another (beffroi/saml
     * S-56): the violation becomes the exception of the core the unit answers, naming nothing. The failed flush closes
     * the manager, which the registry replaces (EntityManagers).
     *
     * @throws UserAlreadyExistsException when the table refuses the person at one of its unique constraints
     */
    public function save(User $user): void
    {
        try {
            $this->store($user);
        } catch (UniqueConstraintViolationException $exception) {
            throw UserAlreadyExistsException::writtenMeanwhile($exception);
        }
    }
}
