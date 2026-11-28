<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use App\Doctrine\EntityManagers;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Precis\UsernameCaseMapped;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\UsernameUniquenessPendingException;
use Beffroi\Core\Port\CanCountUsersInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use function array_values;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * @extends DoctrineRepository<User>
 */
final readonly class DoctrineUserRepository extends DoctrineRepository implements UserRepositoryInterface, CanCountUsersInterface
{
    public function __construct(
        EntityManagers $managers,
        private TenantBlindIndexes $indexes,
        private BlindIndexDerivations $derivations,
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
     * The tag of the username as written matches a row a reindex left as 0.1 wrote it, and otherwise only a row whose
     * enforced form it is, which the tag of its enforced form matches too.
     */
    public function findByUsername(Tenant $tenant, string $username): ?User
    {
        $column = BlindIndexedColumns::of(User::class, 'username');
        $compared = $this->indexes->of($column)->of($username);
        $asWritten = UsernameCaseMapped::comparisonForm($username) === $username
            ? $compared
            : $this->indexes->of(BlindIndexedColumns::usernameAsWritten())->of($username);
        $found = null;
        foreach ($this->repository()->findBy(['tenant' => $tenant, $column->tag => [$asWritten, $compared]]) as $user) {
            if ($user->usernameIndex === $asWritten) {
                return $user;
            }
            $found = $user;
        }

        return $found;
    }

    public function findAllByEmail(Tenant $tenant, EmailAddress $email): array
    {
        $column = BlindIndexedColumns::of(User::class, 'email');

        return array_values($this->repository()->findBy([
            'tenant' => $tenant,
            $column->tag => $this->indexes->of($column)->of($email->value),
        ]));
    }

    /**
     * beffroi/saml S-56
     *
     * @throws UserAlreadyExistsException
     */
    public function countUsersIn(Tenant $tenant): int
    {
        return (int) $this->queryBuilder('u')
            ->select('COUNT(u.id)')
            ->where('u.tenant = :tenant')
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * @throws UserAlreadyExistsException
     * @throws UsernameUniquenessPendingException
     */
    public function save(User $user): void
    {
        if ($this->namesAnew($user) && ! $this->derivations->isCurrent($user->tenant)) {
            throw new UsernameUniquenessPendingException(sprintf(
                'No person is created or renamed in the tenant "%s" until its usernames are all compared by their enforced form: run "beffroi:user:reindex".',
                $user->tenant->slug,
            ));
        }
        try {
            $this->store($user);
        } catch (UniqueConstraintViolationException $exception) {
            throw UserAlreadyExistsException::writtenMeanwhile($exception);
        }
    }

    /**
     * A person not stored yet, or whose username differs from the one their row holds.
     */
    private function namesAnew(User $user): bool
    {
        $manager = $this->manager();
        if (! $manager->contains($user)) {
            return true;
        }

        return ($manager->getUnitOfWork()->getOriginalEntityData($user)['username'] ?? null) !== $user->username;
    }
}
