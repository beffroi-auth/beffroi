<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use function array_filter;
use function array_merge;
use function array_values;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use App\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\CredentialQuestion;
use Beffroi\Core\Domain\Credential\ExternallyIdentifiedCredentialInterface;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Port\CanCountPasswordsHashedAsTypedInterface;
use Beffroi\Core\Port\CanForgetCredentialsInterface;
use Beffroi\Core\Port\CanPageCredentialsInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordsHashedAsTypedInterface;
use function is_a;
use function is_numeric;
use function is_subclass_of;
use function sort;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;
use function usort;

final class DoctrineCredentialRepository implements
    CanCountPasswordsHashedAsTypedInterface,
    CanForgetCredentialsInterface,
    CanPageCredentialsInterface,
    CredentialRepositoryInterface,
    PasswordsHashedAsTypedInterface
{
    /**
     * @var list<class-string<Credential>>|null
     */
    private ?array $kinds = null;

    public function __construct(
        private readonly EntityManagers $managers,
    ) {
    }

    /**
     * @param class-string<Credential> $kind
     *
     * @return Listing<Credential>
     */
    public function pageOfCredentials(User $user, string $kind, CredentialQuestion $question, Pagination $pagination): Listing
    {
        return Listing::of($question->narrow($this->findByUser($user, $kind)), $pagination);
    }

    /**
     * @template T of Credential
     *
     * @param class-string<T> $kind
     *
     * @return list<T>
     */
    public function findByUser(User $user, string $kind = Credential::class): array
    {
        $credentials = [];
        foreach ($this->kinds() as $class) {
            if (! is_a($class, $kind, true)) {
                continue;
            }
            $credentials = array_merge($credentials, $this->managers
                ->forClass($class)
                ->getRepository($class)
                ->findBy([
                    'user' => $user,
                ], [
                    'createdAt' => 'ASC',
                    'id' => 'ASC',
                ]));
        }
        usort($credentials, static fn (Credential $a, Credential $b): int => $a->createdAt <=> $b->createdAt);

        return array_values(array_filter($credentials, static fn (Credential $credential): bool => $credential instanceof $kind));
    }

    public function find(Uuid $id): ?Credential
    {
        foreach ($this->kinds() as $class) {
            $credential = $this->managers->forClass($class)->find($class, $id);
            if ($credential !== null) {
                return $credential;
            }
        }

        return null;
    }

    /**
     * @template T of Credential
     *
     * @param class-string<T> $kind
     *
     * @return T|null
     */
    public function findByExternalId(Tenant $tenant, string $kind, string $externalId): ?Credential
    {
        if (! is_a($kind, ExternallyIdentifiedCredentialInterface::class, true)) {
            throw new InvalidArgumentException(sprintf('A credential of kind "%s" is not presented by an identifier.', $kind));
        }

        return $this->managers
            ->forClass($kind)
            ->getRepository($kind)
            ->findOneBy([
                'tenant' => $tenant,
                'externalId' => $externalId,
            ]);
    }

    public function save(Credential $credential): void
    {
        $manager = $this->managers->forClass($credential::class);
        $manager->persist($credential);
        $manager->flush();
    }

    /**
     * @return iterable<Credential>
     */
    public function credentialsOf(Tenant $tenant): iterable
    {
        foreach ($this->kinds() as $class) {
            $rows = $this->managers
                ->forClass($class)
                ->createQuery(sprintf('SELECT c FROM %s c WHERE c.tenant = :tenant ORDER BY c.createdAt ASC, c.id ASC', $class))
                ->setParameter('tenant', $tenant->id, UuidType::NAME)
                ->toIterable();
            /** @var Credential $credential */
            foreach ($rows as $credential) {
                yield $credential;
            }
        }
    }

    public function forget(Credential $credential): void
    {
        $manager = $this->managers->forClass($credential::class);
        $managed = $manager->find($credential::class, $credential->id);
        if ($managed === null) {
            return;
        }
        $manager->remove($managed);
        $manager->flush();
    }

    public function countIn(Tenant $tenant): int
    {
        $count = $this->managers
            ->forClass(PasswordCredential::class)
            ->createQuery(sprintf('SELECT COUNT(c.id) FROM %s c WHERE c.hashedAsTyped = true AND c.tenant = :tenant', PasswordCredential::class))
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->getSingleScalarResult();

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Through the index beffroi_password_credential_hashed_as_typed, which finds nothing at once when nothing remains.
     */
    public function remainIn(Tenant $tenant): bool
    {
        return $this->managers
            ->forClass(PasswordCredential::class)
            ->createQuery(sprintf('SELECT 1 FROM %s c WHERE c.hashedAsTyped = true AND c.tenant = :tenant', PasswordCredential::class))
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->setMaxResults(1)
            ->getOneOrNullResult() !== null;
    }

    /**
     * @return list<class-string<Credential>>
     */
    private function kinds(): array
    {
        if ($this->kinds !== null) {
            return $this->kinds;
        }
        $kinds = [];
        foreach ($this->managers->all() as $manager) {
            foreach ($manager->getMetadataFactory()->getAllMetadata() as $metadata) {
                if ($metadata instanceof OrmClassMetadata && $metadata->isMappedSuperclass) {
                    continue;
                }
                $class = $metadata->getName();
                if (is_subclass_of($class, Credential::class)) {
                    $kinds[] = $class;
                }
            }
        }
        sort($kinds);

        return $this->kinds = $kinds;
    }
}
