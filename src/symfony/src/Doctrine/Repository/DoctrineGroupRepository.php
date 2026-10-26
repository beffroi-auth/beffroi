<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\GroupAlreadyExistsException;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;

/**
 * The groups of a tenant, in beffroi_group (decision 0002), found by tenant and name as the unique constraint
 * of the table holds them. The name is in clear, a group naming an organisational unit and not a person.
 *
 * @extends DoctrineRepository<Group>
 */
final readonly class DoctrineGroupRepository extends DoctrineRepository implements GroupRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, Group::class);
    }

    public function findByName(Tenant $tenant, string $name): ?Group
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'name' => $name,
        ]);
    }

    /**
     * The unique constraint on (tenant, name) is what refuses a name a concurrent creation wrote after the
     * lookup; the group is the one row the write holds, so the violation is its own. The failed flush closes
     * the manager, which the registry replaces (EntityManagers).
     */
    public function save(Group $group): void
    {
        try {
            $this->store($group);
        } catch (UniqueConstraintViolationException $exception) {
            throw GroupAlreadyExistsException::named($group->name, $exception);
        }
    }
}
