<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Uid\Uuid;
use function trim;

final readonly class NamedUser
{
    public function __construct(
        private UserRepositoryInterface $users,
    ) {
    }

    /**
     * An identifier names the person it identifies in the tenant, so that one whose username no lookup finds, set aside
     * by beffroi:user:reindex, is named still.
     */
    public function orTold(SymfonyStyle $io, Tenant $tenant, string $username): ?User
    {
        $name = trim($username);
        $identified = Uuid::isValid($name) ? $this->users->find(Uuid::fromString($name)) : null;
        $user = $identified?->belongsTo($tenant) === true ? $identified : $this->users->findByUsername($tenant, $name);
        if ($user === null) {
            $io->error(sprintf('There is no user named "%s" in the tenant "%s".', $name, $tenant->slug));

            return null;
        }

        return $user;
    }
}
