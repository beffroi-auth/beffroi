<?php

declare(strict_types=1);

namespace App\Command;

use App\Doctrine\Role\RuntimeRoleGrants;
use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Grant the role the processes run as what they serve, and no update nor deletion of the chained records but through the retention. Run as the role that owns the tables, after the migrations; the image does it when BEFFROI_MIGRATIONS_DATABASE_URL names that role.',
)]
final readonly class DatabaseGrantCommand
{
    public const string NAME = 'beffroi:database:grant';

    public function __construct(
        private RuntimeRoleGrants $grants,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The role of PostgreSQL the server and the worker connect as.')]
        string $role,
    ): int {
        try {
            $played = $this->grants->grant($role);
        } catch (InvalidArgumentException $refused) {
            $io->error($refused->getMessage());

            return Command::INVALID;
        }
        $io->success(['The role "' . $role . '" is granted what the processes serve, and appends to the chained records without rewriting them:', ...$played]);

        return Command::SUCCESS;
    }
}
