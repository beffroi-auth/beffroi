<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Author\TheHost;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Identity\PersonEnabling;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Enable a person beffroi:user:disable disabled: they may sign in again, every session of theirs having ended with the disabling.',
)]
final readonly class UserEnableCommand
{
    public const string NAME = 'beffroi:user:enable';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private PersonEnabling $enabling,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the person, as "beffroi:user:show" names them.')]
        string $username,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }

        if (! $this->enabling->enable($user, new TheHost(), $this->contexts->fromConsole(self::NAME))) {
            $io->note(sprintf('The user "%s" was enabled already: nothing changed.', PrintedText::inBlock($user->username)));

            return Command::SUCCESS;
        }
        $io->success(sprintf('The user "%s" may sign in again.', PrintedText::inBlock($user->username)));

        return Command::SUCCESS;
    }
}
