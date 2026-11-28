<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Author\TheHost;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Identity\PersonDisabling;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Disable a person: they can no longer sign in, and every session of theirs ends, its applications told by back-channel logout. To let them sign in again, see beffroi:user:enable.',
)]
final readonly class UserDisableCommand
{
    public const string NAME = 'beffroi:user:disable';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private PersonDisabling $disabling,
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

        $ended = $this->disabling->disable($user, new TheHost(), $this->contexts->fromConsole(self::NAME));
        if ($ended === null) {
            $io->note(sprintf('The user "%s" was disabled already: nothing changed.', PrintedText::inBlock($user->username)));

            return Command::SUCCESS;
        }
        $io->success(sprintf('The user "%s" is disabled, and %d session(s) of theirs ended.', PrintedText::inBlock($user->username), $ended));

        return Command::SUCCESS;
    }
}
