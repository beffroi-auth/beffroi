<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Application\Identity\Member\UsernameMember;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UsernameRefusedException;
use Beffroi\Core\Exception\UsernameUniquenessPendingException;
use Beffroi\Core\Port\UserRepositoryInterface;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Writes no line of history and no act, as beffroi:user:profile writes none.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Give a person another username, the profile of RFC 8265 refusing what it refuses and no other person of the tenant comparing as it; the person is named by their identifier when two usernames compare as one.',
)]
final readonly class UserRenameCommand
{
    public const string NAME = 'beffroi:user:rename';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private UsernameMember $usernames,
        private UserRepositoryInterface $users,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The identifier of the person, or their username.')]
        string $user,
        #[Argument(description: 'Their new username.')]
        string $username,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $person = $this->namedUsers->orTold($io, $tenant, $user);
        if ($person === null) {
            return Command::FAILURE;
        }
        try {
            $this->usernames->say($person, $username, $this->clock->now());
            $this->users->save($person);
        } catch (InvalidArgumentException|UsernameRefusedException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::INVALID;
        } catch (UserAlreadyExistsException|UsernameUniquenessPendingException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::FAILURE;
        }
        $io->success(sprintf('The person "%s" is named "%s".', $person->id->toRfc4122(), PrintedText::inBlock($person->username)));

        return Command::SUCCESS;
    }
}
