<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use function array_map;
use function implode;
use function sprintf;
use Psr\Clock\ClockInterface;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'List the sessions open in the name of a user, with what each one proved and where it was last seen.',
)]
final readonly class UserSessionsCommand
{
    public const string NAME = 'beffroi:user:sessions';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private AuthenticationSessionRepositoryInterface $sessions,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user, or their identifier.')]
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
        $sessions = $this->sessions->findActiveByUser($user, $this->clock->now());
        if ($sessions === []) {
            $io->text(sprintf('No session is open in the name of "%s".', PrintedText::of($user->username)));

            return Command::SUCCESS;
        }
        $io->title(sprintf('Sessions of "%s"', PrintedText::of($user->username)));
        $io->table(
            ['Identifier', 'Proved', 'Opened', 'Last seen', 'From'],
            array_map(static fn (AuthenticationSession $session): array => [
                $session->id->toString(),
                $session->authenticationContextClass()->value . ' (' . implode(' ', $session->proofs->methodReferences()) . ')',
                $session->establishedAt->format('Y-m-d H:i:s'),
                $session->lastSeenAt->format('Y-m-d H:i:s'),
                $session->lastSeenFrom->ipAddress ?? 'address not recorded',
            ], $sessions),
        );

        return Command::SUCCESS;
    }
}
