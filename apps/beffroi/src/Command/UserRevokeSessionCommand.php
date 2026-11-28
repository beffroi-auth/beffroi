<?php

declare(strict_types=1);

namespace App\Command;

use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Uid\Uuid;
use function trim;

#[AsCommand(
    name: self::NAME,
    description: 'End a session of a user by its identifier; the relying parties of that session are told by the back-channel.',
)]
final readonly class UserRevokeSessionCommand
{
    public const string NAME = 'beffroi:user:revoke-session';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionTerminator $terminator,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user, or their identifier.')]
        string $username,
        #[Argument(description: 'The identifier of the session, as "beffroi:user:sessions" lists it.')]
        string $id,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if (! Uuid::isValid(trim($id))) {
            $io->error(sprintf('"%s" is not the identifier of a session.', trim($id)));

            return Command::INVALID;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        $session = $this->sessions->find(Uuid::fromString(trim($id)));
        if ($session === null || ! $session->user->id->equals($user->id)) {
            $io->error(sprintf('The user "%s" has no session "%s".', PrintedText::inBlock($user->username), trim($id)));

            return Command::FAILURE;
        }
        if ($session->hasEnded()) {
            $io->warning(sprintf('That session ended on %s already.', $session->endedAt?->format('Y-m-d H:i:s')));

            return Command::SUCCESS;
        }

        $this->terminator->end($session, SessionEnd::User, $this->contexts->fromConsole(self::NAME));
        $io->success(sprintf('The session "%s" of "%s" is ended.', trim($id), PrintedText::inBlock($user->username)));

        return Command::SUCCESS;
    }
}
