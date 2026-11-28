<?php

declare(strict_types=1);

namespace App\Command;

use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Group\LocalMemberships;
use Beffroi\Core\Exception\GroupMembershipException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A membership the tenant holds itself taken back (decision 0002): a person taken out of a group the deployment names
 * stops administering the tenant at once (decision 0038). A membership a directory gave is taken back by that
 * directory, the next assertion or the next push writing it again.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Take a user out of a group of the tenant, a membership the tenant holds itself.',
)]
final readonly class GroupRemoveMemberCommand
{
    public const string NAME = 'beffroi:group:remove-member';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private NamedGroup $namedGroups,
        private LocalMemberships $memberships,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The name of the group, exactly as the tenant holds it.')]
        string $group,
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
        $named = $this->namedGroups->orTold($io, $tenant, $group);
        if ($named === null) {
            return Command::FAILURE;
        }

        try {
            $this->memberships->remove($named, $user, $this->contexts->fromConsole(self::NAME));
        } catch (GroupMembershipException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::FAILURE;
        }
        $io->success(sprintf('"%s" is no longer a member of the group "%s".', PrintedText::inBlock($user->username), PrintedText::inBlock($named->name)));

        return Command::SUCCESS;
    }
}
