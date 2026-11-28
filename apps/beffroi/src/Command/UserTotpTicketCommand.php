<?php

declare(strict_types=1);

namespace App\Command;

use App\Controller\TotpTicketController;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Ticket\TotpTicketIssue;
use Beffroi\Core\Exception\TicketRefusedException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Issue the link that lets a person set up an authenticator app in place of the one they hold, and print it; spending it ends every session of theirs.',
)]
final readonly class UserTotpTicketCommand
{
    public const string NAME = 'beffroi:user:totp-ticket';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private TotpTicketIssue $tickets,
        private RequestContextFactory $contexts,
        private IssuedTicketOutput $output,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the person, as "beffroi:user:show" names them, or their identifier.')]
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

        try {
            $issued = $this->tickets->issue($user, $this->contexts->fromConsole(self::NAME));
        } catch (TicketRefusedException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::INVALID;
        }

        $this->output->print($io, TotpTicketController::ROUTE, $issued);
        $io->success(sprintf(
            'The link is printed once and opens one set-up of an authenticator app; whoever issued it hands it over. Any authenticator app link issued for "%s" before this one opens nothing any more, and spending it revokes the app they held and ends every session of theirs.',
            PrintedText::inBlock($user->username),
        ));

        return Command::SUCCESS;
    }
}
