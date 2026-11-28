<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Author\TheHost;
use App\Http\RequestContextFactory;
use Beffroi\Oidc\Application\Consent\ConsentRevocation;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Take back the consent a user gave a client, and the access it holds; the next authorization request asks again.',
)]
final readonly class UserRevokeConsentCommand
{
    public const string NAME = 'beffroi:user:revoke-consent';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private ClientRepositoryInterface $clients,
        private ConsentRepositoryInterface $consents,
        private ConsentRevocation $revocation,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user, or their identifier.')]
        string $username,
        #[Argument(description: 'The identifier of the client the consent was given to.')]
        string $clientId,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        $client = $this->clients->findByClientId($tenant, $clientId);
        if ($client === null) {
            $io->error(sprintf('No client "%s" is registered with this tenant.', $clientId));

            return Command::INVALID;
        }
        $consent = $this->consents->findActive($user, $client);
        if ($consent === null) {
            $io->note(sprintf('"%s" has granted nothing to "%s"; there is nothing to take back.', $username, $clientId));

            return Command::SUCCESS;
        }
        $this->revocation->revoke($consent, new TheHost(), $this->contexts->fromConsole(self::NAME));
        $io->success(sprintf(
            '"%s" has taken back what "%s" was granted, and what it was issued under it; the next authorization request asks again.',
            $username,
            $clientId,
        ));

        return Command::SUCCESS;
    }
}
