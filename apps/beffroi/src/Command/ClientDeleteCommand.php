<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Author\TheHost;
use App\Http\RequestContextFactory;
use Beffroi\Oidc\Application\Client\Registration\RegisteredClientRemoval;
use Beffroi\Oidc\Port\ClientStoreInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Delete a client that registered itself; a client declared in the configuration is refused.',
)]
final readonly class ClientDeleteCommand
{
    public const string NAME = 'beffroi:client:delete';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedClient $namedClients,
        private ClientStoreInterface $store,
        private RegisteredClientRemoval $removal,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The identifier of the client, as "beffroi:client:list" shows it.')]
        string $clientId,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $client = $this->namedClients->orTold($io, $tenant, $clientId);
        if ($client === null) {
            return Command::FAILURE;
        }
        if (! $client->wasRegisteredHere()) {
            $io->error(sprintf(
                'The client "%s" is declared in the configuration of the deployment, so this provider cannot take it back; remove its block from "beffroi.yaml" instead.',
                $client->clientId,
            ));

            return Command::INVALID;
        }
        $record = $this->store->findRecord($tenant, $client->clientId);
        if ($record === null) {
            $io->error(sprintf('The client "%s" is gone already.', $client->clientId));

            return Command::FAILURE;
        }

        $this->removal->remove($record, new TheHost(), $this->contexts->fromConsole(self::NAME));
        $io->success(sprintf(
            'The client "%s" is deleted; nothing it was issued can be spent any more.',
            $client->clientId,
        ));

        return Command::SUCCESS;
    }
}
