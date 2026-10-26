<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Port\ServiceProvidersInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The metadata of the service providers of the tenant read now (beffroi/saml, spec/saml.md section 6.2): a service
 * provider declared in the configuration is registered the first time, and refreshed every time after. The hourly
 * step of the schedule does the same thing with the same object (`RefreshTheSamlMetadata`); this is how an
 * operator registers a service provider the day it is declared, and reads why its metadata were refused.
 *
 * It registers only what the configuration declares: a service provider is declared in "beffroi.yaml" and nowhere
 * else (S-5), and this command reads its metadata, it does not make one.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Read the metadata of the service providers the configuration declares, or of one of them, and keep each document accepted; an expired or an older document is refused and the one accepted kept.',
)]
final readonly class SamlServiceProviderRefreshCommand
{
    public const string NAME = 'beffroi:saml:service-provider:refresh';

    /**
     * @param MetadataRefresh<ServiceProvider> $refresh the refresh of the service providers
     */
    public function __construct(
        private ConfiguredTenant $tenant,
        private ServiceProvidersInterface $serviceProviders,
        private MetadataRefresh $refresh,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The entity ID of one service provider, as "beffroi.saml.service_providers" declares it; all of them, unless given.')]
        ?string $entityId = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if ($entityId === null) {
            $refreshments = $this->refresh->refreshAll($tenant);
        } else {
            $serviceProvider = $this->serviceProviders->find($tenant, $entityId);
            if (! $serviceProvider instanceof ServiceProvider) {
                $io->error(sprintf('The tenant declares no service provider "%s"; declare it under "beffroi.saml.service_providers" first.', $entityId));

                return Command::INVALID;
            }
            $refreshments = [$this->refresh->refresh($tenant, $serviceProvider)];
        }
        if ($refreshments === []) {
            $io->warning('The tenant declares no service provider: declare one under "beffroi.saml.service_providers".');

            return Command::INVALID;
        }
        return MetadataRefreshments::told($io, $refreshments);
    }
}
