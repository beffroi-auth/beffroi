<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The metadata of the upstream identity providers of the tenant read now (beffroi/saml, spec/saml.md section 6.10):
 * an identity provider declared in the configuration is registered the first time, and refreshed every time after.
 * The hourly step of the schedule does the same thing with the same object (`RefreshTheSamlMetadata`); this is how an
 * operator registers an identity provider the day it is declared, and reads why its metadata were refused.
 *
 * It registers only what the configuration declares: an upstream identity provider is declared in "beffroi.yaml" and
 * nowhere else (S-42), and this command reads its metadata, it does not make one.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Read the metadata of the upstream identity providers the configuration declares, or of one of them, and keep each document accepted; an expired or an older document is refused and the one accepted kept.',
)]
final readonly class SamlIdentityProviderRefreshCommand
{
    public const string NAME = 'beffroi:saml:identity-provider:refresh';

    /**
     * @param MetadataRefresh<UpstreamIdentityProvider> $refresh the refresh of the upstream identity providers
     */
    public function __construct(
        private ConfiguredTenant $tenant,
        private UpstreamIdentityProvidersInterface $identityProviders,
        private MetadataRefresh $refresh,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The entity ID of one identity provider, as "beffroi.saml.identity_providers" declares it; all of them, unless given.')]
        ?string $entityId = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if ($entityId === null) {
            $refreshments = $this->refresh->refreshAll($tenant);
        } else {
            $identityProvider = $this->identityProviders->find($tenant, $entityId);
            if (! $identityProvider instanceof UpstreamIdentityProvider) {
                $io->error(sprintf('The tenant declares no identity provider "%s"; declare it under "beffroi.saml.identity_providers" first.', $entityId));

                return Command::INVALID;
            }
            $refreshments = [$this->refresh->refresh($tenant, $identityProvider)];
        }
        if ($refreshments === []) {
            $io->warning('The tenant declares no identity provider: declare one under "beffroi.saml.identity_providers".');

            return Command::INVALID;
        }

        return MetadataRefreshments::told($io, $refreshments);
    }
}
