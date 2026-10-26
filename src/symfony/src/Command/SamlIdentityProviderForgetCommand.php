<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Saml\Application\Metadata\AcceptedMetadataForgetting;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The accepted metadata of an upstream identity provider forgotten, by hand (beffroi/saml, spec/saml.md S-6, S-42,
 * section 6.10). The newest document accepted is kept against a rollback, and an identity provider whose metadata are
 * read signed that went back to an earlier document is refused at every refresh, until its accepted document expires;
 * forgetting it is the operator's decision, and the next "beffroi:saml:identity-provider:refresh" registers the
 * identity provider again as a first one.
 *
 * It writes and reads nothing else. It forgets a row, whether the configuration still declares its identity provider
 * or not. An entity ID nothing is accepted for is refused, compared exactly, rather than reported forgotten.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Forget the metadata accepted for an upstream identity provider, so that the next refresh registers it again as a first one; the refresh refuses older documents only against what is accepted.',
)]
final readonly class SamlIdentityProviderForgetCommand
{
    public const string NAME = 'beffroi:saml:identity-provider:forget';

    public function __construct(
        private ConfiguredTenant $tenant,
        private AcceptedMetadataForgetting $forgetting,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The entity ID of the identity provider, compared exactly, as "beffroi.saml.identity_providers" declares it or declared it.')]
        string $entityId,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if (! $this->forgetting->forget($tenant, $entityId)) {
            $io->error(sprintf('No metadata are accepted for the identity provider "%s": nothing is forgotten.', $entityId));

            return Command::INVALID;
        }
        $io->success(sprintf(
            'The metadata accepted for the identity provider "%s" are forgotten; "%s" registers it again as a first one.',
            $entityId,
            SamlIdentityProviderRefreshCommand::NAME,
        ));

        return Command::SUCCESS;
    }
}
