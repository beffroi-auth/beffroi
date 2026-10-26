<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\RefreshTheSamlMetadata;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Exception;
use function array_keys;
use Psr\Log\LoggerInterface;
use function sprintf;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * The hourly refresh of the metadata of the SAML peers of the tenant (beffroi/saml, spec/saml.md sections 6.2 and
 * 6.10), every role in the order it is wired, each by the same object its console command calls
 * (`beffroi:saml:service-provider:refresh`, `beffroi:saml:identity-provider:refresh`): what differs is who reads the
 * outcome, a terminal there and a log here. A role is one refresh tagged, and nothing here names one.
 *
 * It fails nothing. A location that cannot be reached and a document refused are written to the log as errors, the
 * level an operator is alerted on, and taken again at the next tick, the document accepted serving meanwhile, until
 * its own validUntil refuses it (spec/saml.md S-6): a refusal nobody reads would keep that document for as long. Each
 * role is read apart from the others, its refresh built when it is read: declarations that hold an environment
 * variable are refused when the service that holds them is built, at its first use, and a role refused so is written
 * to the log as an error, naming its refresh, before the next role is read (section 6.10).
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class RefreshTheSamlMetadataHandler
{
    /**
     * The tag of the refresh of each role.
     */
    public const string TAG = 'beffroi.saml.metadata_refresh';

    /**
     * @param ServiceProviderInterface<MetadataRefresh<covariant PeerInterface>> $refreshes the refresh of every role, by its id
     */
    public function __construct(
        private TenantProvider $tenants,
        private ServiceProviderInterface $refreshes,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(RefreshTheSamlMetadata $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no tenant to serve, and a tick is not the place to say so
            return;
        }
        foreach (array_keys($this->refreshes->getProvidedServices()) as $role) {
            try {
                $refreshments = $this->refreshes->get($role)->refreshAll($tenant);
            } catch (Exception $refusal) {
                $this->logger->error(sprintf(
                    'The SAML metadata of the role "%s" could not be refreshed, the next role is read: %s was thrown: %s',
                    $role,
                    $refusal::class,
                    $refusal->getMessage(),
                ));
                continue;
            }
            foreach ($refreshments as $refreshment) {
                if ($refreshment->refused) {
                    $this->logger->error($refreshment->what);
                    continue;
                }
                $this->logger->info($refreshment->what);
            }
        }
    }
}
