<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Model\ModelEntityId;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use function is_string;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The entity ID a deployment names for the service provider of its tenant, checked when the container is compiled
 * (beffroi/saml, spec/saml.md S-38): a URI of M-6 as the model reads one, so that the metadata it names can be
 * written, and never the entity ID of the identity provider of the tenant, the issuer followed by the path of its
 * metadata, which RouterIdentityProviderEndpoints holds it to.
 *
 * Only a compiler pass tells a value from an environment variable, which only the running deployment knows: an entity
 * ID that holds one is left to RouterServiceProviderEndpoints, which applies both rules at its first use, and so is the
 * second rule when the issuer holds one. A deployment that names none goes by the URL of its metadata, which is a URI
 * and is not the identity provider's.
 */
final class ServiceProviderEntityIdPass implements CompilerPassInterface
{
    /**
     * The key the entity ID is written under, which the failure names.
     */
    public const string PATH = 'beffroi.saml.service_provider.entity_id';

    /**
     * @throws InvalidConfigurationException when the entity ID is no URI of M-6, or is the one of the identity provider
     */
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(RouterServiceProviderEndpoints::class)) {
            return;
        }
        $entityId = $container->getDefinition(RouterServiceProviderEndpoints::class)->getArgument('$entityId');
        if (! is_string($entityId) || self::holdsAnEnvironmentVariable($container, $entityId)) {
            return;
        }
        try {
            ModelEntityId::read($entityId);
            $issuer = $container->hasDefinition(TenantFactory::class) ? $container->getDefinition(TenantFactory::class)->getArgument('$issuer') : null;
            if (is_string($issuer) && ! self::holdsAnEnvironmentVariable($container, $issuer)) {
                ServiceProviderEndpoints::assertOwnEntityId($entityId, $issuer . IdentityProviderRoutes::METADATA_PATH);
            }
        } catch (InvalidArgumentException $refusal) {
            throw new InvalidConfigurationException('Invalid configuration for path "' . self::PATH . '": ' . $refusal->getMessage(), 0, $refusal);
        }
    }

    private static function holdsAnEnvironmentVariable(ContainerBuilder $container, string $value): bool
    {
        $environment = [];
        $container->resolveEnvPlaceholders($value, null, $environment);

        return $environment !== [];
    }
}
