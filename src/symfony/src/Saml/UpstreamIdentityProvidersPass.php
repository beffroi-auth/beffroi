<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use function array_keys;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use function is_array;
use function is_string;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The upstream identity providers the configuration declares, built when the container is compiled (beffroi/saml,
 * spec/saml.md section 6.10 step 1): the service that holds them is built at its first use, the hourly step of the
 * schedule or the first sign-in, and a declaration that does not hold together would fail there, long after the
 * deployment was built. A domain two of them declare is refused here with them (S-44), and so is an identity
 * provider declared under one of the entity IDs of the tenant itself, the one of its identity provider, the issuer
 * followed by the path of its metadata, and the one of its service provider, the one the deployment names or else the
 * issuer followed by the path of its metadata (S-42): an issuer or an entity ID that holds an environment variable
 * leaves the comparison that needs it undone, its value being the running deployment's.
 *
 * The checks are the constructors of the declarations and of the collection, run by building the same object the
 * container builds later, so that no rule is written twice; none of them opens a file or reaches the network. A
 * declaration that holds an environment variable is left to its first use, with what it shares with the others. The
 * claims of the profile (S-45) are checked right after the compilation, in the same build: they come from the claims
 * the container builds, so the declarations are built here with every claim they name held (DeclaredClaims), and
 * handed to MappedClaimsWarmer, which builds them again against the claims of the profile.
 */
final class UpstreamIdentityProvidersPass implements CompilerPassInterface
{
    /**
     * The key the declarations are written under, which the failure names.
     */
    public const string PATH = 'beffroi.saml.identity_providers';

    /**
     * The declarations built as the container builds them, under those claims, for a tenant whose slug plays no part
     * in what a declaration is; what the constructors refuse is the failure of the configuration, naming its key.
     *
     * @param array<array-key, mixed> $declarations by entity ID
     *
     * @throws InvalidConfigurationException when a declaration does not hold together, or two declare one domain
     */
    public static function build(array $declarations, ProfileClaimsInterface $claims): void
    {
        try {
            new ConfigurationUpstreamIdentityProviders('', $declarations, $claims);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidConfigurationException(sprintf('Invalid configuration for path "%s": %s', self::PATH, $exception->getMessage()), 0, $exception);
        }
    }

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(ConfigurationUpstreamIdentityProviders::class)) {
            return;
        }
        $declarations = $container->getDefinition(ConfigurationUpstreamIdentityProviders::class)->getArgument('$definitions');
        if (! is_array($declarations)) {
            return;
        }
        $literal = LiteralDeclarations::of($container, $declarations);
        self::build($literal, DeclaredClaims::filledBy($literal));
        self::refuseTheTenant($container, array_keys($literal));
        $container->getDefinition(MappedClaimsWarmer::class)->setArgument('$upstreamDeclarations', $literal);
    }

    /**
     * S-42: no identity provider declared under an entity ID of the tenant itself.
     *
     * @param list<array-key> $entityIds
     *
     * @throws InvalidConfigurationException
     */
    private static function refuseTheTenant(ContainerBuilder $container, array $entityIds): void
    {
        $issuer = self::literal(
            $container,
            $container->hasDefinition(TenantFactory::class) ? $container->getDefinition(TenantFactory::class)->getArgument('$issuer') : null,
        );
        $named = $container->hasDefinition(RouterServiceProviderEndpoints::class)
            ? $container->getDefinition(RouterServiceProviderEndpoints::class)->getArgument('$entityId')
            : null;
        $identityProvider = self::under($issuer, IdentityProviderRoutes::METADATA_PATH);
        $serviceProvider = $named === null ? self::under($issuer, ServiceProviderRoutes::METADATA_PATH) : self::literal($container, $named);
        try {
            foreach ($entityIds as $entityId) {
                UpstreamIdentityProvider::assertNotTheTenant((string) $entityId, $identityProvider, $serviceProvider);
            }
        } catch (InvalidArgumentException $exception) {
            throw new InvalidConfigurationException(sprintf('Invalid configuration for path "%s": %s', self::PATH, $exception->getMessage()), 0, $exception);
        }
    }

    /**
     * The URL of that path under the issuer, or null when the issuer is not known yet.
     */
    private static function under(?string $issuer, string $path): ?string
    {
        return $issuer === null ? null : $issuer . $path;
    }

    /**
     * The value when it is a string that holds no environment variable, which only the running deployment knows, and
     * null otherwise.
     */
    private static function literal(ContainerBuilder $container, mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }
        $environment = [];
        $container->resolveEnvPlaceholders($value, null, $environment);

        return $environment === [] ? $value : null;
    }
}
