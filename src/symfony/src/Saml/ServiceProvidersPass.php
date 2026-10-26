<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Port\ServedClaimsInterface;
use function is_array;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The service providers the configuration declares, built when the container is compiled (beffroi/saml, spec/saml.md
 * section 6.2 step 1): the service that holds them is built at its first use, the hourly step of the schedule or the
 * first login, and a declaration that does not hold together would fail there, long after the deployment was built.
 *
 * The checks are the constructors of the declaration, run by building the same object the container builds later, so
 * that no rule is written twice; none of them opens a file or reaches the network, a container being built before
 * the metadata it names exist. A declaration that holds an environment variable is left to its first use: what the
 * variable says is known to the running deployment only. The claim of a mapping (S-16) is checked right after the
 * compilation, in the same build: the claims the provider serves come from the claims providers the container builds,
 * so the declarations are built here with every claim they map served (DeclaredClaims), and handed to
 * MappedClaimsWarmer, which builds them again against the claims the provider serves.
 */
final class ServiceProvidersPass implements CompilerPassInterface
{
    /**
     * The key the declarations are written under, which the failure names.
     */
    public const string PATH = 'beffroi.saml.service_providers';

    /**
     * The declarations built as the container builds them, under those claims, for a tenant whose slug plays no part
     * in what a declaration is; what the constructors refuse is the failure of the configuration, naming its key.
     *
     * @param array<array-key, mixed> $declarations by entity ID
     *
     * @throws InvalidConfigurationException when a declaration does not hold together
     */
    public static function build(array $declarations, ServedClaimsInterface $claims): void
    {
        try {
            new ConfigurationServiceProviders('', $declarations, $claims);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidConfigurationException(sprintf('Invalid configuration for path "%s": %s', self::PATH, $exception->getMessage()), 0, $exception);
        }
    }

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(ConfigurationServiceProviders::class)) {
            return;
        }
        $declarations = $container->getDefinition(ConfigurationServiceProviders::class)->getArgument('$definitions');
        if (! is_array($declarations)) {
            return;
        }
        $literal = LiteralDeclarations::of($container, $declarations);
        self::build($literal, DeclaredClaims::mappedBy($literal));
        $container->getDefinition(MappedClaimsWarmer::class)->setArgument('$declarations', $literal);
    }
}
