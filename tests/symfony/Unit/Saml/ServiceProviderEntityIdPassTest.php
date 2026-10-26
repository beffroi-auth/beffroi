<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Saml\RouterServiceProviderEndpoints;
use Beffroi\Bundle\Saml\ServiceProviderEntityIdPass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Spec/saml.md S-38: the entity ID a deployment names for the service provider of its tenant is checked when the
 * container is compiled, a URI of M-6 that is not the entity ID of the identity provider, so that the deployment fails
 * its build and not the first request for its metadata; a value an environment variable holds is left to the locator,
 * which checks it at its first use.
 */
final class ServiceProviderEntityIdPassTest extends TestCase
{
    private const string ISSUER = 'https://op.test';

    /**
     * S-38, M-6: an entity ID that is no URI of the model, or that is the entity ID of the identity provider, whether
     * the identity provider is enabled or not, fails the compilation, naming the key of the configuration and the
     * rule.
     *
     * @param array<string, mixed> $saml
     */
    #[Test]
    #[DataProvider('provideEntityIdsRefused')]
    public function anEntityIdThatBreaksARuleFailsTheCompilation(array $saml, string $message): void
    {
        // Given
        $container = self::container($saml);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.service_provider.entity_id": ' . $message);

        // When
        new ServiceProviderEntityIdPass()->process($container);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideEntityIdsRefused(): iterable
    {
        $identityProvider = 'The entity ID of the service provider of the tenant, "https://op.test/saml/metadata", is the one of its identity provider: each role is an entity of its own (spec/saml.md S-38).';
        yield 'the entity ID of the identity provider, enabled' => [
            [
                'identity_provider' => null,
                'service_provider' => [
                    'entity_id' => self::ISSUER . '/saml/metadata',
                ],
            ],
            $identityProvider,
        ];
        yield 'the entity ID of the identity provider, left off' => [
            [
                'service_provider' => [
                    'entity_id' => self::ISSUER . '/saml/metadata',
                ],
            ],
            $identityProvider,
        ];
        yield 'no scheme' => [
            [
                'service_provider' => [
                    'entity_id' => 'sp.example',
                ],
            ],
            'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): A URI is not absolute (M-6).',
        ];
        yield 'a format character' => [
            [
                'service_provider' => [
                    'entity_id' => "https://op.test/saml\u{200B}sp",
                ],
            ],
            'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).',
        ];
    }

    /**
     * S-38: an entity ID that is a URI of its own compiles, and reaches the locator as it was written.
     */
    #[Test]
    public function anEntityIdOfItsOwnCompiles(): void
    {
        // Given
        $container = self::container([
            'service_provider' => [
                'entity_id' => 'urn:example:op:service-provider',
            ],
        ]);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertSame('urn:example:op:service-provider', self::locatorEntityId($container));
    }

    /**
     * S-38: an entity ID an environment variable holds is known to the running deployment only, so the container
     * builds and the value reaches the locator, which checks it at its first use.
     */
    #[Test]
    public function anEntityIdOfTheEnvironmentIsLeftToTheLocator(): void
    {
        // Given
        $container = new ContainerBuilder();
        $entityId = $container->getParameterBag()->get('env(SP_ENTITY_ID)');
        $container = self::container([
            'service_provider' => [
                'entity_id' => $entityId,
            ],
        ], $container);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertSame($entityId, self::locatorEntityId($container));
    }

    /**
     * S-38: an issuer an environment variable holds leaves the comparison with the entity ID of the identity provider
     * to the locator, the container building with an entity ID that may be that one, which reaches the locator.
     */
    #[Test]
    public function anIssuerOfTheEnvironmentLeavesTheComparisonToTheLocator(): void
    {
        // Given
        $container = new ContainerBuilder();
        $issuer = $container->getParameterBag()->get('env(ISSUER)');
        static::assertIsString($issuer);
        $container = self::container(
            [
                'service_provider' => [
                    'entity_id' => self::ISSUER . '/saml/metadata',
                ],
            ],
            $container,
            $issuer,
        );

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertSame(self::ISSUER . '/saml/metadata', self::locatorEntityId($container));
    }

    /**
     * S-38: a deployment that names no entity ID goes by the URL of the metadata, a URI that is not the identity
     * provider's: it compiles, the locator handed none.
     */
    #[Test]
    public function anEntityIdLeftOutCompiles(): void
    {
        // Given
        $container = self::container([
            'service_provider' => null,
        ]);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertNull(self::locatorEntityId($container));
    }

    /**
     * S-41: a service provider left off wires no locator, and has no entity ID to check.
     */
    #[Test]
    public function aServiceProviderLeftOffHasNothingToCheck(): void
    {
        // Given
        $container = self::container([]);

        // When
        new ServiceProviderEntityIdPass()->process($container);

        // Then
        static::assertFalse($container->hasDefinition(RouterServiceProviderEndpoints::class));
    }

    /**
     * The pass is one of the bundle's, run by every kernel that builds its container.
     */
    #[Test]
    public function theBundleRunsThePass(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new BeffroiBundle()->build($container);

        // Then
        static::assertCount(1, \array_filter(
            $container->getCompilerPassConfig()->getBeforeOptimizationPasses(),
            static fn (object $pass): bool => $pass instanceof ServiceProviderEntityIdPass,
        ));
    }

    /**
     * A container the extension of the bundle loaded with this SAML configuration, the tenant under the issuer given.
     *
     * @param array<string, mixed> $saml
     */
    private static function container(array $saml, ?ContainerBuilder $container = null, string $issuer = self::ISSUER): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiBundle()->getContainerExtension();
        static::assertNotNull($extension);
        $extension->load([
            [
                'tenant' => [
                    'issuer' => $issuer,
                ],
                'keys' => [
                    'kms' => 'op',
                    'key_id' => 'signing',
                ],
                'saml' => $saml,
            ],
        ], $container);

        return $container;
    }

    private static function locatorEntityId(ContainerBuilder $container): mixed
    {
        return $container->getDefinition(RouterServiceProviderEndpoints::class)->getArgument('$entityId');
    }
}
