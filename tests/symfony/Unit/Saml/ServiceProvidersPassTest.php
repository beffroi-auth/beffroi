<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Saml\MappedClaimsWarmer;
use Beffroi\Bundle\Saml\ServiceProvidersPass;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Spec/saml.md section 6.2 step 1: the service providers the configuration declares are built when the container is
 * compiled, from what the extension hands their service, so that a declaration that does not hold together fails the
 * build of the deployment and not its first refresh or its first login; the claim of a mapping is left to the warmer
 * the pass hands them to, which checks it right after, in the same build.
 */
final class ServiceProvidersPassTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    /**
     * Section 6.2 step 1: a declaration that does not hold together is refused when the container is compiled, naming
     * the key of the configuration and the service provider, with the message of the constructor that refused it.
     *
     * @param array<array-key, mixed> $declaration
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatDoNotHoldTogether')]
    public function aDeclarationThatDoesNotHoldTogetherFailsTheCompilation(string $entityId, array $declaration, string $message): void
    {
        // Given
        $container = self::container([
            $entityId => $declaration,
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'Invalid configuration for path "beffroi.saml.service_providers": The service provider "%s": %s',
            $entityId,
            $message,
        ));

        // When
        new ServiceProvidersPass()->process($container);
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>, string}>
     */
    public static function provideDeclarationsThatDoNotHoldTogether(): iterable
    {
        yield 'a plain http location' => [
            self::ENTITY_ID,
            ['metadata' => 'http://sp.example.com/saml/metadata'],
            'The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).',
        ];
        yield 'an entity ID that holds whitespace' => [
            'https://sp.example.com/my saml',
            ['metadata' => 'https://sp.example.com/saml/metadata'],
            'The entity ID of a service provider is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md section 6.2 step 1).',
        ];
        yield 'a signer that is no certificate' => [
            self::ENTITY_ID,
            ['metadata' => 'https://sp.example.com/saml/metadata', 'metadata_signers' => ['not a certificate']],
            'A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).',
        ];
        yield 'an attribute of the uri format whose name is no URI' => [
            self::ENTITY_ID,
            ['metadata' => 'https://sp.example.com/saml/metadata', 'attributes' => ['mail' => ['claim' => 'email']]],
            'An attribute name of the uri format is an absolute URI (Core section 8.2.2, spec/saml.md section 6.2 step 1).',
        ];
    }

    /**
     * Section 6.2 step 1: a declaration that holds together compiles, and reaches its service as it was written.
     */
    #[Test]
    public function aDeclarationThatHoldsTogetherCompiles(): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
                'attributes' => [
                    'urn:oid:0.9.2342.19200300.100.1.3' => [
                        'claim' => 'email',
                    ],
                ],
            ],
        ]);
        $written = self::declarations($container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame($written, self::declarations($container));
    }

    /**
     * S-16, section 6.2 step 1: the claims the provider serves come from the claims providers the container builds, so
     * a mapping of a claim no provider serves compiles, and its declaration is handed to the warmer, which checks the
     * claim right after the compilation.
     */
    #[Test]
    public function theClaimOfAMappingIsLeftToTheWarmer(): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
                'attributes' => [
                    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => [
                        'claim' => 'a_claim_no_provider_serves',
                    ],
                ],
            ],
        ]);
        $written = self::declarations($container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame($written, self::warmed($container));
    }

    /**
     * Section 6.2 step 1: what an environment variable says is known to the running deployment only, so a declaration
     * that holds one is left to its first use.
     */
    #[Test]
    public function aDeclarationThatHoldsAnEnvironmentVariableIsLeftToItsFirstUse(): void
    {
        // Given
        $container = new ContainerBuilder();
        $location = $container->getParameterBag()->get('env(SP_METADATA)');
        $container = self::container([
            self::ENTITY_ID => [
                'metadata' => $location,
            ],
        ], $container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame($location, self::declarations($container)[self::ENTITY_ID]['metadata'] ?? null);
    }

    /**
     * Section 6.2 step 1: a declaration that holds an environment variable is left to its first use by the warmer too,
     * which is handed the others.
     */
    #[Test]
    public function aDeclarationThatHoldsAnEnvironmentVariableIsNotHandedToTheWarmer(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container = self::container([
            'https://env.example.com/saml' => [
                'metadata' => $container->getParameterBag()->get('env(SP_METADATA)'),
            ],
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
            ],
        ], $container);

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertSame([self::ENTITY_ID], \array_keys(self::warmed($container)));
    }

    /**
     * The other declarations are built whatever one of them holds: a declaration that does not hold together beside
     * one that waits for the environment still fails the compilation.
     */
    #[Test]
    public function aDeclarationThatDoesNotHoldTogetherBesideOneOfTheEnvironmentFails(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container = self::container([
            'https://env.example.com/saml' => [
                'metadata' => $container->getParameterBag()->get('env(SP_METADATA)'),
            ],
            self::ENTITY_ID => [
                'metadata' => 'http://sp.example.com/saml/metadata',
            ],
        ], $container);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The service provider "https://sp.example.com/saml": The metadata of a service provider or of an identity provider are read from an https URL');

        // When
        new ServiceProvidersPass()->process($container);
    }

    /**
     * A container without the service, which a kernel without this bundle's services builds, has nothing to check.
     */
    #[Test]
    public function aContainerWithoutTheServiceProvidersHasNothingToCheck(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new ServiceProvidersPass()->process($container);

        // Then
        static::assertFalse($container->hasDefinition(ConfigurationServiceProviders::class));
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
        $passes = \array_filter(
            $container->getCompilerPassConfig()->getBeforeOptimizationPasses(),
            static fn (object $pass): bool => $pass instanceof ServiceProvidersPass,
        );
        static::assertCount(1, $passes);
    }

    /**
     * The container the extension builds from a configuration that declares these service providers.
     *
     * @param array<array-key, mixed> $serviceProviders
     */
    private static function container(array $serviceProviders, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiBundle()->getContainerExtension();
        static::assertNotNull($extension);
        $extension->load([
            [
                'tenant' => [
                    'issuer' => 'https://op.test',
                ],
                'keys' => [
                    'kms' => 'op',
                    'key_id' => 'signing',
                ],
                'saml' => [
                    'identity_provider' => null,
                    'service_providers' => $serviceProviders,
                ],
            ],
        ], $container);

        return $container;
    }

    /**
     * @return array<array-key, array<array-key, mixed>>
     */
    private static function declarations(ContainerBuilder $container): array
    {
        $declarations = $container->getDefinition(ConfigurationServiceProviders::class)->getArgument('$definitions');
        static::assertIsArray($declarations);

        /** @var array<array-key, array<array-key, mixed>> $declarations */
        return $declarations;
    }

    /**
     * The declarations the pass handed the warmer.
     *
     * @return array<array-key, mixed>
     */
    private static function warmed(ContainerBuilder $container): array
    {
        $declarations = $container->getDefinition(MappedClaimsWarmer::class)->getArgument('$declarations');
        static::assertIsArray($declarations);

        return $declarations;
    }
}
