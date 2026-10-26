<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use function array_filter;
use function array_keys;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Saml\MappedClaimsWarmer;
use Beffroi\Bundle\Saml\UpstreamIdentityProvidersPass;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Spec/saml.md section 6.10 step 1, S-44, S-45: the upstream identity providers the configuration declares are built
 * when the container is compiled, from what the extension hands their service, so that a declaration that does not
 * hold together, or a domain two of them declare, fails the build of the deployment and not its first refresh or its
 * first sign-in; the claims of the profile are left to the warmer the pass hands them to.
 */
final class UpstreamIdentityProvidersPassTest extends TestCase
{
    private const string ENTITY_ID = 'https://idp.acme.example/saml';

    private const string OTHER = 'https://idp.other.example/saml';

    /**
     * S-44, the acceptance of issue #779: a domain two identity providers of the tenant declare is refused when the
     * container is compiled, naming the key of the configuration, the domain and both providers.
     */
    #[Test]
    public function aDomainDeclaredByTwoIdentityProvidersFailsTheCompilation(): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
            self::OTHER => self::declaration('/srv/saml/other-idp.xml', ['other.example', 'Acme.Example']),
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(sprintf(
            'Invalid configuration for path "beffroi.saml.identity_providers": The domain "acme.example" is declared by the identity providers "%s" and "%s", and a domain answers to one provider (spec/saml.md S-44).',
            self::ENTITY_ID,
            self::OTHER,
        ));

        // When
        new UpstreamIdentityProvidersPass()->process($container);
    }

    /**
     * S-42, M-6: an identity provider declared under an entity ID that is no URI as the model reads one is refused
     * when the container is compiled, by the rule the entity ID of the service provider is held to (ModelEntityId).
     */
    #[Test]
    public function anEntityIdThatIsNoUriFailsTheCompilation(): void
    {
        // Given
        $container = self::container([
            'idp.acme.example' => self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "idp.acme.example": The entity ID of an identity provider is refused (spec/saml.md S-42): A URI is not absolute (M-6).');

        // When
        new UpstreamIdentityProvidersPass()->process($container);
    }

    /**
     * S-42: an identity provider declared under the entity ID of the identity provider of the tenant, the issuer
     * followed by the path of its metadata, is refused when the container is compiled, whether that role is enabled
     * or not.
     */
    #[Test]
    public function theEntityIdOfTheIdentityProviderOfTheTenantFailsTheCompilation(): void
    {
        // Given
        $container = self::container([
            'https://op.test/saml/metadata' => self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "https://op.test/saml/metadata" is declared under the entity ID of the identity provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).');

        // When
        new UpstreamIdentityProvidersPass()->process($container);
    }

    /**
     * S-42, S-38: an identity provider declared under the entity ID of the service provider of the tenant, the URL of
     * its metadata or the one the deployment names, is refused when the container is compiled.
     *
     * @param array<string, mixed>|null $serviceProvider
     */
    #[Test]
    #[DataProvider('provideEntityIdsOfTheServiceProvider')]
    public function theEntityIdOfTheServiceProviderOfTheTenantFailsTheCompilation(?array $serviceProvider, string $entityId): void
    {
        // Given
        $container = self::container([
            $entityId => self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
        ], serviceProvider: $serviceProvider);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(sprintf(
            'Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "%s" is declared under the entity ID of the service provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).',
            $entityId,
        ));

        // When
        new UpstreamIdentityProvidersPass()->process($container);
    }

    /**
     * @return iterable<string, array{?array<string, mixed>, string}>
     */
    public static function provideEntityIdsOfTheServiceProvider(): iterable
    {
        yield 'the URL of its metadata' => [null, 'https://op.test/saml/sp/metadata'];
        yield 'the one the deployment names' => [['entity_id' => 'urn:acme:op:sp'], 'urn:acme:op:sp'];
    }

    /**
     * S-42: what an environment variable says is known to the running deployment only, so an entity ID of the service
     * provider that holds one is compared with nothing when the container is compiled.
     */
    #[Test]
    public function anEntityIdOfTheServiceProviderOfTheEnvironmentIsComparedWithNothing(): void
    {
        // Given
        $container = new ContainerBuilder();
        $entityId = $container->getParameterBag()->get('env(SP_ENTITY_ID)');
        $container = self::container(
            [
                self::ENTITY_ID => self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
            ],
            $container,
            ['entity_id' => $entityId],
        );
        $written = self::declarations($container);

        // When
        new UpstreamIdentityProvidersPass()->process($container);

        // Then
        static::assertSame($written, self::warmed($container));
    }

    /**
     * Section 6.10 step 1: a declaration that does not hold together is refused when the container is compiled,
     * naming the key of the configuration and the identity provider, with the message of the constructor that
     * refused it.
     *
     * @param array<array-key, mixed> $declaration
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatDoNotHoldTogether')]
    public function aDeclarationThatDoesNotHoldTogetherFailsTheCompilation(array $declaration, string $message): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => $declaration,
        ]);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(sprintf(
            'Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "%s": %s',
            self::ENTITY_ID,
            $message,
        ));

        // When
        new UpstreamIdentityProvidersPass()->process($container);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDeclarationsThatDoNotHoldTogether(): iterable
    {
        yield 'a plain http location' => [
            self::declaration('http://idp.acme.example/saml/metadata', ['acme.example']),
            'The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).',
        ];
        yield 'a domain that is none' => [
            self::declaration('/srv/saml/acme-idp.xml', ['acme']),
            '"acme" is no e-mail domain: a name of the DNS of two labels at least, of letters, digits and hyphens, a name outside ASCII written as its A-label.',
        ];
        yield 'a domain declared twice' => [
            self::declaration('/srv/saml/acme-idp.xml', ['acme.example', 'ACME.example']),
            'The domain "acme.example" is declared twice (spec/saml.md S-44).',
        ];
        yield 'an attribute of the subject with a space' => [
            [...self::declaration('/srv/saml/acme-idp.xml', ['acme.example']), 'subject_attribute' => 'object id'],
            'The attribute of the subject is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).',
        ];
        yield 'a value of the groups that names no group' => [
            [...self::declaration('/srv/saml/acme-idp.xml', ['acme.example']), 'groups' => ['attribute' => 'groups', 'map' => ['member' => '']]],
            'The value "member" of the groups names no group (spec/saml.md S-45).',
        ];
        yield 'a parameter of the address that is no token' => [
            [...self::declaration('/srv/saml/acme-idp.xml', ['acme.example']), 'address_parameter' => 'login%5Fhint'],
            'The parameter of the address is one to 64 unreserved characters of RFC 3986 (spec/saml.md S-68).',
        ];
        yield 'a parameter of the address the binding holds' => [
            [...self::declaration('/srv/saml/acme-idp.xml', ['acme.example']), 'address_parameter' => 'relaystate'],
            'The parameter of the address "relaystate" is a parameter of the binding (spec/saml.md S-68).',
        ];
    }

    /**
     * S-45, section 6.10 step 1: the claims the profile holds come from the claims the container builds, so a claim
     * no profile holds compiles, and its declaration is handed to the warmer, which checks the claim right after the
     * compilation.
     */
    #[Test]
    public function theClaimsOfTheProfileAreLeftToTheWarmer(): void
    {
        // Given
        $container = self::container([
            self::ENTITY_ID => [
                ...self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
                'profile' => ['givenName' => 'a_claim_no_profile_holds'],
            ],
        ]);
        $written = self::declarations($container);

        // When
        new UpstreamIdentityProvidersPass()->process($container);

        // Then
        static::assertSame($written, self::warmed($container));
    }

    /**
     * Section 6.10 step 1: a declaration that holds an environment variable is left to its first use, by the
     * compilation and by the warmer, which is handed the others; a domain it shares with another is refused then.
     */
    #[Test]
    public function aDeclarationThatHoldsAnEnvironmentVariableIsLeftToItsFirstUse(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container = self::container([
            self::OTHER => self::declaration($container->getParameterBag()->get('env(IDP_METADATA)'), ['acme.example']),
            self::ENTITY_ID => self::declaration('/srv/saml/acme-idp.xml', ['acme.example']),
        ], $container);

        // When
        new UpstreamIdentityProvidersPass()->process($container);

        // Then
        static::assertSame([self::ENTITY_ID], array_keys(self::warmed($container)));
    }

    /**
     * A container without the service, which a kernel without this bundle's services builds, has nothing to check.
     */
    #[Test]
    public function aContainerWithoutTheIdentityProvidersHasNothingToCheck(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new UpstreamIdentityProvidersPass()->process($container);

        // Then
        static::assertFalse($container->hasDefinition(ConfigurationUpstreamIdentityProviders::class));
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
        $passes = array_filter(
            $container->getCompilerPassConfig()->getBeforeOptimizationPasses(),
            static fn (object $pass): bool => $pass instanceof UpstreamIdentityProvidersPass,
        );
        static::assertCount(1, $passes);
    }

    /**
     * @param list<string> $domains
     *
     * @return array<string, mixed>
     */
    private static function declaration(mixed $location, array $domains): array
    {
        return [
            'metadata' => $location,
            'domains' => $domains,
            'email_attribute' => 'mail',
        ];
    }

    /**
     * The container the extension builds from a configuration that declares these upstream identity providers, the
     * service provider of the tenant enabled with what is given.
     *
     * @param array<array-key, mixed> $identityProviders
     * @param array<string, mixed>|null $serviceProvider
     */
    private static function container(array $identityProviders, ?ContainerBuilder $container = null, ?array $serviceProvider = null): ContainerBuilder
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
                    'service_provider' => $serviceProvider,
                    'identity_providers' => $identityProviders,
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
        $declarations = $container->getDefinition(ConfigurationUpstreamIdentityProviders::class)->getArgument('$definitions');
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
        $declarations = $container->getDefinition(MappedClaimsWarmer::class)->getArgument('$upstreamDeclarations');
        static::assertIsArray($declarations);

        return $declarations;
    }
}
