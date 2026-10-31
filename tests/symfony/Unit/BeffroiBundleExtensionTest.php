<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit;

use DateInterval;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Configuration\SamlSection;
use Beffroi\Bundle\Configuration\SelfClientSection;
use Beffroi\Bundle\Configuration\WebPushSection;
use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Key\StagingDelay;
use Beffroi\Bundle\Saml\JoseSamlEncryptionAlgorithms;
use Beffroi\Bundle\Saml\RouterServiceProviderEndpoints;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Vapid;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use function array_map;
use Beffroi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Application\Upstream\AssertionConsumerService;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * What the extension hands the services from the configuration, read on the definitions before the
 * container is compiled: the values of "beffroi.tokens" become the DateIntervals of the use cases, the
 * values of "beffroi.keys" and "beffroi.tenant" the arguments of the bridges.
 */
final class BeffroiBundleExtensionTest extends TestCase
{
    #[Test]
    public function theLifetimesOfTheConfigurationReachTheUseCases(): void
    {
        // When
        $container = self::load([
            'tokens' => [
                'authorization_code_ttl' => 45,
                'access_token_ttl' => 300,
                'id_token_ttl' => 120,
                'refresh_token_ttl' => 1000,
                'refresh_token_absolute_ttl' => 2000,
            ],
        ]);

        // Then
        static::assertSame('PT45S', self::interval($container, AuthorizationCodeIssuer::class, '$lifetime'));
        static::assertSame('PT300S', self::interval($container, JwtAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT300S', self::interval($container, OpaqueAccessTokenIssuer::class, '$lifetime'));
        static::assertSame('PT120S', self::interval($container, JwtIdTokenIssuer::class, '$lifetime'));
        static::assertSame('PT1000S', self::interval($container, TokenIssuer::class, '$refreshTokenLifetime'));
        static::assertSame('PT2000S', self::interval($container, AuthorizationCodeGrant::class, '$refreshTokenFamilyLifetime'));
    }

    #[Test]
    public function theTenantAndTheKeysReachTheBridges(): void
    {
        // When
        $container = self::load([
            'tenant' => [
                'issuer' => 'https://op.test/tenant-a',
                'slug' => 'tenant-a',
                'name' => 'Tenant A',
            ],
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'storage' => '/var/lib/beffroi/keys',
            ],
        ]);

        // Then
        $factory = $container->getDefinition(TenantFactory::class);
        static::assertSame('https://op.test/tenant-a', $factory->getArgument('$issuer'));
        static::assertSame('tenant-a', $factory->getArgument('$slug'));
        static::assertSame('Tenant A', $factory->getArgument('$name'));
        static::assertSame('key_management.op', (string) $container->getAlias('beffroi.kms'));
        static::assertSame('k', $container->getDefinition(EnvelopeKeySealer::class)->getArgument('$kmsKeyId'));
        static::assertSame('/var/lib/beffroi/keys', $container->getDefinition(FileTenantKeyRepository::class)->getArgument('$directory'));
    }

    /**
     * Architecture §3.3: the staging delay derives from the JWK Set max-age unless the configuration sets
     * it; the derivation happens at runtime, so that an environment placeholder can stand for either.
     */
    #[Test]
    public function theStagingDelayDerivesFromTheJwksMaxAgeUnlessSet(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'jwks_max_age' => 120,
            ],
        ]);

        // Then
        $delay = $container->getDefinition('beffroi.keys.rotation_schedule')->getArgument(0);
        static::assertInstanceOf(Definition::class, $delay);
        $factory = $delay->getFactory();
        static::assertIsArray($factory);
        static::assertSame(StagingDelay::class, $factory[0]);
        static::assertSame('interval', $factory[1]);
        static::assertSame([null, 120], $delay->getArguments());
    }

    #[Test]
    public function aConfiguredStagingDelayReachesTheJoseFamilies(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'k',
                'jwks_max_age' => 120,
                'staging_delay' => 30,
            ],
        ]);

        // Then
        $delay = $container->getDefinition('beffroi.keys.rotation_schedule')->getArgument(0);
        static::assertInstanceOf(Definition::class, $delay);
        static::assertSame([30, 120], $delay->getArguments());
    }

    /**
     * Decision 0009: what a tenant does with a client that registers itself reaches the bridge that
     * answers for that tenant, the mode it names and the two durations it keeps a client for.
     */
    #[Test]
    public function theRegistrationPolicyOfTheConfigurationReachesTheBridge(): void
    {
        // When
        $container = self::load([
            'client_registration' => [
                'mode' => OpenRegistrationAuthorization::MODE,
                'exempt_confidential_clients_from_pkce' => true,
                'keep_a_client_unused_for' => 86400,
                'keep_a_client_never_used_for' => 3600,
            ],
        ]);

        // Then
        $policies = $container->getDefinition(ConfigurationClientRegistrationPolicy::class);
        static::assertSame(OpenRegistrationAuthorization::MODE, $policies->getArgument('$mode'));
        static::assertTrue($policies->getArgument('$exemptsConfidentialClientsFromPkce'));
        static::assertSame('PT86400S', self::interval($container, ConfigurationClientRegistrationPolicy::class, '$keepsAClientUnusedFor'));
        static::assertSame('PT3600S', self::interval($container, ConfigurationClientRegistrationPolicy::class, '$keepsAClientNeverUsedFor'));
    }

    /**
     * Decision 0009: closed is the default, and the mode is a value of one tenant's policy: there is no
     * key here, whatever its name, that opens a registration endpoint for a deployment. What a deployment
     * that writes nothing hands the bridge is no mode at all, which is no policy and no endpoint.
     */
    #[Test]
    public function aDeploymentThatWritesNothingHandsTheBridgeNoMode(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertNull($container->getDefinition(ConfigurationClientRegistrationPolicy::class)->getArgument('$mode'));
    }

    #[Test]
    public function theClientsReachTheConfigurationRepository(): void
    {
        // When
        $container = self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
        ]);

        // Then
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertSame(['app'], array_keys($clients));
    }

    /**
     * Issue #282: the application that hosts the bundle is a client of a source of its own, a declaration of the
     * configuration like the clients beside it, built once the router can write the URLs of its routes.
     */
    #[Test]
    public function theClientOfTheApplicationIsASourceOfItsOwn(): void
    {
        // When
        $container = self::load([
            'self_client' => [
                'redirect_route' => 'app_oidc_callback',
                'secret' => '%env(APP_OIDC_SECRET)%',
            ],
        ]);

        // Then
        $source = $container->getDefinition(SelfClientSection::SOURCE);
        static::assertSame(ConfigurationClientRepository::class, $source->getClass());
        static::assertArrayHasKey('beffroi.oidc.client_source', $source->getTags());
        static::assertArrayHasKey('beffroi.oidc.client_inventory', $source->getTags());
    }

    #[Test]
    public function anApplicationThatDeclaresNoClientIsNone(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertFalse($container->hasDefinition(SelfClientSection::SOURCE));
    }

    /**
     * One identifier is one client of the tenant: the application does not take the identifier of a client the
     * deployment declares beside it, whose source would answer for it first.
     */
    #[Test]
    public function theApplicationDoesNotTakeTheIdentifierOfADeclaredClient(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "self_client.client_id" names "app", a client "clients" declares as well: one identifier is one client of the tenant.');

        // When
        self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
            'self_client' => [
                'redirect_route' => 'app_oidc_callback',
                'secret' => '%env(APP_OIDC_SECRET)%',
            ],
        ]);
    }

    /**
     * Architecture §4.6: the shape is a per-client option. The tree reads the name and nothing else; a
     * client that names none leaves it to the wiring, which is what knows the shapes and their order.
     */
    #[Test]
    public function theAccessTokenShapeOfAClientIsRead(): void
    {
        // When
        $container = self::load([
            'clients' => [
                'app' => [
                    'redirect_uris' => ['https://app.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                ],
                'api-app' => [
                    'redirect_uris' => ['https://api.test/cb'],
                    'token_endpoint_auth_method' => 'none',
                    'access_token_format' => 'opaque',
                ],
            ],
        ]);

        // Then
        $clients = $container->getDefinition(ConfigurationClientRepository::class)->getArgument('$definitions');
        static::assertIsArray($clients);
        static::assertIsArray($clients['app']);
        static::assertIsArray($clients['api-app']);
        static::assertNull($clients['app']['access_token_format']);
        static::assertSame('opaque', $clients['api-app']['access_token_format']);
    }

    /**
     * Architecture §4.6: one class per shape, tagged, and the shape it writes is the issuer's own
     * business; the wiring holds an order and no name (issue #239).
     */
    #[Test]
    public function theAccessTokenIssuersAreTaggedAndNothingNamesTheirShape(): void
    {
        // When
        $container = self::load([]);

        // Then
        foreach ([JwtAccessTokenIssuer::class, OpaqueAccessTokenIssuer::class] as $issuer) {
            static::assertArrayHasKey('beffroi.oidc.access_token_issuer', $container->getDefinition($issuer)->getTags());
        }
        foreach ([JwtAccessTokenVerifier::class, OpaqueAccessTokenVerifier::class] as $verifier) {
            static::assertArrayHasKey('beffroi.oidc.access_token_verifier', $container->getDefinition($verifier)->getTags());
        }
    }

    /**
     * Architecture §5.2: a process serves both planes unless BEFFROI_PLANE says otherwise.
     */
    #[Test]
    public function theDefaultPlaneIsBoth(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertSame('all', $container->getParameterBag()->all()['env(BEFFROI_PLANE)']);
    }

    /**
     * The application may set the default plane of its processes itself; the bundle does not override it.
     */
    #[Test]
    public function theApplicationKeepsItsOwnDefaultPlane(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->setParameter('env(BEFFROI_PLANE)', 'protocol');

        // When
        self::load([], $container);

        // Then
        static::assertSame('protocol', $container->getParameterBag()->all()['env(BEFFROI_PLANE)']);
    }

    /**
     * Decisions 0011 and 0018: what registers the encrypted types runs while the bundles boot, and what it
     * is handed is the encrypter of the sealed columns, so an encrypter built there would build the store,
     * the connection and the KMS client of every process that boots. It is lazy, and public because a
     * private service with one consumer is inlined and an inlined service is not a proxy.
     */
    #[Test]
    public function theEncrypterOfTheSealedColumnsIsLazySoThatABootReachesNoKms(): void
    {
        // When
        $container = self::load([]);

        // Then
        $encrypter = $container->getDefinition('beffroi.personal_data.encrypter');
        static::assertTrue($encrypter->isLazy());
        static::assertTrue($encrypter->isPublic());
    }

    /**
     * Spec/saml.md S-64: the key files read past the key of an upstream identity provider nothing wires any more, every
     * algorithm of that family named "SAML-ENCRYPTION:" and the entity ID of its provider.
     */
    #[Test]
    public function theKeyOfAProviderNothingWiresIsDormant(): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertSame([SamlEncryptionAlgorithmInterface::NAME_PREFIX], $container->getDefinition(DormantKeyAlgorithms::class)->getArgument(1));
    }

    /**
     * Spec/saml.md S-40, S-41, decision 0030: each SAML role reaches its switch as the configuration writes it, which the
     * container reads when it builds what the role changes.
     *
     * @param array<string, mixed> $saml
     * @param array{bool, bool} $on whether the identity provider and the service provider are
     */
    #[Test]
    #[DataProvider('provideRoles')]
    public function eachSamlRoleReachesItsSwitchAsTheConfigurationWritesIt(array $saml, array $on): void
    {
        // When
        $container = self::load([
            'saml' => $saml,
        ]);

        // Then
        static::assertSame($on, [
            $container->getDefinition(SamlSection::IDENTITY_PROVIDER_ROLE)->getArgument(0),
            $container->getDefinition(SamlSection::SERVICE_PROVIDER_ROLE)->getArgument(0),
        ]);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, array{bool, bool}}>
     */
    public static function provideRoles(): iterable
    {
        yield 'neither' => [[], [false, false]];
        yield 'the identity provider alone' => [
            [
                'identity_provider' => null,
            ],
            [true, false],
        ];
        yield 'the service provider alone' => [
            [
                'service_provider' => null,
            ],
            [false, true],
        ];
        yield 'both' => [
            [
                'identity_provider' => null,
                'service_provider' => null,
            ],
            [true, true],
        ];
    }

    /**
     * Spec/saml.md S-41: what the consumers of a service of a role are handed under the name of its class is what the
     * role builds, the service while it is on and none while it is off, the route of the role being wired in every
     * image.
     */
    #[Test]
    #[DataProvider('provideServicesOfARole')]
    public function theServiceOfARoleIsHandedOverByItsRole(string $class, string $role): void
    {
        // When
        $container = self::load([]);

        // Then
        static::assertEquals([new Reference($role), 'served'], $container->getDefinition($class)->getFactory());
    }

    /**
     * @return iterable<string, array{class-string, string}>
     */
    public static function provideServicesOfARole(): iterable
    {
        yield 'the metadata of the identity provider' => [IdentityProviderMetadataHandler::class, SamlSection::IDENTITY_PROVIDER_ROLE];
        yield 'the metadata of the service provider' => [ServiceProviderMetadataHandler::class, SamlSection::SERVICE_PROVIDER_ROLE];
        yield 'the sign-on at an upstream identity provider' => [UpstreamSignOn::class, SamlSection::SERVICE_PROVIDER_ROLE];
        yield 'the assertion consumer service' => [AssertionConsumerService::class, SamlSection::SERVICE_PROVIDER_ROLE];
    }

    /**
     * Architecture §5.6: naming a subject is what turns web push on, the subject reaching the role of web push as the
     * configuration writes it, and none naming none.
     */
    #[Test]
    #[DataProvider('provideWebPushSubjects')]
    public function theSubjectOfWebPushReachesItsRole(mixed $webPush, ?string $subject): void
    {
        // When
        $container = self::load([
            'web_push' => $webPush,
        ]);

        // Then
        static::assertSame($subject, $container->getDefinition(WebPushSection::ROLE)->getArgument(0));
    }

    /**
     * @return iterable<string, array{mixed, ?string}>
     */
    public static function provideWebPushSubjects(): iterable
    {
        yield 'none' => [[], null];
        yield 'a subject' => [
            [
                'subject' => 'mailto:operator@op.test',
            ],
            'mailto:operator@op.test',
        ];
    }

    /**
     * Spec/saml.md S-38: the entity ID the deployment names for its service provider reaches the locator of its
     * endpoints, and none leaves it to the URL of the metadata.
     */
    #[Test]
    #[DataProvider('provideServiceProviderEntityIds')]
    public function theEntityIdOfTheServiceProviderReachesItsLocator(mixed $serviceProvider, ?string $entityId): void
    {
        // When
        $container = self::load([
            'saml' => [
                'service_provider' => $serviceProvider,
            ],
        ]);

        // Then
        static::assertSame($entityId, $container->getDefinition(RouterServiceProviderEndpoints::class)->getArgument('$entityId'));
    }

    /**
     * @return iterable<string, array{mixed, ?string}>
     */
    public static function provideServiceProviderEntityIds(): iterable
    {
        yield 'the URL of the metadata' => [null, null];
        yield 'one the deployment names' => [
            [
                'entity_id' => 'urn:example:op:service-provider',
            ],
            'urn:example:op:service-provider',
        ];
    }

    /**
     * Spec/saml.md S-38: an entity ID of the service provider that is no string is refused when the configuration is
     * read, rather than read as none and the service provider named by the URL of its metadata.
     */
    #[Test]
    #[DataProvider('provideEntityIdsThatAreNoString')]
    public function anEntityIdOfTheServiceProviderThatIsNoStringIsRefused(mixed $entityId, string $type): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains(\sprintf(
            'Invalid type for path "beffroi.saml.service_provider.entity_id". Expected "string", but got "%s".',
            $type,
        ));

        // When
        self::load([
            'saml' => [
                'service_provider' => [
                    'entity_id' => $entityId,
                ],
            ],
        ]);
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideEntityIdsThatAreNoString(): iterable
    {
        yield 'a number' => [12_345, 'int'];
        yield 'a boolean' => [true, 'bool'];
    }

    /**
     * Spec/saml.md S-12, S-40, section 5.1: the metadata of the service provider are handed the max-age of the keys,
     * and the cacheDuration and the staging delay of the SAML key, those of its family, which a deployment that serves
     * the service provider alone sets without naming the identity provider.
     */
    #[Test]
    public function theMetadataOfTheServiceProviderAreHandedTheFiguresOfTheSamlKey(): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'signing',
                'jwks_max_age' => 90,
            ],
            'saml' => [
                'service_provider' => null,
                'keys' => [
                    'staging_delay' => 172_800,
                    'cache_duration' => 3_600,
                ],
            ],
        ]);

        // Then
        $handler = $container->getDefinition(SamlSection::SERVICE_PROVIDER_METADATA);
        static::assertSame(
            [90, 3_600, 172_800],
            [$handler->getArgument('$maxAge'), $handler->getArgument('$cacheDuration'), $handler->getArgument('$stagingDelay')],
        );
    }

    /**
     * Spec/saml.md section 5.1: the algorithm of a capability a deployment may turn off is dormant in every image,
     * whether the configuration turns the capability on or not, the key files asking whether it is dormant only of a
     * name the registry of its family does not carry, which it carries while the capability is on.
     *
     * @param array<string, mixed> $config
     * @param class-string $algorithm
     */
    #[Test]
    #[DataProvider('provideCapabilities')]
    public function theAlgorithmOfACapabilityADeploymentMayTurnOffIsDormantInEveryImage(array $config, string $algorithm): void
    {
        // When
        $container = self::load($config);

        // Then
        static::assertTrue($container->getDefinition($algorithm)->hasTag(DormantKeyAlgorithms::TAG));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, class-string}>
     */
    public static function provideCapabilities(): iterable
    {
        yield 'SAML left off' => [[], SamlSigning::class];
        yield 'the SAML service provider' => [
            [
                'saml' => [
                    'service_provider' => null,
                ],
            ],
            SamlSigning::class,
        ];
        yield 'the SAML identity provider' => [
            [
                'saml' => [
                    'identity_provider' => null,
                ],
            ],
            SamlSigning::class,
        ];
        yield 'web push left off' => [[], Vapid::class];
        yield 'web push' => [
            [
                'web_push' => [
                    'subject' => 'mailto:operator@op.test',
                ],
            ],
            Vapid::class,
        ];
    }

    /**
     * Spec/saml.md S-4, section 6.1 steps 4 and 6: WantAuthnRequestsSigned true unless the tenant says otherwise, and
     * the metadata cacheable for the max-age of its keys.
     *
     * @param array<string, mixed> $identityProvider
     */
    #[Test]
    #[DataProvider('provideIdentityProviders')]
    public function theSettingsOfTheIdentityProviderReachItsMetadata(array $identityProvider, bool $wantAuthnRequestsSigned): void
    {
        // When
        $container = self::load([
            'keys' => [
                'kms' => 'op',
                'key_id' => 'signing',
                'jwks_max_age' => 90,
            ],
            'saml' => [
                'identity_provider' => $identityProvider,
            ],
        ]);

        // Then
        $handler = $container->getDefinition(SamlSection::IDENTITY_PROVIDER_METADATA);
        static::assertSame(
            [$wantAuthnRequestsSigned, 90],
            [$handler->getArgument('$wantAuthnRequestsSigned'), $handler->getArgument('$maxAge')],
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function provideIdentityProviders(): iterable
    {
        yield 'the default' => [[], true];
        yield 'signed requests turned off' => [
            [
                'want_authn_requests_signed' => false,
            ],
            false,
        ];
    }

    /**
     * Spec/saml.md S-5, section 5.2: the service providers the configuration declares reach the declarations of the
     * tenant whose slug the configuration names, each with what a declaration leaves out filled in.
     */
    #[Test]
    public function theServiceProvidersReachTheDeclarationsOfTheTenant(): void
    {
        // When
        $container = self::load([
            'tenant' => [
                'issuer' => 'https://op.test',
                'slug' => 'acme',
            ],
            'saml' => [
                'identity_provider' => null,
                'service_providers' => [
                    'https://sp.example.com/saml' => [
                        'metadata' => 'https://sp.example.com/saml/metadata',
                        'attributes' => [
                            'urn:oid:0.9.2342.19200300.100.1.3' => [
                                'claim' => 'email',
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        // Then
        $declarations = $container->getDefinition(ConfigurationServiceProviders::class);
        static::assertSame('acme', $declarations->getArgument('$tenantSlug'));
        static::assertSame(
            [
                'https://sp.example.com/saml' => [
                    'metadata' => 'https://sp.example.com/saml/metadata',
                    'attributes' => [
                        'urn:oid:0.9.2342.19200300.100.1.3' => [
                            'claim' => 'email',
                            'name_format' => 'uri',
                            'friendly_name' => null,
                        ],
                    ],
                    'metadata_signers' => [],
                    'encrypt_assertions' => false,
                    'signs_authn_requests' => true,
                ],
            ],
            $declarations->getArgument('$definitions'),
        );
    }

    /**
     * Spec/saml.md section 5.2: a tenant that is no identity provider serves no service provider, and a deployment
     * that declares one for it is refused at boot rather than left with a declaration nothing reads.
     */
    #[Test]
    public function aServiceProviderOfATenantThatIsNoIdentityProviderIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('Service providers are declared for a tenant that is a SAML identity provider: enable "beffroi.saml.identity_provider", or remove "beffroi.saml.service_providers".');

        // When
        self::load([
            'saml' => [
                'service_providers' => [
                    'https://sp.example.com/saml' => [
                        'metadata' => 'https://sp.example.com/saml/metadata',
                    ],
                ],
            ],
        ]);
    }

    /**
     * Spec/saml.md S-42, section 5.7: the upstream identity providers the configuration declares reach the declarations
     * of the tenant whose slug the configuration names, each with what a declaration leaves out filled in.
     */
    #[Test]
    public function theUpstreamIdentityProvidersReachTheDeclarationsOfTheTenant(): void
    {
        // When
        $container = self::load([
            'tenant' => [
                'issuer' => 'https://op.test',
                'slug' => 'acme',
            ],
            'saml' => [
                'service_provider' => null,
                'identity_providers' => [
                    'https://idp.acme.example/saml' => [
                        'metadata' => 'https://idp.acme.example/saml/metadata',
                        'domains' => ['acme.example'],
                        'email_attribute' => 'mail',
                        'groups' => [
                            'attribute' => 'groups',
                            'map' => ['member' => 'Members'],
                        ],
                    ],
                ],
            ],
        ]);

        // Then
        $declarations = $container->getDefinition(ConfigurationUpstreamIdentityProviders::class);
        static::assertSame('acme', $declarations->getArgument('$tenantSlug'));
        static::assertSame(
            [
                'https://idp.acme.example/saml' => [
                    'metadata' => 'https://idp.acme.example/saml/metadata',
                    'domains' => ['acme.example'],
                    'email_attribute' => 'mail',
                    'groups' => [
                        'attribute' => 'groups',
                        'map' => ['member' => 'Members'],
                    ],
                    'metadata_signers' => [],
                    'profile' => [],
                    'subject_attribute' => null,
                    'require_encrypted_assertions' => false,
                    'address_parameter' => null,
                ],
            ],
            $declarations->getArgument('$definitions'),
        );
    }

    /**
     * Spec/saml.md S-64: each upstream identity provider declared has the algorithm of the key it encrypts for wired in
     * the family of those keys, named after its entity ID.
     */
    #[Test]
    public function eachDeclaredIdentityProviderHasTheAlgorithmOfItsKeyWired(): void
    {
        // When
        $container = self::load([
            'saml' => [
                'service_provider' => null,
                'identity_providers' => [
                    'https://idp.acme.example/saml' => [
                        'metadata' => 'https://idp.acme.example/saml/metadata',
                        'domains' => ['acme.example'],
                        'email_attribute' => 'mail',
                    ],
                    'https://idp.other.example/saml' => [
                        'metadata' => 'https://idp.other.example/saml/metadata',
                        'domains' => ['other.example'],
                        'email_attribute' => 'mail',
                    ],
                ],
            ],
        ]);

        // Then
        $definition = $container->getDefinition(JoseSamlEncryptionAlgorithms::class);
        $factory = $definition->getFactory();
        static::assertIsCallable($factory);
        $algorithms = $factory($definition->getArgument('$identityProviders'), $definition->getArgument('$serviceProviderEnabled'), new RsaKeyBits());
        static::assertInstanceOf(JoseSamlEncryptionAlgorithms::class, $algorithms);
        static::assertSame(
            ['https://idp.acme.example/saml', 'https://idp.other.example/saml'],
            array_map(static fn (SamlEncryptionAlgorithmInterface $algorithm): string => $algorithm->identityProvider(), $algorithms->all()),
        );
    }

    /**
     * Spec/saml.md S-42, section 5.7: a tenant that is no service provider receives no assertion of an upstream
     * identity provider, and a deployment that declares one for it is refused at boot rather than left with a
     * declaration nothing reads.
     */
    #[Test]
    public function anUpstreamIdentityProviderOfATenantThatIsNoServiceProviderIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('Upstream identity providers are declared for a tenant that is a SAML service provider: enable "beffroi.saml.service_provider", or remove "beffroi.saml.identity_providers".');

        // When
        self::load([
            'saml' => [
                'identity_provider' => null,
                'identity_providers' => [
                    'https://idp.acme.example/saml' => [
                        'metadata' => 'https://idp.acme.example/saml/metadata',
                        'domains' => ['acme.example'],
                        'email_attribute' => 'mail',
                    ],
                ],
            ],
        ]);
    }

    /**
     * Spec/saml.md S-44: an upstream identity provider answers for one domain at least, refused at boot otherwise.
     */
    #[Test]
    public function anUpstreamIdentityProviderWithoutADomainIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The path "beffroi.saml.identity_providers.https://idp.acme.example/saml.domains" should have at least 1 element(s) defined.');

        // When
        self::load([
            'saml' => [
                'service_provider' => null,
                'identity_providers' => [
                    'https://idp.acme.example/saml' => [
                        'metadata' => 'https://idp.acme.example/saml/metadata',
                        'domains' => [],
                        'email_attribute' => 'mail',
                    ],
                ],
            ],
        ]);
    }

    /**
     * Spec/saml.md S-12, S-40, section 7, issue #738: the SAML signing key is a family of its own, published seven
     * days before it signs and working a year unless the deployment says otherwise under the node of the family,
     * whichever role is enabled, or none, the registry of its keys being wired in every case.
     *
     * @param array<string, mixed> $saml
     */
    #[Test]
    #[DataProvider('provideSamlSchedules')]
    public function theSamlKeysRotateByASchedule(array $saml, string $stagingDelay, string $age): void
    {
        // When
        $container = self::load([
            'saml' => $saml,
        ]);

        // Then
        static::assertSame(
            [$stagingDelay, $age],
            [
                self::interval($container, 'beffroi.saml.rotation_schedule', 0),
                self::interval($container, 'beffroi.saml.rotation_schedule', 1),
            ],
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function provideSamlSchedules(): iterable
    {
        yield 'a deployment that serves no SAML' => [[], 'PT604800S', 'PT31536000S'];
        yield 'the defaults of the identity provider' => [
            [
                'identity_provider' => null,
            ],
            'PT604800S',
            'PT31536000S',
        ];
        yield 'figures the deployment sets for the identity provider' => [
            [
                'identity_provider' => null,
                'keys' => [
                    'staging_delay' => 1_209_600,
                    'age' => 15_552_000,
                ],
            ],
            'PT1209600S',
            'PT15552000S',
        ];
        yield 'figures the deployment sets for the service provider alone' => [
            [
                'service_provider' => null,
                'keys' => [
                    'staging_delay' => 1_209_600,
                    'age' => 15_552_000,
                ],
            ],
            'PT1209600S',
            'PT15552000S',
        ];
    }

    /**
     * Spec/saml.md S-12: the metadata is handed its cacheDuration and the staging delay it is shorter than.
     */
    #[Test]
    public function theMetadataIsHandedItsCacheDurationAndTheStagingDelay(): void
    {
        // When
        $container = self::load([
            'saml' => [
                'identity_provider' => null,
                'keys' => [
                    'staging_delay' => 172_800,
                    'cache_duration' => 3_600,
                ],
            ],
        ]);

        // Then
        $handler = $container->getDefinition(SamlSection::IDENTITY_PROVIDER_METADATA);
        static::assertSame([3_600, 172_800], [$handler->getArgument('$cacheDuration'), $handler->getArgument('$stagingDelay')]);
    }

    /**
     * Spec/saml.md S-12: a cacheDuration a service provider would still be inside when the next key signs is refused
     * when the configuration is read.
     */
    #[Test]
    public function aCacheDurationAsLongAsTheStagingDelayIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The cacheDuration of the metadata, 86400 s, is shorter than the staging delay of a SAML key, 86400 s, or a service provider that honours it meets the next key before its certificate (spec/saml.md S-12).');

        // When
        self::load([
            'saml' => [
                'keys' => [
                    'staging_delay' => 86_400,
                ],
            ],
        ]);
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function load(array $config, ?ContainerBuilder $container = null): ContainerBuilder
    {
        $container ??= new ContainerBuilder();
        $extension = new BeffroiBundle()->getContainerExtension();
        static::assertNotNull($extension);
        $extension->load([
            $config
                + [
                    'tenant' => [
                        'issuer' => 'https://op.test',
                    ],
                    'keys' => [
                        'kms' => 'op',
                        'key_id' => 'signing',
                    ],
                ],
        ], $container);

        return $container;
    }

    /**
     * The lifetime a service is handed, as the specification of a DateInterval: the one the definition carries,
     * or the one its factory builds from the numbers it is given, which is how a lifetime held to a bound or to
     * a rule reaches its service (BoundedNumber, SlidingRefreshLifetime).
     */
    private static function interval(ContainerBuilder $container, string $service, int|string $argument): string
    {
        $definition = $container->getDefinition($service)->getArgument($argument);
        static::assertInstanceOf(Definition::class, $definition);
        static::assertSame(DateInterval::class, $definition->getClass());
        $factory = $definition->getFactory();
        if ($factory !== null) {
            static::assertIsCallable($factory);
            $built = $factory(...$definition->getArguments());
            static::assertInstanceOf(DateInterval::class, $built);

            return $built->format('PT%sS');
        }
        $spec = $definition->getArgument(0);
        static::assertIsString($spec);

        return $spec;
    }
}
