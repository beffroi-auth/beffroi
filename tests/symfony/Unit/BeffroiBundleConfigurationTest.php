<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit;

use DateTimeImmutable;
use Beffroi\Bundle\Configuration\ClientRegistrationSection;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use function sprintf;
use Beffroi\Bundle\Configuration\TokensSection;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Tests\Fixture\Predicates;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Bundle\Key\KeyAge;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use Beffroi\Oidc\Application\Token\GrantNames;
use Beffroi\Oidc\Bridge\Configuration\ClientDefinition;
use Beffroi\Oidc\Domain\Client\Metadata\DeploymentDefaults;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\Definition\PrototypedArrayNode;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ConfigurationExtensionInterface;

/**
 * The configuration tree of architecture §5.1, read through the Config component as the kernel reads it.
 */
final class BeffroiBundleConfigurationTest extends TestCase
{
    private const array MINIMAL = [
        'tenant' => [
            'issuer' => 'https://op.test',
        ],
        'keys' => [
            'kms' => 'op',
            'key_id' => 'signing',
        ],
    ];

    /**
     * Architecture §9: the lifetimes are the choices of the design, applied when the configuration says nothing.
     */
    #[Test]
    public function theDefaultsAreThoseOfTheArchitecture(): void
    {
        // When
        $config = self::process(self::MINIMAL);

        // Then
        static::assertSame(
            [
                'issuer' => 'https://op.test',
                'slug' => 'default',
                'name' => null,
                // a tenant that declares no look is served the pages it has always been served (issue #449)
                'look' => [
                    'logo_uri' => null,
                    'primary_color' => null,
                    'primary_content_color' => null,
                ],
                // nothing is a person's to change until the tenant says which claims are (issue #452)
                'self_served_claims' => [],
                // the tree keeps no list of the predicates of the provider: a tenant that names no class
                // is handed the default policy of the core (TenantFactory, issue #607)
                'authentication_classes' => [],
            ],
            $config['tenant'],
        );
        static::assertSame(
            [
                'kms' => 'op',
                'key_id' => 'signing',
                // the secret of the kernel binds the stored data keys, as the component does by default
                'data_key_secrets' => ['%kernel.secret%'],
                'storage' => '%kernel.project_dir%/var/keys',
                'jwks_max_age' => JwksHandler::DEFAULT_MAX_AGE,
                'staging_delay' => null,
                'age' => KeyAge::DEFAULT_SECONDS,
            ],
            $config['keys'],
        );
        static::assertSame(
            [
                'metadata_storage' => '%kernel.project_dir%/var/webauthn',
            ],
            $config['webauthn'],
        );
        static::assertSame(
            [
                'authorization_code_ttl' => 60,
                'access_token_ttl' => 600,
                'id_token_ttl' => 600,
                'request_uri_ttl' => 60,
                'device_code_ttl' => 600,
                'device_code_interval' => 5,
                'backchannel_authentication_ttl' => 300,
                'backchannel_authentication_max_requested_expiry' => 1800,
                'backchannel_authentication_interval' => 5,
                'refresh_token_ttl' => 2592000,
                'refresh_token_absolute_ttl' => 7776000,
            ],
            $config['tokens'],
        );
        static::assertSame(
            [
                'mode' => null,
                'keep_a_client_unused_for' => ClientRegistrationSection::DEFAULT_KEEP_A_CLIENT_UNUSED_FOR,
                'keep_a_client_never_used_for' => ClientRegistrationSection::DEFAULT_KEEP_A_CLIENT_NEVER_USED_FOR,
                'sector_identifier_timeout' => ClientRegistrationSection::DEFAULT_SECTOR_IDENTIFIER_TIMEOUT,
                'sector_identifier_max_size' => ClientRegistrationSection::DEFAULT_SECTOR_IDENTIFIER_MAX_SIZE,
                'statement_issuers' => [],
                'statement_max_lifetime' => ClientRegistrationSection::DEFAULT_STATEMENT_MAX_LIFETIME,
                'statement_leeway' => ClientRegistrationSection::DEFAULT_STATEMENT_LEEWAY,
                'default_scope' => null,
                'exempt_confidential_clients_from_pkce' => false,
            ],
            $config['client_registration'],
        );
        static::assertSame([], $config['clients']);
    }

    /**
     * Decision 0010: the tree keeps no policy of its own (issue #607), so a tenant that configures nothing
     * and a row written before the column existed speak the one default vocabulary, the core's.
     */
    #[Test]
    public function aTenantThatNamesNoClassSpeaksTheDefaultPolicyOfTheCore(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'default', null, new MockClock('2026-09-20T12:00:00+00:00'), Predicates::wired());

        // When / Then
        static::assertTrue(AuthenticationContextPolicy::default()->equals($factory->authenticationContextPolicy()));
    }

    /**
     * Decision 0009: the two durations the tree carries are the ones the policy of the module defaults to, so
     * that the reference a deployment reads and the default a deployment gets cannot say different things.
     */
    #[Test]
    public function theDefaultRetentionOfAClientIsTheOneOfThePolicy(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode');
        $now = new DateTimeImmutable('2026-09-20T12:00:00+00:00');

        // When
        $retention = $policy->retentionAt($now);

        // Then
        static::assertEquals($now->modify(sprintf('-%d seconds', ClientRegistrationSection::DEFAULT_KEEP_A_CLIENT_UNUSED_FOR)), $retention->usedSince);
        static::assertEquals(
            $now->modify(sprintf('-%d seconds', ClientRegistrationSection::DEFAULT_KEEP_A_CLIENT_NEVER_USED_FOR)),
            $retention->registeredSince,
        );
    }

    /**
     * Decision 0010: the classes are configured in order, each on a predicate of the provider, the
     * numeric names kept as names.
     */
    #[Test]
    public function theAuthenticationClassesAreReadInOrderOnThePredicatesOfTheProvider(): void
    {
        // When
        $config = self::process([
            'tenant' => self::MINIMAL['tenant']
                + [
                    'authentication_classes' => [
                        'urn:okta:loa:2fa:any' => 'two_factors',
                        '2' => 'two_factors',
                        '1' => 'single_factor',
                    ],
                ],
        ] + self::MINIMAL);

        // Then
        static::assertIsArray($config['tenant']);
        static::assertSame(
            [
                'urn:okta:loa:2fa:any' => 'two_factors',
                2 => 'two_factors',
                1 => 'single_factor',
            ],
            $config['tenant']['authentication_classes'],
        );
    }

    /**
     * The tree cannot tell an absent list from an empty one, so it carries the defaults of the module
     * itself; a client declared with nothing but a redirect URI is the same client either way.
     */
    #[Test]
    public function aClientDeclaredWithNothingGetsTheDefaultsOfTheModule(): void
    {
        // Given
        $fromModule = ClientDefinition::fromArray(
            'oidc-demo',
            [
                'redirect_uris' => ['https://demo.test/login/check'],
                'token_endpoint_auth_method' => 'none',
            ],
            Registrations::reader(),
        );

        // When
        $config = self::process(
            self::MINIMAL
            + [
                'clients' => [
                    'oidc-demo' => [
                        'redirect_uris' => ['https://demo.test/login/check'],
                        'token_endpoint_auth_method' => 'none',
                    ],
                ],
            ],
        );

        // Then
        static::assertIsArray($config['clients']);
        static::assertSame(['oidc-demo'], array_keys($config['clients']));
        static::assertIsArray($config['clients']['oidc-demo']);
        $fromTree = ClientDefinition::fromArray(
            'oidc-demo',
            self::stringKeyed($config['clients']['oidc-demo']),
            Registrations::reader(),
        );
        static::assertEquals($fromModule, $fromTree);
        static::assertSame(DeploymentDefaults::GRANT_TYPES, GrantNames::of($fromTree->registration->grantTypes));
        static::assertSame(['openid', 'profile', 'email'], $fromTree->registration->allowedScopes->values());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideRefusedConfigurations(): iterable
    {
        yield 'no tenant' => [
            [
                'keys' => self::MINIMAL['keys'],
            ],
            'tenant',
        ];
        yield 'no issuer' => [
            [
                'tenant' => [],
                'keys' => self::MINIMAL['keys'],
            ],
            'issuer',
        ];
        // the tree holds the shape and the wiring holds the predicates (issue #607): a name no wired
        // predicate carries refuses the start in TenantFactory, where the registry can be read
        yield 'a class named on no predicate at all' => [
            [
                'tenant' => self::MINIMAL['tenant']
                    + [
                        'authentication_classes' => [
                            'gold' => '',
                        ],
                    ],
                'keys' => self::MINIMAL['keys'],
            ],
            'authentication_classes',
        ];
        yield 'no kms' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => [
                    'key_id' => 'signing',
                ],
            ],
            'kms',
        ];
        yield 'no key id' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => [
                    'kms' => 'op',
                ],
            ],
            'key_id',
        ];
        yield 'an authorization code living longer than RFC 6749 section 4.1.2 recommends' => [
            self::MINIMAL
                + [
                    'tokens' => [
                        'authorization_code_ttl' => TokensSection::MAX_AUTHORIZATION_CODE_TTL + 1,
                    ],
                ],
            'authorization_code_ttl',
        ];
        yield 'a lifetime of zero' => [
            self::MINIMAL
                + [
                    'tokens' => [
                        'access_token_ttl' => 0,
                    ],
                ],
            'access_token_ttl',
        ];
        yield 'a negative cache lifetime of the JWK Set' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => self::MINIMAL['keys']
                    + [
                        'jwks_max_age' => -1,
                    ],
            ],
            'jwks_max_age',
        ];
        yield 'an age of nothing' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => self::MINIMAL['keys']
                    + [
                        'age' => 0,
                    ],
            ],
            'age',
        ];
        yield 'a negative staging delay' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => self::MINIMAL['keys']
                    + [
                        'staging_delay' => -1,
                    ],
            ],
            'staging_delay',
        ];
        yield 'no secret to bind a stored data key' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => self::MINIMAL['keys']
                    + [
                        'data_key_secrets' => [],
                    ],
            ],
            'data_key_secrets',
        ];
        yield 'an empty secret to bind a stored data key' => [
            [
                'tenant' => self::MINIMAL['tenant'],
                'keys' => self::MINIMAL['keys']
                    + [
                        'data_key_secrets' => [''],
                    ],
            ],
            'data_key_secrets',
        ];
        yield 'a sliding refresh lifetime beyond the absolute one' => [
            self::MINIMAL
                + [
                    'tokens' => [
                        'refresh_token_ttl' => 100,
                        'refresh_token_absolute_ttl' => 99,
                    ],
                ],
            'refresh_token_ttl',
        ];
        yield 'an unknown client option' => [
            self::MINIMAL
                + [
                    'clients' => [
                        'app' => [
                            'insecure_redirect_uris' => true,
                        ],
                    ],
                ],
            'insecure_redirect_uris',
        ];
        yield 'a consent flag that is not a boolean' => [
            self::MINIMAL
                + [
                    'clients' => [
                        'app' => [
                            'requires_consent' => 'no',
                        ],
                    ],
                ],
            'requires_consent',
        ];
        yield 'a PKCE flag that is not a boolean' => [
            self::MINIMAL
                + [
                    'clients' => [
                        'app' => [
                            'requires_pkce' => 'no',
                        ],
                    ],
                ],
            'requires_pkce',
        ];
        yield 'an unknown top-level option' => [
            self::MINIMAL
                + [
                    'compatibility' => [],
                ],
            'compatibility',
        ];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[Test]
    #[DataProvider('provideRefusedConfigurations')]
    public function itRefusesWhatItDoesNotKnowOrCannotAllow(array $config, string $named): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains($named);

        // When
        self::process($config);
    }

    /**
     * One secret written alone is the list of one secret, the first and the only one, as the component reads
     * its own.
     */
    #[Test]
    public function oneSecretToBindTheStoredDataKeysIsAListOfOne(): void
    {
        // When
        $config = self::process([
            'tenant' => self::MINIMAL['tenant'],
            'keys' => self::MINIMAL['keys']
                + [
                    'data_key_secrets' => '%env(BEFFROI_DATA_KEY_SECRET)%',
                ],
        ]);

        // Then
        static::assertIsArray($config['keys']);
        static::assertSame(['%env(BEFFROI_DATA_KEY_SECRET)%'], $config['keys']['data_key_secrets'] ?? null);
    }

    /**
     * A client identifier is a value, not a configuration key to normalize: "oidc-demo" stays "oidc-demo".
     */
    #[Test]
    public function clientIdentifiersAreKeptAsWritten(): void
    {
        // When
        $config = self::process(
            self::MINIMAL
            + [
                'clients' => [
                    'oidc-demo' => [],
                    'Conformance.Client_1' => [],
                ],
            ],
        );

        // Then
        static::assertIsArray($config['clients']);
        static::assertSame(['oidc-demo', 'Conformance.Client_1'], array_keys($config['clients']));
    }

    /**
     * Decision 0006: no option to do it wrong. Nothing in the tree, at any depth, names an insecure mode,
     * a compatibility switch or a way to allow or disable a security rule.
     */
    #[Test]
    public function theTreeHasNoInsecureOptionAndNoCompatibilitySwitch(): void
    {
        // Given
        $names = [];

        // When
        self::collect(self::configuration()->getConfigTreeBuilder()->buildTree(), $names);

        // Then
        static::assertNotSame([], $names);
        foreach ($names as $name) {
            static::assertSame(0, preg_match('/insecure|compat|legacy|allow_|disable_|skip_|unsafe/i', $name), $name);
        }
    }

    /**
     * @param list<string> $names
     */
    private static function collect(NodeInterface $node, array &$names): void
    {
        $names[] = $node->getName();
        if ($node instanceof PrototypedArrayNode) {
            self::collect($node->getPrototype(), $names);
        }
        if ($node instanceof ArrayNode) {
            foreach ($node->getChildren() as $child) {
                self::collect($child, $names);
            }
        }
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private static function process(array $config): array
    {
        return self::stringKeyed(new Processor()->processConfiguration(self::configuration(), [$config]));
    }

    /**
     * @param array<array-key, mixed> $values
     *
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $values): array
    {
        $result = [];
        foreach ($values as $key => $value) {
            $result[(string) $key] = $value;
        }

        return $result;
    }

    private static function configuration(): ConfigurationInterface
    {
        $extension = new BeffroiBundle()->getContainerExtension();
        static::assertInstanceOf(ConfigurationExtensionInterface::class, $extension);
        $configuration = $extension->getConfiguration([], new ContainerBuilder());
        static::assertInstanceOf(ConfigurationInterface::class, $configuration);

        return $configuration;
    }
}
