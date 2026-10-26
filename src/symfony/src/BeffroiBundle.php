<?php

declare(strict_types=1);

namespace Beffroi\Bundle;

use function is_a;
use function dirname;
use Beffroi\Bundle\Doctrine\Type\ActorType;
use Beffroi\Bundle\Messenger\MessengerContract;
use Beffroi\Bundle\Doctrine\Type\AddressType;
use Beffroi\Bundle\Doctrine\Type\AuthenticationContextPolicyType;
use Beffroi\Bundle\Doctrine\Type\AuthenticationPredicateType;
use Beffroi\Bundle\Doctrine\Type\SelfServedClaimsType;
use Beffroi\Bundle\Doctrine\Type\LogoutProgressType;
use Beffroi\Bundle\Doctrine\Type\TenantLookType;
use Beffroi\Bundle\Doctrine\Type\AuthenticationProofsType;
use Beffroi\Bundle\Doctrine\Type\BackupCodesType;
use Beffroi\Bundle\Doctrine\Type\BindingMessageType;
use Beffroi\Bundle\Doctrine\Type\BytesType;
use Beffroi\Bundle\Doctrine\Type\NeedsPasswordAlgorithmsInterface;
use Beffroi\Bundle\Doctrine\Type\PasswordAlgorithmType;
use Beffroi\Bundle\Doctrine\Type\PasswordHashType;
use Beffroi\Bundle\Doctrine\Type\ProfileType;
use Beffroi\Bundle\Doctrine\Type\UserSourceType;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Beffroi\Bundle\Doctrine\Type\AuthenticationSnapshotType;
use Beffroi\Bundle\Doctrine\Type\ClaimsRequestType;
use Beffroi\Bundle\Doctrine\Type\ClientSecretType;
use Beffroi\Bundle\Doctrine\Type\CodeChallengeType;
use Beffroi\Bundle\Configuration\BackchannelAuthenticationSection;
use Beffroi\Bundle\Configuration\BackChannelLogoutSection;
use Beffroi\Bundle\Configuration\ClientAuthenticationSection;
use Beffroi\Bundle\Configuration\ClientRegistrationSection;
use Beffroi\Bundle\Configuration\ClientsSection;
use Beffroi\Bundle\Configuration\InteractionSection;
use Beffroi\Bundle\Configuration\ConfigurationSectionInterface;
use Beffroi\Bundle\Configuration\DpopSection;
use Beffroi\Bundle\Configuration\GeoipSection;
use Beffroi\Bundle\Configuration\KeysSection;
use Beffroi\Bundle\Configuration\HistorySection;
use Beffroi\Bundle\Configuration\JournalSection;
use Beffroi\Bundle\Configuration\LoadSection;
use Beffroi\Bundle\Configuration\MutualTlsSection;
use Beffroi\Bundle\Configuration\PasswordsSection;
use Beffroi\Bundle\Configuration\RequestObjectsSection;
use Beffroi\Bundle\Configuration\TenantSection;
use Beffroi\Bundle\Configuration\TokensSection;
use Beffroi\Bundle\Configuration\SamlSection;
use Beffroi\Bundle\Configuration\TrustedIssuersSection;
use Beffroi\Bundle\Configuration\WebauthnSection;
use Beffroi\Bundle\Configuration\WebPushSection;
use Beffroi\Bundle\Doctrine\Type\ConfirmationType;
use Beffroi\Bundle\Doctrine\Type\AuthorizationDetailsType;
use Beffroi\Bundle\Doctrine\Type\NeedsAuthorizationDetailTypesInterface;
use Beffroi\Bundle\Doctrine\Type\NeedsAuthenticationPredicatesInterface;
use Beffroi\Bundle\Doctrine\Type\NeedsCodeChallengeMethodsInterface;
use Beffroi\Bundle\Doctrine\Type\NeedsConfirmationReaderInterface;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use Beffroi\Oidc\Port\ConfirmationReaderInterface;
use Beffroi\Bundle\Doctrine\Type\DeviceType;
use Beffroi\Bundle\Doctrine\Type\EmailAddressType;
use Beffroi\Bundle\Doctrine\Type\GeoLocationType;
use Beffroi\Bundle\Doctrine\Type\IssuerType;
use Beffroi\Bundle\Doctrine\Type\KeyConfirmationType;
use Beffroi\Bundle\Doctrine\Type\PasskeyUserHandleType;
use Beffroi\Bundle\Doctrine\Type\RedirectUriType;
use Beffroi\Bundle\Doctrine\Type\RequestContextType;
use Beffroi\Bundle\Doctrine\Type\ResourceIndicatorsType;
use Beffroi\Bundle\Doctrine\Type\ScopesType;
use Beffroi\Bundle\Doctrine\Type\SectorIdentifierType;
use Beffroi\Bundle\Doctrine\Type\SubjectType;
use Beffroi\Bundle\Key\KmsClientPass;
use Beffroi\Bundle\Saml\ServiceProviderEntityIdPass;
use Beffroi\Bundle\Saml\ServiceProvidersPass;
use Beffroi\Bundle\Saml\UpstreamIdentityProvidersPass;
use Beffroi\Bundle\Plane\Plane;
use Beffroi\Bundle\Security\CorePasswordHasher;
use Beffroi\Bundle\Security\RateLimitedAttempts;
use Beffroi\Bundle\Security\SecurityUser;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedTypes;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Kernel\AbstractBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/**
 * The configuration of architecture §5.1, and nothing that decision 0006 forbids: no "insecure_*" key, no
 * compatibility switch.
 */
final class BeffroiBundle extends AbstractBundle
{
    protected string $extensionAlias = 'beffroi';

    public function configure(DefinitionConfigurator $definition): void
    {
        $children = $definition->rootNode()->children();
        foreach (self::sections() as $section) {
            $section->describe($children);
        }
        $children->end();
    }

    /**
     * By the name the mappings use (architecture §5.3).
     */
    public const array DBAL_TYPES = [
        IssuerType::NAME => IssuerType::class,
        SectorIdentifierType::NAME => SectorIdentifierType::class,
        SubjectType::NAME => SubjectType::class,
        EmailAddressType::NAME => EmailAddressType::class,
        AddressType::NAME => AddressType::class,
        AuthenticationProofsType::NAME => AuthenticationProofsType::class,
        AuthenticationSnapshotType::NAME => AuthenticationSnapshotType::class,
        GeoLocationType::NAME => GeoLocationType::class,
        DeviceType::NAME => DeviceType::class,
        RequestContextType::NAME => RequestContextType::class,
        RedirectUriType::NAME => RedirectUriType::class,
        ScopesType::NAME => ScopesType::class,
        ResourceIndicatorsType::NAME => ResourceIndicatorsType::class,
        AuthorizationDetailsType::NAME => AuthorizationDetailsType::class,
        BindingMessageType::NAME => BindingMessageType::class,
        ClaimsRequestType::NAME => ClaimsRequestType::class,
        CodeChallengeType::NAME => CodeChallengeType::class,
        ClientSecretType::NAME => ClientSecretType::class,
        ActorType::NAME => ActorType::class,
        ConfirmationType::NAME => ConfirmationType::class,
        KeyConfirmationType::NAME => KeyConfirmationType::class,
        BytesType::NAME => BytesType::class,
        PasswordAlgorithmType::NAME => PasswordAlgorithmType::class,
        PasswordHashType::NAME => PasswordHashType::class,
        ProfileType::NAME => ProfileType::class,
        UserSourceType::NAME => UserSourceType::class,
        PasskeyUserHandleType::NAME => PasskeyUserHandleType::class,
        AuthenticationContextPolicyType::NAME => AuthenticationContextPolicyType::class,
        AuthenticationPredicateType::NAME => AuthenticationPredicateType::class,
        TenantLookType::NAME => TenantLookType::class,
        SelfServedClaimsType::NAME => SelfServedClaimsType::class,
        BackupCodesType::NAME => BackupCodesType::class,
        LogoutProgressType::NAME => LogoutProgressType::class,
    ];

    /**
     * The types that read a wiring back are told what the deployment is wired with, as soon as the
     * container can answer: which algorithm a stored password hash names, which kind of confirmation a
     * stored "cnf" names, what an "authorization_details" a user agreed to asks for, which method a stored
     * PKCE challenge was made with, which predicate a stored "acr" policy and a stored login floor name. It goes to the class and not to an instance: Doctrine builds its types itself,
     * when a connection is first made, so no instance of one exists while the bundles boot. A deployment
     * has one wiring, and a kernel booted after another hands over the same one.
     */
    public function boot(): void
    {
        $container = $this->container;
        if ($container === null) {
            return;
        }
        $algorithms = $container->has('beffroi.password_algorithms') ? $container->get('beffroi.password_algorithms') : null;
        $confirmations = $container->has('beffroi.confirmations') ? $container->get('beffroi.confirmations') : null;
        $authorizationDetails = $container->has('beffroi.authorization_detail_types') ? $container->get('beffroi.authorization_detail_types') : null;
        $codeChallengeMethods = $container->has('beffroi.code_challenge_methods') ? $container->get('beffroi.code_challenge_methods') : null;
        $predicates = $container->has('beffroi.authentication_predicates') ? $container->get('beffroi.authentication_predicates') : null;
        foreach (self::DBAL_TYPES as $class) {
            if ($algorithms instanceof PasswordAlgorithmsInterface && is_a($class, NeedsPasswordAlgorithmsInterface::class, true)) {
                $class::resolveWith($algorithms);
            }
            if ($confirmations instanceof ConfirmationReaderInterface && is_a($class, NeedsConfirmationReaderInterface::class, true)) {
                $class::resolveWith($confirmations);
            }
            if ($authorizationDetails instanceof AuthorizationDetailsReaderInterface && is_a($class, NeedsAuthorizationDetailTypesInterface::class, true)) {
                $class::resolveWith($authorizationDetails);
            }
            if ($codeChallengeMethods instanceof CodeChallengeMethodsInterface && is_a($class, NeedsCodeChallengeMethodsInterface::class, true)) {
                $class::resolveWith($codeChallengeMethods);
            }
            if ($predicates instanceof AuthenticationPredicatesInterface && is_a($class, NeedsAuthenticationPredicatesInterface::class, true)) {
                $class::resolveWith($predicates);
            }
        }
        $this->registerEncryptedTypes();
    }

    /**
     * The encrypted types of the columns that carry a personal datum (decisions 0011 and 0018,
     * EncryptedColumnTypes), declared as one service because each one holds an encrypter, which a class
     * DoctrineBundle instantiates with no argument cannot. Booting is where the bridge asks for it, and it
     * is early enough for every entry point at once: the front controller, the console with its schema
     * tool and its migrations, and the test kernel. Registering twice is safe, which is what a rebooted
     * kernel does.
     *
     * A connection is asked for first, and this is the ordering nobody can see from the call: an encrypted
     * type resolves the type it decorates by name, in the global registry, at the moment it is registered,
     * and seven of them decorate a type of DBAL_TYPES above, which DoctrineBundle only puts in that
     * registry when a connection is first created (ConnectionFactory::initializeTypes). Asking opens
     * nothing, a DBAL connection reaching the database on its first query and not before.
     */
    private function registerEncryptedTypes(): void
    {
        $container = $this->container;
        if ($container === null || ! $container->has('beffroi.encrypted_types')) {
            return;
        }
        $doctrine = $container->has('doctrine') ? $container->get('doctrine') : null;
        if ($doctrine instanceof ManagerRegistry) {
            $doctrine->getConnection();
        }
        $types = $container->get('beffroi.encrypted_types');
        if ($types instanceof EncryptedTypes) {
            $types->register();
        }
    }

    /**
     * The passes of the bundle. The KMS client it seals with is named in its own configuration and
     * registered in the framework's, so nothing but a pass can tell a name that answers from one that
     * does not. The service providers of the tenant are built when the container is compiled, so that a
     * declaration that does not hold together fails the build and not the first login (spec/saml.md
     * section 6.2 step 1), which only a pass can do while leaving aside the values of the environment; the
     * claim of a mapping, which needs the claims providers built, is checked by MappedClaimsWarmer right
     * after, in the same build.
     */
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->addCompilerPass(new KmsClientPass());
        $container->addCompilerPass(new ServiceProvidersPass());
        $container->addCompilerPass(new ServiceProviderEntityIdPass());
        $container->addCompilerPass(new UpstreamIdentityProvidersPass());
    }

    /**
     * Doctrine gets the mappings, the types and the migrations of the bundle (architecture §5.3); the
     * security component gets the hasher of its users (§5.4); the rate limiter gets the limiter of the
     * attempts at a code (§3.4), a rule of the core the application does not tune. The firewall is the
     * application's to declare.
     */
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $bundleDir = dirname(__DIR__);
        if ($builder->hasExtension('doctrine')) {
            $builder->prependExtensionConfig('doctrine', [
                'dbal' => [
                    'types' => self::DBAL_TYPES,
                ],
                'orm' => [
                    'mappings' => [
                        'BeffroiCore' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $bundleDir . '/config/doctrine/core',
                            'prefix' => 'Beffroi\\Core\\Domain',
                            'alias' => 'BeffroiCore',
                        ],
                        'BeffroiOidc' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $bundleDir . '/config/doctrine/oidc',
                            'prefix' => 'Beffroi\\Oidc\\Domain',
                            'alias' => 'BeffroiOidc',
                        ],
                        'BeffroiSaml' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $bundleDir . '/config/doctrine/saml',
                            'prefix' => 'Beffroi\\Saml\\Domain',
                            'alias' => 'BeffroiSaml',
                        ],
                    ],
                ],
            ]);
        }
        if ($builder->hasExtension('security')) {
            $builder->prependExtensionConfig('security', [
                'password_hashers' => [
                    SecurityUser::class => [
                        'id' => CorePasswordHasher::class,
                    ],
                ],
            ]);
        }
        if ($builder->hasExtension('rate_limiter')) {
            $limiters = [];
            foreach (RateLimitedAttempts::LIMITERS as $limiter) {
                $limiters[$limiter] = [
                    'policy' => 'sliding_window',
                    'limit' => RateLimitedAttempts::LIMIT,
                    'interval' => RateLimitedAttempts::INTERVAL,
                ];
            }
            $builder->prependExtensionConfig('rate_limiter', [
                'limiters' => $limiters,
            ]);
        }
        if ($builder->hasExtension('framework')) {
            // the keys of the clients, the keys of the issuers a tenant trusts, the assertions of a client,
            // the assertions of a trusted issuer and
            // the software statements already seen, each in a pool of its own, the request objects already seen,
            // what DPoP remembers of a proof and what each budget of a load has been asked for live in
            // pools of their own, so that a deployment can point them at a shared store without
            // touching the rest of its cache
            $builder->prependExtensionConfig('framework', [
                'cache' => [
                    'pools' => [
                        'beffroi.client_keys' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.issuer_keys' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.client_assertions' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.issuer_assertions' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.software_statements' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.request_objects' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.dpop' => [
                            'adapter' => 'cache.app',
                        ],
                        'beffroi.load' => [
                            'adapter' => 'cache.app',
                        ],
                    ],
                ],
            ]);
        }
        // The three buses, their middleware and where each marker is sent are the contract of this
        // provider and not a preference of an operator (issue #456, architecture §5.6): an installation
        // that wires them itself and turns the default middleware off or gets "doctrine_transaction" wrong
        // breaks the asynchronous half of the provider, quietly. What is left to an application is its
        // transports, and the lanes default to the database so that a new installation needs no broker.
        if ($builder->hasExtension('messenger')) {
            if (! $builder->hasParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')')) {
                $builder->setParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')', MessengerContract::DEFAULT_DSN);
            }
            $builder->prependExtensionConfig('messenger', MessengerContract::configuration());
        }
        // The recurring messages of the schedule are routed by their class like every other message, and
        // not handled inside the worker that ticks: the worker that holds the clock only says when.
        if ($builder->hasExtension('scheduler')) {
            $builder->prependExtensionConfig('scheduler', [
                'use_messenger_routing' => true,
            ]);
        }
        if ($builder->hasExtension('doctrine_migrations')) {
            $builder->prependExtensionConfig('doctrine_migrations', [
                'migrations_paths' => [
                    'Beffroi\\Bundle\\Migrations' => $bundleDir . '/migrations',
                ],
            ]);
        }
    }

    /**
     * Whether the kernel runs in debug. A container built without a kernel, which is what a unit test of
     * this extension builds, is not one.
     */
    private static function isDebug(ContainerBuilder $builder): bool
    {
        return $builder->hasParameter('kernel.debug') && $builder->getParameter('kernel.debug') === true;
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');
        // the panel of the provider is a debug tool and nothing else: it is wired when the kernel runs
        // in debug, and a deployment cannot switch it on (issue #152)
        $debug = self::isDebug($builder);
        if ($debug) {
            $container->import('../config/profiler.php');
        }

        if (! $builder->hasParameter('env(BEFFROI_PLANE)')) {
            $builder->setParameter('env(BEFFROI_PLANE)', Plane::All->value);
        }

        $services = $container->services();
        foreach (self::sections() as $section) {
            $section->load($config, $services, $debug);
        }
    }

    /**
     * The capabilities this bundle wires, in the order the configuration reference publishes them. It is
     * a list of classes and it lives here because there is nowhere else it could: a configuration tree is
     * built before any service exists, so nothing can be asked for the sections the way the provider asks
     * for its grants or its confirmation kinds.
     *
     * @return list<ConfigurationSectionInterface>
     */
    private static function sections(): array
    {
        return [
            new TenantSection(),
            new KeysSection(),
            new WebauthnSection(),
            new MutualTlsSection(),
            new TokensSection(),
            new LoadSection(),
            new JournalSection(),
            new HistorySection(),
            new GeoipSection(),
            new PasswordsSection(),
            new InteractionSection(),
            new BackChannelLogoutSection(),
            new BackchannelAuthenticationSection(),
            new WebPushSection(),
            new ClientAuthenticationSection(),
            new RequestObjectsSection(),
            new DpopSection(),
            new TrustedIssuersSection(),
            new ClientsSection(),
            new ClientRegistrationSection(),
            new SamlSection(),
        ];
    }
}
