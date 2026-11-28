<?php

declare(strict_types=1);

namespace App\DependencyInjection;

use function dirname;
use App\Controller\AccountArchiveRequestController;
use App\Credential\RateLimitedChannelChangeWindow;
use App\Doctrine\Type\ActorType;
use App\Messenger\MessengerContract;
use App\Doctrine\Type\AddressType;
use App\Doctrine\Type\AuthenticationContextPolicyType;
use App\Doctrine\Type\AuthenticationPredicateType;
use App\Doctrine\Type\SelfServedClaimsType;
use App\Doctrine\Type\LogoutProgressType;
use App\Doctrine\Type\PasskeyAttestationType;
use App\Doctrine\Type\TenantContactType;
use App\Doctrine\Type\TenantLookType;
use App\Doctrine\Type\AuthenticationProofsType;
use App\Doctrine\Type\BackupCodesType;
use App\Doctrine\Type\BindingMessageType;
use App\Doctrine\Type\BytesType;
use App\Doctrine\Type\PasswordAlgorithmType;
use App\Doctrine\Type\PasswordHashType;
use App\Doctrine\Type\ProfileType;
use App\Doctrine\Type\UserSourceType;
use App\Doctrine\Type\JournalAuthorType;
use App\Doctrine\Type\ClaimChangeAuthorType;
use App\Doctrine\Type\MailEncryptionKeyType;
use App\Doctrine\Type\ChosenChannelsType;
use App\Doctrine\Type\AuthenticationSnapshotType;
use App\Doctrine\Type\ClaimNamesType;
use App\Doctrine\Type\ClaimsRequestType;
use App\Doctrine\Type\ClientSecretType;
use App\Doctrine\Type\CodeChallengeType;
use App\Configuration\BackchannelAuthenticationSection;
use App\Configuration\BackChannelLogoutSection;
use App\Configuration\ClientAuthenticationSection;
use App\Configuration\ClientRegistrationSection;
use App\Configuration\ClientsSection;
use App\Configuration\ExposesParametersInterface;
use App\Configuration\InteractionSection;
use App\Configuration\LocalesSection;
use App\Configuration\ConfigurationSectionInterface;
use App\Configuration\DpopSection;
use App\Configuration\GeoipSection;
use App\Configuration\KeysSection;
use App\Configuration\HistorySection;
use App\Configuration\JournalSection;
use App\Configuration\AdministratorSection;
use App\Configuration\LoadSection;
use App\Configuration\ConfirmationSection;
use App\Configuration\MailSection;
use App\Configuration\MutualTlsSection;
use App\Configuration\NoticesSection;
use App\Configuration\OutboundSection;
use App\Configuration\PasswordsSection;
use App\Configuration\RequestObjectsSection;
use App\Configuration\TenantSection;
use App\Configuration\TokensSection;
use App\Configuration\SamlSection;
use App\Configuration\SelfClientSection;
use App\Configuration\SmsSection;
use App\Configuration\TrustedIssuersSection;
use App\Configuration\WebauthnSection;
use App\Configuration\WebPushSection;
use App\Doctrine\Type\ConfirmationType;
use App\Doctrine\Type\AuthorizationDetailsType;
use App\Doctrine\Type\DeviceType;
use App\Doctrine\Type\EmailAddressType;
use App\Doctrine\Type\GeoLocationType;
use App\Doctrine\Type\GrantedMembersType;
use App\Doctrine\Type\IssuerType;
use App\Doctrine\Type\KeyConfirmationType;
use App\Doctrine\Type\PasskeyUserHandleType;
use App\Doctrine\Type\RedirectUriType;
use App\Doctrine\Type\RequestContextType;
use App\Doctrine\Type\ResourceIndicatorsType;
use App\Doctrine\Type\ScopesType;
use App\Doctrine\Type\SectorIdentifierType;
use App\Doctrine\Type\SubjectType;
use App\Key\KmsClientPass;
use App\Key\KmsHttpClientPass;
use App\Http\ThirdPartyRequestsPass;
use App\Push\WebPushHttpClientPass;
use App\Saml\ServiceProviderEntityIdPass;
use App\Saml\ServiceProvidersPass;
use App\Saml\UpstreamIdentityProvidersPass;
use App\Plane\Plane;
use App\Routing\ProviderRoutes;
use App\Security\CorePasswordHasher;
use App\Security\RateLimitedAttempts;
use App\Security\SecurityUser;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\AbstractExtension;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

final class BeffroiExtension extends AbstractExtension
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $children = $definition->rootNode()->children();
        foreach (self::sections() as $section) {
            $section->describe($children);
        }
        $children->end();
    }

    public const array DBAL_TYPES = [
        IssuerType::NAME => IssuerType::class,
        SectorIdentifierType::NAME => SectorIdentifierType::class,
        SubjectType::NAME => SubjectType::class,
        JournalAuthorType::NAME => JournalAuthorType::class,
        ClaimChangeAuthorType::NAME => ClaimChangeAuthorType::class,
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
        ClaimNamesType::NAME => ClaimNamesType::class,
        GrantedMembersType::NAME => GrantedMembersType::class,
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
        MailEncryptionKeyType::NAME => MailEncryptionKeyType::class,
        ChosenChannelsType::NAME => ChosenChannelsType::class,
        PasskeyUserHandleType::NAME => PasskeyUserHandleType::class,
        AuthenticationContextPolicyType::NAME => AuthenticationContextPolicyType::class,
        AuthenticationPredicateType::NAME => AuthenticationPredicateType::class,
        TenantLookType::NAME => TenantLookType::class,
        TenantContactType::NAME => TenantContactType::class,
        PasskeyAttestationType::NAME => PasskeyAttestationType::class,
        SelfServedClaimsType::NAME => SelfServedClaimsType::class,
        BackupCodesType::NAME => BackupCodesType::class,
        LogoutProgressType::NAME => LogoutProgressType::class,
    ];

    /**
     * An extension cannot add compiler passes itself: the kernel adds these (BeffroiKernelTrait).
     */
    public static function addCompilerPasses(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new KmsClientPass());
        $container->addCompilerPass(new KmsHttpClientPass());
        $container->addCompilerPass(new WebPushHttpClientPass());
        $container->addCompilerPass(new ThirdPartyRequestsPass());
        $container->addCompilerPass(new ServiceProvidersPass());
        $container->addCompilerPass(new ServiceProviderEntityIdPass());
        $container->addCompilerPass(new UpstreamIdentityProvidersPass());
    }

    /**
     * The parameters a firewall names are set here, before any extension loads: SecurityBundle's extension, registered
     * before this one, resolves them when it loads.
     */
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $configs = $builder->getExtensionConfig($this->getAlias());
        foreach (self::sections() as $section) {
            if ($section instanceof ExposesParametersInterface) {
                foreach ($section->parameters($configs) as $name => $value) {
                    $builder->setParameter($name, $value);
                }
            }
        }
        $applicationDir = dirname(__DIR__, 2);
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
                            'dir' => $applicationDir . '/config/beffroi/doctrine/core',
                            'prefix' => 'Beffroi\\Core\\Domain',
                            'alias' => 'BeffroiCore',
                        ],
                        'BeffroiOidc' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $applicationDir . '/config/beffroi/doctrine/oidc',
                            'prefix' => 'Beffroi\\Oidc\\Domain',
                            'alias' => 'BeffroiOidc',
                        ],
                        'BeffroiSaml' => [
                            'type' => 'xml',
                            'is_bundle' => false,
                            'dir' => $applicationDir . '/config/beffroi/doctrine/saml',
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
                // The lock factory named, never "auto": a kernel without one refuses to build rather than count without it.
                $limiters[$limiter] = [
                    'policy' => 'sliding_window',
                    'limit' => RateLimitedAttempts::LIMIT,
                    'interval' => RateLimitedAttempts::INTERVAL,
                    'lock_factory' => 'lock.factory',
                ];
            }
            $limiters[RateLimitedChannelChangeWindow::LIMITER] = [
                'policy' => 'fixed_window',
                'limit' => RateLimitedChannelChangeWindow::LIMIT,
                'interval' => RateLimitedChannelChangeWindow::INTERVAL,
                'lock_factory' => 'lock.factory',
            ];
            $limiters[AccountArchiveRequestController::LIMITER] = [
                'policy' => 'sliding_window',
                'limit' => AccountArchiveRequestController::LIMIT,
                'interval' => AccountArchiveRequestController::INTERVAL,
            ];
            $builder->prependExtensionConfig('rate_limiter', [
                'limiters' => $limiters,
            ]);
        }
        if ($builder->hasExtension('framework')) {
            // Pools of their own: a deployment points them at a shared store without touching the rest of its cache.
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
        if ($builder->hasExtension('messenger')) {
            if (! $builder->hasParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')')) {
                $builder->setParameter('env(' . MessengerContract::DSN_ENVIRONMENT_VARIABLE . ')', MessengerContract::DEFAULT_DSN);
            }
            $builder->prependExtensionConfig('messenger', MessengerContract::configuration());
        }
        if ($builder->hasExtension('scheduler')) {
            $builder->prependExtensionConfig('scheduler', [
                'use_messenger_routing' => true,
            ]);
        }
        if ($builder->hasExtension('doctrine_migrations')) {
            $builder->prependExtensionConfig('doctrine_migrations', [
                'migrations_paths' => [
                    'DoctrineMigrations' => $applicationDir . '/migrations',
                ],
            ]);
        }
    }

    private static function isDebug(ContainerBuilder $builder): bool
    {
        return $builder->hasParameter('kernel.debug') && $builder->getParameter('kernel.debug') === true;
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../../config/beffroi/services.php');
        // The profiler panel follows the debug flag alone: no setting of a deployment switches it on.
        $debug = self::isDebug($builder);
        if ($debug) {
            $container->import('../../config/beffroi/profiler.php');
        }

        if (! $builder->hasParameter('env(BEFFROI_PLANE)')) {
            $builder->setParameter('env(BEFFROI_PLANE)', Plane::Provider->value);
        }
        if (! $builder->hasParameter(Plane::PARAMETER)) {
            $builder->setParameter(Plane::PARAMETER, '%env(enum:' . Plane::class . ':' . Plane::VARIABLE . ')%');
        }

        $services = $container->services();
        ProviderRoutes::register($services, $builder);
        foreach (self::sections() as $section) {
            $section->load($config, $services, $debug);
        }
    }

    /**
     * A list, because a configuration tree is built before any service exists to be collected by tag.
     *
     * @return list<ConfigurationSectionInterface> in the order the configuration reference publishes them
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
            new ConfirmationSection(),
            new AdministratorSection(),
            new JournalSection(),
            new HistorySection(),
            new GeoipSection(),
            new PasswordsSection(),
            new InteractionSection(),
            new LocalesSection(),
            new BackChannelLogoutSection(),
            new BackchannelAuthenticationSection(),
            new WebPushSection(),
            new MailSection(),
            new SmsSection(),
            new NoticesSection(),
            new ClientAuthenticationSection(),
            new RequestObjectsSection(),
            new DpopSection(),
            new TrustedIssuersSection(),
            new ClientsSection(),
            new SelfClientSection(),
            new ClientRegistrationSection(),
            new OutboundSection(),
            new SamlSection(),
        ];
    }
}
