<?php

declare(strict_types=1);

namespace App\Configuration;

use App\Saml\JoseSamlEncryptionAlgorithms;
use App\Saml\RouterServiceProviderEndpoints;
use App\Saml\SamlEncryption;
use App\Saml\UpstreamIdentityProvidersPass;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Application\Upstream\AssertionConsumerService;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Bridge\Model\ModelResponseReceiver;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\ResponseReceiverInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use function array_keys;
use function is_array;
use function is_int;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final readonly class SamlSection extends ConfigurationSection
{
    public const string IDENTITY_PROVIDER_ROLE = 'beffroi.saml.identity_provider.role';

    public const string SERVICE_PROVIDER_ROLE = 'beffroi.saml.service_provider.role';

    public const string ROLE = 'beffroi.saml.role';

    public const string IDENTITY_PROVIDER_METADATA = 'beffroi.saml.identity_provider.metadata';

    public const string SERVICE_PROVIDER_METADATA = 'beffroi.saml.service_provider.metadata';

    private const string SERVICE_PROVIDERS_ALONE = 'Service providers are declared for a tenant that is a SAML identity provider: enable "beffroi.saml.identity_provider", or remove "beffroi.saml.service_providers".';

    private const string IDENTITY_PROVIDERS_ALONE = 'Upstream identity providers are declared for a tenant that is a SAML service provider: enable "beffroi.saml.service_provider", or remove "beffroi.saml.identity_providers".';

    public function name(): string
    {
        return 'saml';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('saml')
            ->info('SAML 2.0 (beffroi/saml, decision 0013): the roles the tenant of this deployment plays.')
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('keys')
            ->info('The family of the SAML keys of the tenant (spec/saml.md S-12): the signing key of both roles (S-40) and the key each upstream identity provider encrypts for (S-64). A node of no role, which turns neither role on. The keys of every other family keep "keys".')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('staging_delay')
            ->info('How long a new SAML key is published in the metadata before it is used, in seconds (spec/saml.md S-12, section 7): seven days by default, seven times the cacheDuration of the metadata, so that a peer whose refresh fails a few times still fetches the next certificate before it is used, and a calendar week for an administrator of a peer that holds an uploaded certificate (Entra without the metadata URL it may be given, or one Microsoft cannot reach) to put the next one in place; AD FS, in the sample of its documentation, gives its partners five days. The keys of every other family keep "keys.staging_delay".')
            ->defaultValue(SamlSigningAlgorithmInterface::STAGING_DELAY)
            ->min(0)
            ->end()
            ->integerNode('age')
            ->info('How long a SAML key works before the planning stages a successor for it, in seconds, counted from its activation (spec/saml.md S-12, section 7): 365 days by default, every rotation being a step for whoever pinned its certificate, and inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key. The keys of every other family keep "keys.age".')
            ->defaultValue(SamlSigningAlgorithmInterface::AGE)
            ->min(1)
            ->end()
            ->end()
            ->end()
            ->arrayNode('metadata')
            ->info('The metadata of both roles of the tenant, its identity provider\'s and its service provider\'s (spec/saml.md S-12, S-40). A node of no role, which turns neither role on.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('cache_duration')
            ->info('How long a peer may keep the metadata before it fetches them again, in seconds, written as their cacheDuration (SAML Metadata section 2.3.2, spec/saml.md S-12): one day by default, how often SimpleSAMLphp\'s metarefresh and a Shibboleth SP refresh them, and strictly shorter than "saml.keys.staging_delay", which the configuration refuses otherwise.')
            ->defaultValue(IdentityProviderMetadataHandler::DEFAULT_CACHE_DURATION)
            ->min(1)
            ->end()
            ->end()
            ->end()
            ->arrayNode('identity_provider')
            ->info('The tenant as a SAML identity provider (spec/saml.md section 6.1), switched by "enabled", which may be an environment variable, read when the container builds what the role changes. Disabled, it serves nothing: no metadata, and the tenant draws no SAML key unless its service provider is enabled, the key of both roles (S-40, S-41). Enabled, its key is drawn with "beffroi:keys:generate --algorithm=SAML-SIGNING" and rotates as every key of the tenant, by the figures of "saml.keys".')
            ->canBeEnabled()
            ->children()
            ->append(self::enabled())
            ->booleanNode('want_authn_requests_signed')
            ->info('What the metadata says in WantAuthnRequestsSigned (SAML Metadata section 2.4.3): true asks every service provider to sign its requests, which is what a broker configured from the metadata does (spec/model.md section 6.9). Turned off, the requests of service providers that cannot sign are accepted where their configuration says so, and the logout of a broker that signs only when asked is lost.')
            ->defaultTrue()
            ->end()
            ->end()
            ->end()
            ->arrayNode('service_provider')
            ->info('The tenant as a SAML service provider to the identity providers upstream of it (spec/saml.md section 6.9), switched by "enabled", which may be an environment variable, read when the container builds what the role changes. Disabled, it serves nothing: its metadata answer that there are none. Enabled, it signs with the SAML signing key of the identity provider, drawn and rotated by the figures of "saml.keys" whichever role is enabled (S-40), and its metadata are served at /saml/sp/metadata.')
            ->canBeEnabled()
            ->children()
            ->append(self::enabled())
            ->stringNode('entity_id')
            ->info('The entity ID of the service provider (spec/saml.md S-38): the URL of its metadata when left out, as the identity provider is named by the URL of its own; another URI for a service provider its upstream identity providers already know by a name it keeps, absolute, at most 1024 characters, with no whitespace, control, format or invisible character (M-6). Never the entity ID of the identity provider of the tenant. Refused when the container is compiled, or at its first use when it or the issuer holds an environment variable.')
            ->defaultNull()
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->end()
            ->append(self::serviceProviders())
            ->append(self::identityProviders())
            ->end()
            ->validate()
            ->ifTrue(self::declaresServiceProvidersAlone(...))
            ->thenInvalid(self::SERVICE_PROVIDERS_ALONE)
            ->end()
            ->validate()
            ->ifTrue(self::declaresIdentityProvidersAlone(...))
            ->thenInvalid(self::IDENTITY_PROVIDERS_ALONE)
            ->end()
            ->validate()
            ->always(self::cachedShorterThanStaged(...))
            ->end()
            ->end();
    }

    /**
     * spec/saml.md S-12
     *
     * A figure from the environment is left to the handler of each role, which checks it when it is built.
     *
     * @throws InvalidConfigurationException
     */
    private static function cachedShorterThanStaged(mixed $saml): mixed
    {
        if (! is_array($saml)) {
            return $saml;
        }
        $cacheDuration = self::section($saml, 'metadata')['cache_duration'] ?? null;
        $stagingDelay = self::section($saml, 'keys')['staging_delay'] ?? null;
        if (is_int($cacheDuration) && is_int($stagingDelay)) {
            try {
                PublishedMetadata::assertCacheDuration($cacheDuration, $stagingDelay);
            } catch (InvalidArgumentException $refusal) {
                throw new InvalidConfigurationException($refusal->getMessage(), 0, $refusal);
            }
        }

        return $saml;
    }

    /**
     * @throws InvalidConfigurationException
     * @throws InvalidArgumentException
     */
    public static function declaredServiceProviders(
        string $tenantSlug,
        mixed $definitions,
        ServedClaimsInterface $claims,
        bool $identityProviderEnabled,
    ): ConfigurationServiceProviders {
        $serviceProviders = self::serviceProviders()->normalized($definitions, 'saml.service_providers');
        if ($serviceProviders !== [] && ! $identityProviderEnabled) {
            throw new InvalidConfigurationException(self::SERVICE_PROVIDERS_ALONE);
        }

        return new ConfigurationServiceProviders($tenantSlug, $serviceProviders, $claims);
    }

    /**
     * spec/saml.md S-42
     *
     * @param string|null $serviceProviderEntityId null for the URL of its metadata
     *
     * @throws InvalidConfigurationException
     * @throws InvalidArgumentException
     */
    public static function declaredIdentityProviders(
        string $tenantSlug,
        mixed $definitions,
        ProfileClaimsInterface $claims,
        bool $serviceProviderEnabled,
        string $issuer,
        ?string $serviceProviderEntityId,
    ): ConfigurationUpstreamIdentityProviders {
        $identityProviders = self::identityProviders()->normalized($definitions, 'saml.identity_providers');
        if ($identityProviders !== [] && ! $serviceProviderEnabled) {
            throw new InvalidConfigurationException(self::IDENTITY_PROVIDERS_ALONE);
        }
        UpstreamIdentityProvidersPass::refuseTheTenantAt(array_keys($identityProviders), $issuer, $serviceProviderEntityId);

        return new ConfigurationUpstreamIdentityProviders($tenantSlug, $identityProviders, $claims);
    }

    /**
     * spec/saml.md S-64
     *
     * @param iterable<JoseKeyAlgorithmInterface&SamlEncryptionAlgorithmInterface> $tagged
     *
     * @throws InvalidConfigurationException
     */
    public static function encryptionAlgorithms(
        mixed $identityProviders,
        bool $serviceProviderEnabled,
        RsaKeyBits $keyBits,
        iterable $tagged = [],
    ): JoseSamlEncryptionAlgorithms {
        $algorithms = [];
        $declared = $serviceProviderEnabled ? self::identityProviders()->normalized($identityProviders, 'saml.identity_providers') : [];
        foreach (array_keys($declared) as $identityProvider) {
            $algorithms[] = new SamlEncryption((string) $identityProvider, $keyBits);
        }
        foreach ($tagged as $algorithm) {
            $algorithms[] = $algorithm;
        }

        return new JoseSamlEncryptionAlgorithms($algorithms);
    }

    private static function serviceProviders(): EnvironmentListDefinition
    {
        $serviceProviders = new EnvironmentListDefinition('service_providers');
        $serviceProviders
            ->info('The service providers of the tenant, keyed by entity ID, compared exactly with the one of their metadata (spec/saml.md S-5). Their metadata are read by "beffroi:saml:service-provider:refresh" and every hour after, refused when expired, older than the document accepted, or without a key for encryption where the declaration asks for encryption (S-6, S-7). Declared only for a tenant that is an identity provider.')
            ->useAttributeAsKey('entity_id')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('metadata')
            ->info('Where the metadata are read from: an https URL, fetched without following a redirect, or the absolute path of a file of the deployment. Nothing else, a plain http URL included. The channel is what vouches for them unless metadata_signers pins who signs them.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('metadata_signers')
            ->info('The certificates the metadata are signed by, each the base64 of its DER as an X509Certificate carries it, sixteen at most: the metadata are then verified under them and carry a validUntil (spec/saml.md S-5, S-6). Left empty, they are trusted by the channel they come through.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('attributes')
            ->info('The claims of the provider sent to this service provider, keyed by the name of the SAML attribute each one is sent as (Core section 2.7.3.1), 256 at most. A claim may be sent under several names.')
            ->useAttributeAsKey('name')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('claim')
            ->info('The name of the claim, as the provider names it (OIDC Core section 5.1).')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->enumNode('name_format')
            ->info('The name format of the attribute (Core section 8.2): "uri", the default the SAML V2.0 interoperability profiles ask for, under which the name is an absolute URI; "basic"; or "unspecified".')
            ->values(['uri', 'basic', 'unspecified'])
            ->defaultValue('uri')
            ->end()
            ->scalarNode('friendly_name')
            ->info('A name a person reads (Core section 2.7.3.1), which nothing compares.')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->end()
            ->booleanNode('encrypt_assertions')
            ->info('The assertions of this service provider are encrypted to a key of its metadata, which must then hold one for encryption, or the metadata are refused (spec/saml.md S-7).')
            ->defaultFalse()
            ->end()
            ->booleanNode('signs_authn_requests')
            ->info('This service provider signs its authentication requests. Turned off for one that cannot, Entra among them, whose unsigned requests are then the only ones accepted (issue #730); a provider that signs is refused while its metadata hold no key for signing (S-11); there is no switch for the tenant or for the deployment.')
            ->defaultTrue()
            ->end()
            ->end()
            ->end();

        return $serviceProviders;
    }

    private static function identityProviders(): EnvironmentListDefinition
    {
        $identityProviders = new EnvironmentListDefinition('identity_providers');
        $identityProviders
            ->info('The upstream identity providers of the tenant, keyed by entity ID, compared exactly with the one of their metadata (spec/saml.md S-42): identity providers whose assertions the service provider of the tenant receives. Their metadata are read by "beffroi:saml:identity-provider:refresh" and every hour after, refused when expired, older than the document accepted, without an identity provider role, without a key for signing, or with a single sign-on service that is not https (S-6, S-43). Declared only for a tenant that is a service provider.')
            ->useAttributeAsKey('entity_id')
            ->normalizeKeys(false)
            ->arrayPrototype()
            ->children()
            ->scalarNode('metadata')
            ->info('Where the metadata are read from: an https URL, fetched without following a redirect, or the absolute path of a file of the deployment. Nothing else, a plain http URL included. The channel is what vouches for them unless metadata_signers pins who signs them.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('metadata_signers')
            ->info('The certificates the metadata are signed by, each the base64 of its DER as an X509Certificate carries it, sixteen at most: the metadata are then verified under them and carry a validUntil (spec/saml.md S-42, S-6). Left empty, they are trusted by the channel they come through.')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('domains')
            ->info('The e-mail domains this identity provider answers for, one at least and 256 at most, each a name of the DNS read without regard to case, a name outside ASCII written as its A-label (spec/saml.md S-44). A domain is the whole part of an address after its "@" and nothing under it, and answers to one identity provider of the tenant: a domain two of them declare is refused.')
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->scalarNode('email_attribute')
            ->info('The name of the attribute of an assertion that carries the e-mail address of a person (spec/saml.md S-45), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" for Entra.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('profile')
            ->info('The attributes of an assertion that fill the profile of a person, keyed by the name of the attribute, each naming the claim of OpenID Connect Core section 5.1 it fills, one attribute per claim (spec/saml.md S-45): a claim a person can describe themselves with in this deployment, refused otherwise when the deployment is built.')
            ->useAttributeAsKey('attribute')
            ->normalizeKeys(false)
            ->scalarPrototype()
            ->end()
            ->end()
            ->scalarNode('subject_attribute')
            ->info('The name of the attribute that names a person when the NameID of an assertion is not persistent (spec/saml.md S-45): a value the identity provider keeps for that person and never one the person changes, "http://schemas.microsoft.com/identity/claims/objectidentifier" for Entra rather than an address. Left out, a person is named by a persistent NameID only.')
            ->defaultNull()
            ->end()
            ->booleanNode('require_encrypted_assertions')
            ->info('An assertion of this identity provider arrives encrypted for the key it is given, or it is refused, whatever signs it (spec/saml.md S-67). The certificate it encrypts for is in the metadata of the service provider given to it alone, at /saml/sp/metadata/ followed by its entity ID in base64url, once its key is drawn with "beffroi:keys:generate --algorithm=SAML-ENCRYPTION:" and its entity ID (S-64, S-65).')
            ->defaultFalse()
            ->end()
            ->scalarNode('address_parameter')
            ->info('The query parameter of the single sign-on service of this identity provider that takes the address a person gave the login page, which it prefills its sign-in with: "login_hint" for Entra. One to 64 unreserved characters of RFC 3986, none of the parameters of the binding (SAMLRequest, SAMLResponse, SAMLEncoding, RelayState, SigAlg, Signature) in any case (spec/saml.md S-68). Left out, no address is sent. The address is a hint and nothing more: the person is who the signed assertion names.')
            ->defaultNull()
            ->end()
            ->arrayNode('groups')
            ->info('The attribute of an assertion that carries the groups of a person, and the group of the tenant each of its values stands for (spec/saml.md S-45). A value the map does not name is no group, and no group is created from what an identity provider sends.')
            ->children()
            ->scalarNode('attribute')
            ->info('The name of the attribute that carries the groups.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('map')
            ->info('The name of a group of the tenant, keyed by a value of the attribute, compared exactly, 256 values at most; the object IDs of the groups for Entra.')
            ->useAttributeAsKey('value')
            ->normalizeKeys(false)
            ->scalarPrototype()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();

        return $identityProviders;
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $own = $this->own($config);
        $tenant = self::section($config, 'tenant');
        $identityProvider = self::section($own, 'identity_provider');
        $serviceProvider = self::section($own, 'service_provider');
        $keys = self::section($own, 'keys');
        $metadata = self::section($own, 'metadata');
        $identityProviderEnabled = self::boolean($identityProvider, 'enabled');
        $serviceProviderEnabled = self::boolean($serviceProvider, 'enabled');
        // ServiceProviderEntityIdPass checks it once the container is compiled.
        $entityId = is_string($serviceProvider['entity_id'] ?? null) ? $serviceProvider['entity_id'] : null;
        $services->set(self::IDENTITY_PROVIDER_ROLE, RoleSwitch::class)->args([$identityProviderEnabled]);
        $services->set(self::SERVICE_PROVIDER_ROLE, RoleSwitch::class)->args([$serviceProviderEnabled]);
        $services
            ->set(self::ROLE, RoleSwitch::class)
            ->factory(RoleSwitch::anyOf(...))
            ->args([[
                service(self::IDENTITY_PROVIDER_ROLE),
                service(self::SERVICE_PROVIDER_ROLE),
            ]]);
        $services
            ->get(ConfigurationServiceProviders::class)
            ->factory(self::declaredServiceProviders(...))
            ->arg('$tenantSlug', self::string($tenant, 'slug'))
            ->arg('$definitions', $own['service_providers'] ?? [])
            ->arg('$identityProviderEnabled', $identityProviderEnabled);
        $services
            ->get(ConfigurationUpstreamIdentityProviders::class)
            ->factory(self::declaredIdentityProviders(...))
            ->arg('$tenantSlug', self::string($tenant, 'slug'))
            ->arg('$definitions', $own['identity_providers'] ?? [])
            ->arg('$serviceProviderEnabled', $serviceProviderEnabled)
            ->arg('$issuer', self::string($tenant, 'issuer'))
            ->arg('$serviceProviderEntityId', $entityId);
        $services->get(JoseSamlEncryptionAlgorithms::class)->factory(self::encryptionAlgorithms(...))->arg(
            '$identityProviders',
            $own['identity_providers'] ?? [],
        )->arg('$serviceProviderEnabled', $serviceProviderEnabled);
        $services->set('beffroi.saml.rotation_schedule', RotationSchedule::class)->args([
            self::bounded($keys, 'staging_delay', named: 'saml.keys.staging_delay', minimum: 0),
            self::bounded($keys, 'age', named: 'saml.keys.age'),
        ]);
        $maxAge = self::integer(self::section($config, 'keys'), 'jwks_max_age');
        $cacheDuration = self::integer($metadata, 'cache_duration');
        $stagingDelay = self::integer($keys, 'staging_delay');
        $services
            ->set(self::IDENTITY_PROVIDER_METADATA, IdentityProviderMetadataHandler::class)
            ->autowire()
            ->arg('$wantAuthnRequestsSigned', self::boolean($identityProvider, 'want_authn_requests_signed'))
            ->arg('$maxAge', $maxAge)
            ->arg('$cacheDuration', $cacheDuration)
            ->arg('$stagingDelay', $stagingDelay);
        self::servedBy($services, IdentityProviderMetadataHandler::class, self::IDENTITY_PROVIDER_METADATA, self::IDENTITY_PROVIDER_ROLE);
        $services->set(RouterServiceProviderEndpoints::class)->autowire()->arg('$entityId', $entityId);
        $services->alias(ServiceProviderEndpointsInterface::class, RouterServiceProviderEndpoints::class);
        $services
            ->set(self::SERVICE_PROVIDER_METADATA, ServiceProviderMetadataHandler::class)
            ->autowire()
            ->arg('$maxAge', $maxAge)
            ->arg('$cacheDuration', $cacheDuration)
            ->arg('$stagingDelay', $stagingDelay);
        self::servedBy($services, ServiceProviderMetadataHandler::class, self::SERVICE_PROVIDER_METADATA, self::SERVICE_PROVIDER_ROLE);
        $services->set('beffroi.saml.service_provider.sign_on', UpstreamSignOn::class)->autowire();
        self::servedBy($services, UpstreamSignOn::class, 'beffroi.saml.service_provider.sign_on', self::SERVICE_PROVIDER_ROLE);
        $services->set(ModelResponseReceiver::class)->autowire()->arg('$accepted', service('beffroi.saml.identity_providers.accepted_metadata'));
        $services->alias(ResponseReceiverInterface::class, ModelResponseReceiver::class);
        $services->set('beffroi.saml.service_provider.assertion_consumer_service', AssertionConsumerService::class)->autowire();
        self::servedBy(
            $services,
            AssertionConsumerService::class,
            'beffroi.saml.service_provider.assertion_consumer_service',
            self::SERVICE_PROVIDER_ROLE,
        );
    }

    /**
     * A role from the environment is a placeholder here, left to declaredServiceProviders().
     */
    private static function declaresServiceProvidersAlone(mixed $saml): bool
    {
        if (! is_array($saml)) {
            return false;
        }

        return self::section($saml, 'service_providers') !== [] && (self::section($saml, 'identity_provider')['enabled'] ?? false) === false;
    }

    /**
     * A role from the environment is a placeholder here, left to declaredIdentityProviders().
     */
    private static function declaresIdentityProvidersAlone(mixed $saml): bool
    {
        if (! is_array($saml)) {
            return false;
        }

        return self::section($saml, 'identity_providers') !== [] && (self::section($saml, 'service_provider')['enabled'] ?? false) === false;
    }
}
