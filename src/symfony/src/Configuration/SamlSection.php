<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Saml\JoseSamlEncryptionAlgorithms;
use Beffroi\Bundle\Saml\JoseSamlSigningAlgorithms;
use Beffroi\Bundle\Saml\RouterServiceProviderEndpoints;
use Beffroi\Bundle\Saml\SamlEncryption;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Security\UpstreamLogin;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Application\Upstream\AssertionConsumerService;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Bridge\Model\ModelResponseReceiver;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Beffroi\Saml\Port\ResponseReceiverInterface;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use function array_keys;
use function hash;
use function is_array;
use function is_int;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Whether the tenant of this deployment is a SAML identity provider (beffroi/saml, spec/saml.md section 6.1), whether
 * it wants the requests it receives signed, and the service providers it serves (section 5.2); and whether it is a
 * SAML service provider to identity providers upstream of it, and the entity ID it goes by there (section 5.6).
 *
 * A role the deployment does not enable wires nothing: no handler serves its metadata, and its route answers that
 * there is none (S-41). The SAML signing key is the key of both roles (S-40): with neither enabled the tenant draws no
 * SAML key, its algorithm left dormant instead, so that a key the tenant drew before the deployment turned them off
 * stays in the key directory, read by nothing, and the other keys go on without it. With either enabled, the algorithm
 * of the SAML signing key is wired with the others, so that the key commands draw, list and rotate it, and the
 * scheduled step stages its successors, as every key of the tenant.
 *
 * The entity ID of the service provider is its own (S-38): one the deployment names is a string here, and a URI of
 * M-6 that is not the entity ID of the identity provider once the container is compiled (ServiceProviderEntityIdPass);
 * one that holds an environment variable, or an issuer that does, is checked by RouterServiceProviderEndpoints at its
 * first use.
 *
 * The service providers are declared here and nowhere else, as the clients are (S-5): no request registers one and no
 * page edits one. A declaration is validated when the container is compiled (ServiceProvidersPass), the claim of a
 * mapping right after, in the same build (MappedClaimsWarmer), and one holding an environment variable at its first
 * use; its metadata are read by "beffroi:saml:service-provider:refresh" and by the hourly step of the schedule, and kept
 * in the database.
 *
 * So are the upstream identity providers of the service provider (S-42), with the e-mail domains each answers for,
 * one provider per domain (S-44), and the attributes an assertion of it is read for (S-45): validated when the
 * container is compiled (UpstreamIdentityProvidersPass), the claims of the profile by the same warmer, and their
 * metadata read by "beffroi:saml:identity-provider:refresh" and by the same hourly step.
 *
 * The keys of the identity provider are a family of their own (spec/saml.md S-12, issue #738): their staging delay and their age are set here,
 * counted in days by default, and not by "beffroi.keys", whose figures suit a JWK Set refetched within minutes. The
 * schedule of the family is built whether the role is enabled or not, the registry of the SAML keys being wired in
 * both cases, empty in the second; the cacheDuration of the metadata is refused here, when the configuration is read,
 * unless it is shorter than the staging delay.
 */
final readonly class SamlSection extends ConfigurationSection
{
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
            ->arrayNode('identity_provider')
            ->info('The tenant as a SAML identity provider (spec/saml.md section 6.1). Disabled, nothing of it is wired: it serves no metadata, and the tenant draws no SAML key unless its service provider is enabled, the key of both roles (S-40, S-41). Enabled, its key is drawn with "beffroi:keys:generate --algorithm=SAML-SIGNING" and rotates as every key of the tenant, by the figures of its own family below.')
            ->canBeEnabled()
            ->children()
            ->booleanNode('want_authn_requests_signed')
            ->info('What the metadata says in WantAuthnRequestsSigned (SAML Metadata section 2.4.3): true asks every service provider to sign its requests, which is what a broker configured from the metadata does (spec/model.md section 6.9). Turned off, the requests of service providers that cannot sign are accepted where their configuration says so, and the logout of a broker that signs only when asked is lost.')
            ->defaultTrue()
            ->end()
            ->integerNode('staging_delay')
            ->info('How long a new SAML signing key is published in the metadata before it signs, in seconds (spec/saml.md S-12, section 7): seven days by default, seven times the cacheDuration of the metadata, so that a service provider whose refresh fails a few times still fetches the next certificate before it is used, and a calendar week for an administrator of a service provider that holds an uploaded certificate (Entra without the metadata URL it may be given, or one Microsoft cannot reach) to put the next one in place; AD FS, in the sample of its documentation, gives its partners five days. The keys of every other family keep "keys.staging_delay".')
            ->defaultValue(SamlSigningAlgorithmInterface::STAGING_DELAY)
            ->min(0)
            ->end()
            ->integerNode('age')
            ->info('How long a SAML signing key works before the planning stages a successor for it, in seconds, counted from its activation (spec/saml.md S-12, section 7): 365 days by default, every rotation being a step for whoever pinned its certificate, and inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key. The keys of every other family keep "keys.age".')
            ->defaultValue(SamlSigningAlgorithmInterface::AGE)
            ->min(1)
            ->end()
            ->integerNode('cache_duration')
            ->info('How long a service provider may keep the metadata before it fetches it again, in seconds, written as its cacheDuration (SAML Metadata section 2.3.2, spec/saml.md S-12): one day by default, how often SimpleSAMLphp\'s metarefresh and a Shibboleth SP refresh it, and strictly shorter than "staging_delay", which the configuration refuses otherwise.')
            ->defaultValue(IdentityProviderMetadataHandler::DEFAULT_CACHE_DURATION)
            ->min(1)
            ->end()
            ->end()
            ->validate()
            ->always(static function (array $identityProvider): array {
                $cacheDuration = $identityProvider['cache_duration'] ?? null;
                $stagingDelay = $identityProvider['staging_delay'] ?? null;
                // an environment placeholder is a number at runtime only, where the handler checks it again
                if (is_int($cacheDuration) && is_int($stagingDelay)) {
                    try {
                        PublishedMetadata::assertCacheDuration($cacheDuration, $stagingDelay);
                    } catch (InvalidArgumentException $refusal) {
                        throw new InvalidConfigurationException($refusal->getMessage(), 0, $refusal);
                    }
                }

                return $identityProvider;
            })
            ->end()
            ->end()
            ->arrayNode('service_provider')
            ->info('The tenant as a SAML service provider to the identity providers upstream of it (spec/saml.md section 6.9). Disabled, nothing of it is wired: its metadata answer that there are none. Enabled, it signs with the SAML signing key of the identity provider, drawn and rotated by the figures of "identity_provider" whichever role is enabled (S-40), and its metadata are served at /saml/sp/metadata.')
            ->canBeEnabled()
            ->children()
            ->stringNode('entity_id')
            ->info('The entity ID of the service provider (spec/saml.md S-38): the URL of its metadata when left out, as the identity provider is named by the URL of its own; another URI for a service provider its upstream identity providers already know by a name it keeps, absolute, at most 1024 characters, with no whitespace, control, format or invisible character (M-6). Never the entity ID of the identity provider of the tenant. Refused when the container is compiled, or at its first use when it or the issuer holds an environment variable.')
            ->defaultNull()
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->end()
            ->arrayNode('service_providers')
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
            ->end()
            ->end()
            ->arrayNode('identity_providers')
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
            ->end()
            ->end()
            ->end()
            ->validate()
            ->ifTrue(self::declaresServiceProvidersAlone(...))
            ->thenInvalid('Service providers are declared for a tenant that is a SAML identity provider: enable "beffroi.saml.identity_provider", or remove "beffroi.saml.service_providers".')
            ->end()
            ->validate()
            ->ifTrue(self::declaresIdentityProvidersAlone(...))
            ->thenInvalid('Upstream identity providers are declared for a tenant that is a SAML service provider: enable "beffroi.saml.service_provider", or remove "beffroi.saml.identity_providers".')
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $services->get(ConfigurationServiceProviders::class)->arg('$tenantSlug', self::string(self::section($config, 'tenant'), 'slug'))->arg(
            '$definitions',
            self::section($this->own($config), 'service_providers'),
        );
        $services->get(ConfigurationUpstreamIdentityProviders::class)->arg('$tenantSlug', self::string(self::section($config, 'tenant'), 'slug'))->arg(
            '$definitions',
            self::section($this->own($config), 'identity_providers'),
        );
        $identityProvider = self::section($this->own($config), 'identity_provider');
        $serviceProvider = self::section($this->own($config), 'service_provider');
        // the family of the SAML keys exists in every deployment (JoseKeyAlgorithms), so its schedule does too
        $services->set('beffroi.saml.rotation_schedule', RotationSchedule::class)->args([
            self::seconds($identityProvider, 'staging_delay'),
            self::seconds($identityProvider, 'age'),
        ]);
        $identityProviderEnabled = ($identityProvider['enabled'] ?? false) === true;
        $serviceProviderEnabled = ($serviceProvider['enabled'] ?? false) === true;
        if (! $identityProviderEnabled && ! $serviceProviderEnabled) {
            $services->get(SamlSigning::class)->tag(DormantKeyAlgorithms::TAG);

            return;
        }
        $services->get(SamlSigning::class)->tag(JoseSamlSigningAlgorithms::TAG);
        $maxAge = self::integer(self::section($config, 'keys'), 'jwks_max_age');
        $cacheDuration = self::integer($identityProvider, 'cache_duration');
        $stagingDelay = self::integer($identityProvider, 'staging_delay');
        if ($identityProviderEnabled) {
            $services
                ->set(IdentityProviderMetadataHandler::class)
                ->autowire()
                ->arg('$wantAuthnRequestsSigned', self::boolean(
                    $identityProvider,
                    'want_authn_requests_signed',
                ))
                ->arg('$maxAge', $maxAge)
                ->arg('$cacheDuration', $cacheDuration)
                ->arg('$stagingDelay', $stagingDelay);
        }
        if ($serviceProviderEnabled) {
            // a string or nothing, which the node holds it to; ServiceProviderEntityIdPass checks it once compiled (S-38)
            $entityId = is_string($serviceProvider['entity_id'] ?? null) ? $serviceProvider['entity_id'] : null;
            $services->set(RouterServiceProviderEndpoints::class)->autowire()->arg('$entityId', $entityId);
            $services->alias(ServiceProviderEndpointsInterface::class, RouterServiceProviderEndpoints::class);
            $services
                ->set(ServiceProviderMetadataHandler::class)
                ->autowire()
                ->arg('$maxAge', $maxAge)
                ->arg('$cacheDuration', $cacheDuration)
                ->arg(
                    '$stagingDelay',
                    $stagingDelay,
                );
            // the sign-on at an upstream identity provider, which needs the endpoints of the role (spec/saml.md S-51)
            $services->set(UpstreamSignOn::class)->autowire();
            // the assertion consumer service (spec/saml.md S-52 to S-59): the response read under the accepted document
            // of the provider, from the table of the upstream identity providers, and the login of the firewall it
            // proves, announced only by a deployment that receives assertions
            $services->set(ModelResponseReceiver::class)->autowire()->arg('$accepted', service('beffroi.saml.identity_providers.accepted_metadata'));
            $services->alias(ResponseReceiverInterface::class, ModelResponseReceiver::class);
            $services->set(AssertionConsumerService::class)->autowire();
            $services->set(UpstreamLogin::class)->tag('beffroi.login')->tag('beffroi.login.refusal');
            // the key each upstream identity provider declared encrypts for, an algorithm of its own (spec/saml.md S-64),
            // named by the digest of its entity ID, which a service identifier holds whatever the URI
            foreach (array_keys(self::section($this->own($config), 'identity_providers')) as $identityProvider) {
                $services
                    ->set('beffroi.saml.encryption_algorithm.' . hash('sha256', (string) $identityProvider), SamlEncryption::class)
                    ->args([(string) $identityProvider, service(RsaKeyBits::class)])
                    ->tag(JoseSamlEncryptionAlgorithms::TAG);
            }
        }
    }

    /**
     * Whether service providers are declared for a tenant that is no identity provider, which serves none of them.
     */
    private static function declaresServiceProvidersAlone(mixed $saml): bool
    {
        if (! is_array($saml)) {
            return false;
        }

        return self::section($saml, 'service_providers') !== [] && (self::section($saml, 'identity_provider')['enabled'] ?? false) !== true;
    }

    /**
     * Whether upstream identity providers are declared for a tenant that is no service provider, which receives no
     * assertion of theirs.
     */
    private static function declaresIdentityProvidersAlone(mixed $saml): bool
    {
        if (! is_array($saml)) {
            return false;
        }

        return self::section($saml, 'identity_providers') !== [] && (self::section($saml, 'service_provider')['enabled'] ?? false) !== true;
    }
}
