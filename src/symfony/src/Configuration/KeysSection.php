<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use DateInterval;
use Doctrine\DBAL\Connection;
use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexListener;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Bundle\Command\DataKeysRewrapCommand;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Messenger\EventBusDispatcher;
use Beffroi\Bundle\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyDestruction;
use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeys;
use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Key\FilePairwiseSalt;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Key\KeyAge;
use Beffroi\Bundle\Key\StagingDelay;
use Beffroi\Bundle\Profiler\KmsClient;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedTypes;
use Symfony\Component\KeyManagement\Bridge\DoctrineOrm\SchemaListener\DataKeyStoreSchemaListener;
use Symfony\Component\KeyManagement\Debug\TraceableDataKeyStore;
use Symfony\Component\KeyManagement\Debug\TraceableEnvelopeEncrypter;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\StoredEnvelopeEncrypter;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_locator;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use function is_array;
use function is_string;

/**
 * Where the keys of the tenant live and what seals them (architecture §3.3): the KMS is named here and built by the framework, and what the bundle holds is that name.
 */
final readonly class KeysSection extends ConfigurationSection
{
    public function name(): string
    {
        return 'keys';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('keys')
            ->info('Where the keys of the tenants live: sealed by the KMS named here, stored as files until a table takes over (architecture §3.3).')
            ->isRequired()
            ->children()
            ->scalarNode('kms')
            ->info('Name of the KMS client that seals the private keys, an entry of "key_management.clients" of the framework configuration (a DSN there, or the members of a composite client); the KMS keeps, it never signs.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('key_id')
            ->info('The key of that KMS the keys of the tenants are sealed under (backend-specific: the id of a sodium key, a Vault transit key name, an ARN); "{tenant}" stands for the slug of the tenant, one master key each.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('data_key_secrets')
            ->info('What binds each stored data key to its reference and its scope (StoredDataKey::bindingFor() of symfony/key-management): an HMAC keyed by the data key and by a secret the database does not hold, so that whoever writes the table cannot plant a key they wrapped themselves. The first one binds a new row and every one is accepted when a row is read, so a secret is rotated by writing the new one first, running "beffroi:data-keys:rewrap" for every tenant towards the client that already wraps its keys, which binds each row again under the first, then dropping the old one. Unless set, the secret of the kernel ("kernel.secret"), which is then rotated the same way: a row whose secret is no longer listed opens nothing, nor does anything sealed under its key.')
            ->beforeNormalization()
            ->castToArray()
            ->end()
            ->scalarPrototype()
            ->cannotBeEmpty()
            ->end()
            ->requiresAtLeastOneElement()
            ->defaultValue(['%kernel.secret%'])
            ->end()
            ->scalarNode('storage')
            ->info('Directory of the sealed keys, one file per key and per tenant, and of the pairwise salt of each tenant, one file beside them (OIDC Core section 8.1).')
            ->defaultValue('%kernel.project_dir%/var/keys')
            ->cannotBeEmpty()
            ->end()
            ->integerNode('jwks_max_age')
            ->info('How long a relying party may cache the JWK Set, in seconds (RFC 7517 §5, architecture §4.8); the staging window of a rotation derives from it, so that the two cannot drift apart (§3.3).')
            ->defaultValue(JwksHandler::DEFAULT_MAX_AGE)
            ->min(0)
            ->end()
            ->integerNode('staging_delay')
            ->info('How long a new key is published before it signs, in seconds (architecture §3.3, §9), for every family of keys but the SAML signing key, which has its own ("saml.identity_provider.staging_delay"); unless set, jwks_max_age plus the 60 s refetch cooldown of oidc_login: the max-age is what a relying party with a warm cache needs to see the new key, the cooldown what one served by a shared HTTP cache needs to refetch it.')
            ->defaultNull()
            ->min(0)
            ->end()
            ->integerNode('age')
            ->info('How long a key works before the planning stages a successor for it, in seconds, counted from its activation (architecture §3.3), for every family of keys but the SAML signing key, which has its own ("saml.identity_provider.age"): ninety days by default, which is inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key and short enough that the rotation path is walked four times a year rather than first walked during an incident. It has to be longer than the window a retiring key holds the JWK Set open for, which is the longest lifetime of what a key of that use is bound to, or every rotation would leave a key behind; the rotation refuses an age that is not.')
            ->defaultValue(KeyAge::DEFAULT_SECONDS)
            ->min(1)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $keys = $this->own($config);
        // the client is named here and built there: the KMS clients live in "key_management.clients" of
        // the framework configuration, which is also where a client made of several providers and a data
        // key store are declared, and where a DSN that may carry key material already belongs. What the
        // bundle holds is a name, and an alias to the client that name points at.
        $services->alias('beffroi.kms', 'key_management.' . self::string($keys, 'kms'));
        // Traced in debug, so that the panel of the profiler sees what this provider opens. The component
        // traces what it builds itself and nothing else: the clients it is given, its own envelope
        // encrypter and its own store, none of which this bundle uses, so a page that sealed or opened a
        // column reported nothing at all (beffroi#427). The decorators are the component's own, posed here
        // rather than taken through an alias to its service, because a test takes the KMS of this kernel
        // down by replacing this service at runtime and an alias cannot be replaced.
        $envelopes = inline_service(EnvelopeEncrypter::class)->args([service('beffroi.kms')]);
        $services->set('beffroi.kms.envelopes', $debug ? TraceableEnvelopeEncrypter::class : EnvelopeEncrypter::class)->args(
            $debug
                ? [$envelopes, service('key_management.data_collector'), self::string($keys, 'kms')]
                : [service('beffroi.kms')],
        );
        // The columns that carry a personal datum (decisions 0011 and 0018): a data key per tenant and per
        // family of columns, wrapped by the master key of that tenant, the one its signing keys are already
        // sealed under, and a payload that carries a 16-byte reference to it rather than the wrapped key.
        //
        // Three services and one setting of their own, the secrets that bind a row to its reference and its
        // scope: the table is the bundle's, and what a deployment chooses of the rest it has already chosen
        // above, by naming its KMS and the pattern of its master keys. None of them is tagged
        // "kernel.reset": the component tags its own store with it and "forget()" would put the KMS back on
        // the path of every request that touches a column, where a thread is to keep open what it has
        // opened (decision 0018, 12-garde-des-cles.md §1.5).
        $secrets = self::secrets($keys);
        $services->set('beffroi.data_keys', TenantDataKeyStores::class)->args([
            service(Connection::class),
            tagged_locator('key_management.client', 'key'),
            self::string($keys, 'kms'),
            self::string($keys, 'key_id'),
            $secrets,
            TenantDataKeyStores::TABLE,
        ]);
        // The index key of a tenant, which is what a search matches a sealed column by: a row of the same
        // table, in a scope of its own, on a store whose maximum age is null. The age past which a key is
        // retired is a setting of a store and not of a scope, and an index key must never be retired nor
        // rotated, every tag already written having been derived under it; keeping it in the store rather
        // than beside the master key of the tenant is what has "key-management:rewrap-data-keys" carry it
        // along when a deployment changes backend (decision 0018).
        $services->set('beffroi.data_keys.index', TenantDataKeyStores::class)->args([
            service(Connection::class),
            tagged_locator('key_management.client', 'key'),
            self::string($keys, 'kms'),
            self::string($keys, 'key_id'),
            $secrets,
            TenantDataKeyStores::TABLE,
            null,
        ]);
        // The store opens the index key of a tenant once and every index over it costs that one opening,
        // which is what decision 0018 counts; the table is read for the reference of its first row and for
        // nothing else. Declared by its class so that what looks a user up is autowired with it
        // (DoctrineUserRepository).
        $services->set(TenantBlindIndexes::class)->args([
            service(Connection::class),
            service('beffroi.data_keys.index'),
            service(TenantProvider::class),
            TenantDataKeyStores::TABLE,
        ]);
        // What an operator holds the data keys with (decision 0018). The reading is one service and the two
        // writes are the commands themselves: a command that reads is not the command that writes, and
        // what erases a key is a statement of its own and never a method of the router the encryption path
        // sees. The index key is in the same table, so all three see it with the rest.
        $services->set(TenantDataKeys::class)->args([service('beffroi.data_keys')]);
        $services->set(TenantDataKeyDestruction::class)->args([
            service(Connection::class),
            service(TenantDataKeys::class),
            service(EventBusDispatcher::class),
            service(RequestContextFactory::class),
            TenantDataKeyStores::TABLE,
        ]);
        // The rewrap hands the command of the component a store that lists one tenant's rows, so that
        // nothing of its loop is written twice, and resolves the master key of the tenant rather than
        // asking for it: an operator who had to type it could type another tenant's.
        $services->get(DataKeysRewrapCommand::class)->arg('$store', service('beffroi.data_keys'))->arg('$clients', tagged_locator(
            'key_management.client',
            'key',
        ))->arg('$masterKeyId', self::string($keys, 'key_id'));
        // The tag written in the same statement as the value it indexes, on "onFlush" and not on
        // "prePersist", which fires when persist() is called and would miss a value set afterwards. A row
        // whose tag does not match what it holds is a row no search returns.
        $services->set(BlindIndexListener::class)->args([service(TenantBlindIndexes::class)])->tag('doctrine.event_listener', [
            'event' => 'onFlush',
        ]);
        // The fallback reads an envelope that carries its own data key rather than refusing it: nothing of
        // this repository has written one into a column, but the sealed keys and the sealed secrets are
        // envelopes of that shape and the same encrypter is what reads them.
        // The store is where a sealed column shows: "StoredEnvelopeEncrypter" asks it for the data key of a
        // scope and then seals locally, so the KMS is off the path of a value and the panel would see
        // nothing of one. Traced in debug, and only on this path: the reader keeps its own, so the schema
        // listener still gets a "DataKeyStore" and the rewrapping half stays where it is, which is what
        // the decorator of the component says it deliberately does not claim.
        $stores = $debug
            ? inline_service(TraceableDataKeyStore::class)->args([
                service('beffroi.data_keys'),
                service('key_management.data_collector'),
                TenantDataKeyStores::TABLE,
            ])
            : service('beffroi.data_keys');
        $services->set('beffroi.kms.stored_envelopes', StoredEnvelopeEncrypter::class)->args([
            $stores,
            service('beffroi.kms.envelopes'),
        ]);
        // Lazy, and public so that it stays lazy: the types are registered while the bundles boot, and what
        // they are handed is this encrypter, so building it there would build the store, the connection and
        // the KMS client of every process that boots, for a path a process that seals nothing never takes.
        // A private service with one consumer is inlined, and an inlined service is not a proxy, so being
        // reachable by its name is what keeps the KMS off the path of a boot; it is also what lets a
        // deployment seal a value outside Doctrine. What it costs is asserted rather than trusted
        // (BeffroiBundleExtensionTest).
        $services
            ->set('beffroi.personal_data.encrypter', TenantScopedEncrypter::class)
            ->public()
            ->lazy()
            ->args([
                service('beffroi.kms.stored_envelopes'),
                service(TenantProvider::class),
            ]);
        // What the bundles register while they boot (BeffroiBundle::boot()), and the one argument a
        // deployment chooses: which encrypter the types are given is what decides where the data key of a
        // scope comes from.
        $services
            ->set('beffroi.encrypted_types', EncryptedTypes::class)
            ->public()
            ->factory(EncryptedColumnTypes::service(...))
            ->args([service('beffroi.personal_data.encrypter')]);
        // The table of the store declared in the schema the ORM assembles, so that "doctrine:schema:update"
        // does not offer to drop what no mapping of the bundle puts there. What the listener of the ORM
        // bridge asks for is a DataKeyStore and not the router, so what is tagged is the one store every
        // read goes to: the table of a read is the table of every write.
        $services
            ->set('beffroi.data_keys.reader', DataKeyStore::class)
            ->factory([service('beffroi.data_keys'), 'reader'])
            ->tag('beffroi.data_key_store');
        $services->set(
            'beffroi.data_keys.schema_listener',
            DataKeyStoreSchemaListener::class,
        )->args([tagged_iterator('beffroi.data_key_store')])->tag('doctrine.event_listener', [
            'event' => 'postGenerateSchema',
        ]);
        $services->get(EnvelopeKeySealer::class)->arg('$envelopes', service('beffroi.kms.envelopes'))->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(EnvelopeSecretSealer::class)->arg('$envelopes', service('beffroi.kms.envelopes'))->arg('$kmsKeyId', self::string($keys, 'key_id'));
        $services->get(FileTenantKeyRepository::class)->arg('$directory', self::string($keys, 'storage'));
        // The pairwise salt of a tenant lives beside its sealed keys and is sealed like them (OIDC Core
        // §8.1): one directory to back up, one KMS to lose.
        $services->get(FilePairwiseSalt::class)->arg('$directory', self::string($keys, 'storage'));
        if ($debug) {
            $services->get(KmsClient::class)->arg('$name', self::string($keys, 'kms'));
        }
        $services->get(JwksHandler::class)->arg('$maxAge', self::integer($keys, 'jwks_max_age'));
        // The schedule of the JOSE families, the keys of the JWK Set and the keys the tenant keeps
        // (issue #738): one service the four families of JoseKeyAlgorithms share, the SAML key having a
        // schedule of its own (SamlSection). The staging delay is derived at runtime, once the environment
        // placeholders are numbers.
        $services->set('beffroi.keys.rotation_schedule', RotationSchedule::class)->args([
            inline_service(DateInterval::class)
                ->factory(StagingDelay::interval(...))
                ->args([isset($keys['staging_delay']) ? self::integer($keys, 'staging_delay') : null, self::integer($keys, 'jwks_max_age')]),
            inline_service(DateInterval::class)->factory(KeyAge::interval(...))->args([self::integer($keys, 'age')]),
        ]);
    }

    /**
     * The secrets that bind a stored data key, in the order the deployment wrote them: the first one binds
     * and every one is accepted.
     *
     * @param array<array-key, mixed> $keys
     *
     * @return non-empty-list<string> each a secret, or the parameter or environment placeholder that stands
     *                                for one until runtime
     */
    private static function secrets(array $keys): array
    {
        $written = $keys['data_key_secrets'] ?? null;
        $secrets = [];
        foreach (is_array($written) ? $written : [] as $secret) {
            if (! is_string($secret)) {
                throw new InvalidConfigurationException('The "beffroi" configuration key "data_key_secrets" must be a list of strings.');
            }
            $secrets[] = $secret;
        }
        if ($secrets === []) {
            throw new InvalidConfigurationException('The "beffroi" configuration key "data_key_secrets" names at least one secret.');
        }

        return $secrets;
    }
}
