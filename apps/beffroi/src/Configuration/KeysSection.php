<?php

declare(strict_types=1);

namespace App\Configuration;

use DateInterval;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;
use App\Doctrine\PersonalData\BlindIndexListener;
use App\Doctrine\PersonalData\DataKeysOfTheTenant;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Command\DataKeysRewrapCommand;
use App\Http\RequestContextFactory;
use App\Messenger\EventBusDispatcher;
use App\Doctrine\PersonalData\TenantBlindIndexes;
use App\Doctrine\PersonalData\TenantDataKeyDestruction;
use App\Doctrine\PersonalData\TenantDataKeys;
use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Doctrine\TenantProvider;
use App\Key\FilePairwiseSalt;
use App\Key\FileMailSigningKeyRepository;
use App\Key\FileChainCheckpoints;
use App\Key\FileTenantKeyRepository;
use App\Key\KeyAge;
use App\Key\StagingDelay;
use App\Profiler\KmsClient;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;
use Psr\Container\ContainerInterface;
use SensitiveParameter;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedType;
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
use function is_int;
use function is_string;

final readonly class KeysSection extends ConfigurationSection
{
    /**
     * The sealer of the person an access token names, which every resource server reads in the token.
     */
    public const string PERSON_SEALER = 'beffroi.secret_sealer.person';

    public const string BACKCHANNEL_SEALER = 'beffroi.secret_sealer.backchannel';

    public const string TOTP_PROVISIONING_SEALER = 'beffroi.secret_sealer.totp_provisioning';

    /**
     * @var array<string, non-empty-string> by service, the purpose its envelopes are sealed for
     */
    private const array SECRET_SEALERS = [
        self::PERSON_SEALER => 'beffroi:access-token-person:v1:',
        self::BACKCHANNEL_SEALER => 'beffroi:backchannel-request:v1:',
        self::TOTP_PROVISIONING_SEALER => 'beffroi:totp-provisioning:v1:',
    ];

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
            ->info('Name of the KMS client that seals the private keys, an entry of "key_management.clients", the configuration of KeyManagementBundle (a DSN there, or the members of a composite client); the KMS keeps, it never signs.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('key_id')
            ->info('The key of that KMS the keys of the tenants are sealed under (backend-specific: the id of a sodium key, a Vault transit key name, an ARN); "{tenant}" stands for the slug of the tenant, one master key each.')
            ->isRequired()
            ->cannotBeEmpty()
            ->end()
            ->append(self::dataKeySecrets())
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
            ->scalarNode('staging_delay')
            ->info('How long a new key is published before it signs, in seconds (architecture §3.3, §9), for every family of keys but the SAML signing key, which has its own ("saml.keys.staging_delay"); unless set, or set to an empty string, which is what an environment variable declared empty gives, jwks_max_age plus the 60 s refetch cooldown of oidc_login: the max-age is what a relying party with a warm cache needs to see the new key, the cooldown what one served by a shared HTTP cache needs to refetch it.')
            ->defaultNull()
            ->validate()
            ->always(static function (mixed $delay): mixed {
                // An environment value is a placeholder here; StagingDelay checks it when the schedule is built.
                if ($delay !== null && ! is_int($delay) && ! is_string($delay)) {
                    throw new InvalidConfigurationException('The "beffroi" configuration key "staging_delay" is a number of seconds.');
                }
                StagingDelay::seconds($delay, 0);

                return $delay;
            })
            ->end()
            ->end()
            ->integerNode('age')
            ->info('How long a key works before the planning stages a successor for it, in seconds, counted from its activation (architecture §3.3), for every family of keys but the SAML signing key, which has its own ("saml.keys.age"): ninety days by default, which is inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key and short enough that the rotation path is walked four times a year rather than first walked during an incident. It has to be longer than the window a retiring key holds the JWK Set open for, which is the longest lifetime of what a key of that use is bound to, or every rotation would leave a key behind; the rotation refuses an age that is not.')
            ->defaultValue(KeyAge::DEFAULT_SECONDS)
            ->min(1)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $keys = $this->own($config);
        $services->alias('beffroi.kms', 'key_management.' . self::string($keys, 'kms'));
        // The component traces only what it builds itself, so this encrypter is traced here; set rather than aliased,
        // because a test replaces it at runtime and an alias cannot be replaced.
        $envelopes = inline_service(EnvelopeEncrypter::class)->args([service('beffroi.kms')]);
        $services->set('beffroi.kms.envelopes', $debug ? TraceableEnvelopeEncrypter::class : EnvelopeEncrypter::class)->args(
            $debug
                ? [$envelopes, service('key_management.data_collector'), self::string($keys, 'kms')]
                : [service('beffroi.kms')],
        );
        // The stores are not tagged "kernel.reset" as the component's own is: forget() would put the KMS back on
        // the path of every request that touches a sealed column.
        $secrets = $keys['data_key_secrets'] ?? [];
        $services
            ->set('beffroi.data_keys', TenantDataKeyStores::class)
            ->factory(self::dataKeyStores(...))
            ->args([
                service(Connection::class),
                tagged_locator('key_management.client', 'key'),
                self::string($keys, 'kms'),
                self::string($keys, 'key_id'),
                $secrets,
                TenantDataKeyStores::TABLE,
            ]);
        // No maximum age for this store: an index key is never retired, every tag written being derived under it.
        $services
            ->set('beffroi.data_keys.index', TenantDataKeyStores::class)
            ->factory(self::dataKeyStores(...))
            ->args([
                service(Connection::class),
                tagged_locator('key_management.client', 'key'),
                self::string($keys, 'kms'),
                self::string($keys, 'key_id'),
                $secrets,
                TenantDataKeyStores::TABLE,
                null,
            ]);
        $services->set(TenantBlindIndexes::class)->args([
            service(Connection::class),
            service('beffroi.data_keys.index'),
            service(TenantProvider::class),
            TenantDataKeyStores::TABLE,
        ]);
        $services->set(TenantDataKeys::class)->args([service('beffroi.data_keys')]);
        $services->set(DataKeysOfTheTenant::class)->args([
            service(TenantDataKeys::class),
            service('beffroi.data_keys'),
            service(TenantBlindIndexes::class),
        ]);
        $services->set(TenantDataKeyDestruction::class)->args([
            service(Connection::class),
            service(TenantDataKeys::class),
            service(EventBusDispatcher::class),
            service(RequestContextFactory::class),
            TenantDataKeyStores::TABLE,
        ]);
        // The master key is resolved, never asked for: an operator who had to type it could type another tenant's.
        $services->get(DataKeysRewrapCommand::class)->arg('$store', service('beffroi.data_keys'))->arg('$clients', tagged_locator(
            'key_management.client',
            'key',
        ))->arg('$masterKeyId', self::string($keys, 'key_id'));
        // "onFlush", not "prePersist": prePersist fires when persist() is called and would miss a value set afterwards.
        $services->set(BlindIndexListener::class)->args([service(TenantBlindIndexes::class)])->tag('doctrine.event_listener', [
            'event' => 'onFlush',
        ]);
        // Traced here, the KMS being off the path of a sealed value, and on this path only: the decorator of the
        // component does not claim the rewrapping half the other consumers of the store need.
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
        // Lazy, so that building a sealing type, as writing the schema does, builds no KMS client.
        $services
            ->set('beffroi.personal_data.encrypter', TenantScopedEncrypter::class)
            ->lazy()
            ->args([
                service('beffroi.kms.stored_envelopes'),
                service(TenantProvider::class),
            ]);
        foreach (EncryptedColumnTypes::declarations() as $name => ['type' => $type, 'key' => $family]) {
            // A sealed value authenticates the name of the type it decorates, and would authenticate its class without it.
            $services->set('beffroi.encrypted_type.' . $name, EncryptedType::class)->args([
                inline_service(Type::class)->factory([service('doctrine.dbal.default_connection.type_provider'), 'get'])->args([$type]),
                service('beffroi.personal_data.encrypter'),
                $family,
                $type,
            ])->tag('doctrine.dbal.type', [
                'type_name' => $name,
            ]);
        }
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
        foreach (self::SECRET_SEALERS as $sealer => $purpose) {
            $services->set($sealer, EnvelopeSecretSealer::class)->args([
                '$envelopes' => service('beffroi.kms.envelopes'),
                '$kmsKeyId' => self::string($keys, 'key_id'),
                '$purpose' => $purpose,
            ]);
        }
        $services->get(FileTenantKeyRepository::class)->arg('$directory', self::string($keys, 'storage'));
        $services->get(FilePairwiseSalt::class)->arg('$directory', self::string($keys, 'storage'));
        $services->get(FileMailSigningKeyRepository::class)->arg('$directory', self::string($keys, 'storage'));
        $services->get(FileChainCheckpoints::class)->arg('$directory', self::string($keys, 'storage'));
        if ($debug) {
            $services->get(KmsClient::class)->arg('$name', self::string($keys, 'kms'));
        }
        $services->get(JwksHandler::class)->arg('$maxAge', self::integer($keys, 'jwks_max_age'));
        $services->set('beffroi.keys.rotation_schedule', RotationSchedule::class)->args([
            inline_service(DateInterval::class)
                ->factory(StagingDelay::interval(...))
                ->args([isset($keys['staging_delay']) ? self::integer($keys, 'staging_delay') : null, self::integer($keys, 'jwks_max_age')]),
            self::bounded($keys, 'age', named: 'keys.age'),
        ]);
    }

    /**
     * @param int<0, max>|null $maxAgeSeconds
     *
     * @throws InvalidConfigurationException
     */
    public static function dataKeyStores(
        Connection $connection,
        ContainerInterface $clients,
        string $client,
        string $masterKeyId,
        #[SensitiveParameter]
        mixed $secrets,
        string $table,
        ?int $maxAgeSeconds = DataKeyStore::DEFAULT_MAX_AGE_SECONDS,
    ): TenantDataKeyStores {
        return new TenantDataKeyStores($connection, $clients, $client, $masterKeyId, self::secrets($secrets), $table, $maxAgeSeconds);
    }

    private static function dataKeySecrets(): EnvironmentListDefinition
    {
        $secrets = new EnvironmentListDefinition('data_key_secrets');
        $secrets
            ->wrapsAString()
            ->info('What binds each stored data key to its reference and its scope (StoredDataKey::bindingFor() of symfony/key-management): an HMAC keyed by the data key and by a secret the database does not hold, so that whoever writes the table cannot plant a key they wrapped themselves. The first one binds a new row and every one is accepted when a row is read, so a secret is rotated by writing the new one first, running "beffroi:data-keys:rewrap" for every tenant towards the client that already wraps its keys, which binds each row again under the first, then dropping the old one. Unless set, the secret of the kernel ("kernel.secret"), which is then rotated the same way: a row whose secret is no longer listed opens nothing, nor does anything sealed under its key. An environment variable may carry one secret, which is the list of one, or the list whole, as JSON.')
            ->scalarPrototype()
            ->cannotBeEmpty()
            ->end()
            ->requiresAtLeastOneElement()
            ->defaultValue(['%kernel.secret%']);

        return $secrets;
    }

    /**
     * @throws InvalidConfigurationException
     *
     * @return non-empty-list<string> the first one binds, every one is accepted
     */
    private static function secrets(mixed $written): array
    {
        $secrets = [];
        foreach (self::dataKeySecrets()->normalized($written, 'keys.data_key_secrets') as $secret) {
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
