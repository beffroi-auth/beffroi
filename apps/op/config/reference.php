<?php

// This file is auto-generated and is for apps only. Bundles SHOULD NOT rely on its content.

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Symfony\Component\Config\Loader\ParamConfigurator as Param;

/**
 * This class provides array-shapes for configuring the services and bundles of an application.
 *
 * Services declared with the config() method below are autowired and autoconfigured by default.
 *
 * This is for apps only. Bundles SHOULD NOT use it.
 *
 * Example:
 *
 *     ```php
 *     // config/services.php
 *     namespace Symfony\Component\DependencyInjection\Loader\Configurator;
 *
 *     return App::config([
 *         'services' => [
 *             'App\\' => [
 *                 'resource' => '../src/',
 *             ],
 *         ],
 *     ]);
 *     ```
 *
 * @psalm-type ImportsConfig = list<string|array{
 *     resource: string,
 *     type?: string|null,
 *     ignore_errors?: bool|'not_found',
 * }>
 * @psalm-type ParametersConfig = array<string, scalar|\UnitEnum|array<scalar|\UnitEnum|array<mixed>|Param|null>|Param|null>
 * @psalm-type ArgumentsType = list<mixed>|array<string, mixed>
 * @psalm-type CallType = array<string, ArgumentsType>|array{0:string, 1?:ArgumentsType, 2?:bool}|array{method:string, arguments?:ArgumentsType, returns_clone?:bool}
 * @psalm-type TagsType = list<string|array<string, array<string, mixed>>> // arrays inside the list must have only one element, with the tag name as the key
 * @psalm-type CallbackType = string|array{0:string|ReferenceConfigurator,1:string}|\Closure|ReferenceConfigurator
 * @psalm-type DeprecationType = array{package: string, version: string, message?: string}
 * @psalm-type DefaultsType = array{
 *     public?: bool,
 *     tags?: TagsType,
 *     resource_tags?: TagsType,
 *     autowire?: bool,
 *     autoconfigure?: bool,
 *     bind?: array<string, mixed>,
 * }
 * @psalm-type InstanceofType = array{
 *     shared?: bool,
 *     lazy?: bool|string,
 *     public?: bool,
 *     factory?: CallbackType,
 *     properties?: array<string, mixed>,
 *     configurator?: CallbackType,
 *     calls?: list<CallType>,
 *     tags?: TagsType,
 *     resource_tags?: TagsType,
 *     autowire?: bool,
 *     bind?: array<string, mixed>,
 *     constructor?: string,
 * }
 * @psalm-type DefinitionType = array{
 *     class?: string,
 *     file?: string,
 *     parent?: string,
 *     shared?: bool,
 *     synthetic?: bool,
 *     lazy?: bool|string,
 *     public?: bool,
 *     abstract?: bool,
 *     deprecated?: DeprecationType,
 *     factory?: CallbackType,
 *     configurator?: CallbackType,
 *     arguments?: ArgumentsType,
 *     properties?: array<string, mixed>,
 *     calls?: list<CallType>,
 *     tags?: TagsType,
 *     resource_tags?: TagsType,
 *     decorates?: string,
 *     decorates_tag?: string,
 *     decoration_within?: string|list<string>,
 *     decoration_around?: string|list<string>,
 *     decoration_inner_name?: string,
 *     decoration_priority?: int,
 *     decoration_on_invalid?: 'exception'|'ignore'|null,
 *     autowire?: bool,
 *     autoconfigure?: bool,
 *     bind?: array<string, mixed>,
 *     constructor?: string,
 *     from_callable?: CallbackType,
 * }
 * @psalm-type AliasType = string|array{
 *     alias: string,
 *     public?: bool,
 *     deprecated?: DeprecationType,
 * }
 * @psalm-type PrototypeType = array{
 *     resource: string,
 *     namespace?: string,
 *     exclude?: string|list<string>,
 *     parent?: string,
 *     shared?: bool,
 *     lazy?: bool|string,
 *     public?: bool,
 *     abstract?: bool,
 *     deprecated?: DeprecationType,
 *     factory?: CallbackType,
 *     arguments?: ArgumentsType,
 *     properties?: array<string, mixed>,
 *     configurator?: CallbackType,
 *     calls?: list<CallType>,
 *     tags?: TagsType,
 *     resource_tags?: TagsType,
 *     autowire?: bool,
 *     autoconfigure?: bool,
 *     bind?: array<string, mixed>,
 *     constructor?: string,
 * }
 * @psalm-type StackType = array{
 *     stack: list<DefinitionType|AliasType|PrototypeType|array<class-string, ArgumentsType|null>>,
 *     public?: bool,
 *     deprecated?: DeprecationType,
 *     decorates?: string,
 *     decorates_tag?: string,
 *     decoration_within?: string|list<string>,
 *     decoration_around?: string|list<string>,
 *     decoration_inner_name?: string,
 *     decoration_priority?: int,
 *     decoration_on_invalid?: 'exception'|'ignore'|null,
 * }
 * @psalm-type ServicesConfig = array{
 *     _defaults?: DefaultsType,
 *     _instanceof?: array<class-string, InstanceofType>,
 *     ...<string, DefinitionType|AliasType|PrototypeType|StackType|ArgumentsType|null>
 * }
 * @psalm-type ExtensionType = array<mixed>|scalar|\UnitEnum|Param|null
 * @psalm-type RouterConfig = bool|array{
 *     enabled?: bool|Param, // Default: false
 *     resource?: scalar|Param|null, // Default: null
 *     type?: scalar|Param|null,
 *     default_uri?: scalar|Param|null, // The default URI used to generate URLs in a non-HTTP context. // Default: null
 *     http_port?: scalar|Param|null, // Default: 80
 *     https_port?: scalar|Param|null, // Default: 443
 *     strict_requirements?: scalar|Param|null, // set to true to throw an exception when a parameter does not match the requirements set to false to disable exceptions when a parameter does not match the requirements (and return null instead) set to null to disable parameter checks against requirements 'true' is the preferred configuration in development mode, while 'false' or 'null' might be preferred in production // Default: true
 *     utf8?: bool|Param, // Default: true
 * }
 * @psalm-type CacheConfig = array{
 *     prefix_seed?: scalar|Param|null, // Used to namespace cache keys when using several apps with the same shared backend. // Default: "_%kernel.project_dir%.%kernel.container_class%"
 *     app?: scalar|Param|null, // App related cache pools configuration. Cannot be combined with "default_provider". // Default: "cache.adapter.filesystem"
 *     system?: scalar|Param|null, // System related cache pools configuration. // Default: "cache.adapter.system"
 *     directory?: scalar|Param|null, // Default: "%kernel.share_dir%/pools/app"
 *     default_provider?: scalar|Param|null, // DSN of the backend to use for "cache.app"; the adapter is deduced from it. Replaces "app", which cannot be set alongside it.
 *     default_psr6_provider?: scalar|Param|null,
 *     default_redis_provider?: scalar|Param|null, // Default: "redis://localhost"
 *     default_valkey_provider?: scalar|Param|null, // Default: "valkey://localhost"
 *     default_memcached_provider?: scalar|Param|null, // Default: "memcached://localhost"
 *     default_doctrine_dbal_provider?: scalar|Param|null, // Default: "database_connection"
 *     default_pdo_provider?: scalar|Param|null, // Default: null
 *     default_mongodb_provider?: scalar|Param|null, // Default: "mongodb://localhost/app"
 *     pools?: array<string, array{ // Default: []
 *         adapters?: Param|string|list<scalar|Param|null>,
 *         tags?: scalar|Param|null, // Default: null
 *         public?: bool|Param, // Default: false
 *         default_lifetime?: scalar|Param|null, // Default lifetime of the pool.
 *         provider?: scalar|Param|null, // Overwrite the setting from the default provider for this adapter.
 *         early_expiration_message_bus?: scalar|Param|null,
 *         clearer?: scalar|Param|null,
 *         marshaller?: scalar|Param|null, // The marshaller service to use for this pool.
 *     }>,
 * }
 * @psalm-type AssetConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     strict_mode?: bool|Param, // Throw an exception if an entry is missing from the manifest.json. // Default: false
 *     version_strategy?: scalar|Param|null, // Default: null
 *     version?: scalar|Param|null, // Default: null
 *     version_format?: scalar|Param|null, // Default: "%%s?%%s"
 *     json_manifest_path?: scalar|Param|null, // Default: null
 *     base_path?: scalar|Param|null, // Default: ""
 *     base_urls?: Param|string|list<scalar|Param|null>,
 *     packages?: array<string, array{ // Default: []
 *         strict_mode?: bool|Param, // Throw an exception if an entry is missing from the manifest.json. // Default: false
 *         version_strategy?: scalar|Param|null, // Default: null
 *         version?: scalar|Param|null,
 *         version_format?: scalar|Param|null, // Default: null
 *         json_manifest_path?: scalar|Param|null, // Default: null
 *         base_path?: scalar|Param|null, // Default: ""
 *         base_urls?: Param|string|list<scalar|Param|null>,
 *     }>,
 * }
 * @psalm-type SerializerConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     enable_attributes?: bool|Param, // Default: true
 *     name_converter?: scalar|Param|null,
 *     circular_reference_handler?: scalar|Param|null,
 *     max_depth_handler?: scalar|Param|null,
 *     mapping?: array{
 *         paths?: list<scalar|Param|null>,
 *     },
 *     default_context?: array<string, mixed>,
 *     named_serializers?: array<string, array{ // Default: []
 *         name_converter?: scalar|Param|null,
 *         default_context?: array<string, mixed>,
 *         include_built_in_normalizers?: bool|Param, // Whether to include the built-in normalizers // Default: true
 *         include_built_in_encoders?: bool|Param, // Whether to include the built-in encoders // Default: true
 *     }>,
 * }
 * @psalm-type ValidationConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     enable_attributes?: bool|Param, // Default: true
 *     static_method?: Param|string|list<scalar|Param|null>,
 *     translation_domain?: scalar|Param|null, // Default: "validators"
 *     email_validation_mode?: "html5"|"html5-allow-no-tld"|"strict"|Param, // Default: "html5"
 *     mapping?: array{
 *         paths?: list<scalar|Param|null>,
 *     },
 *     not_compromised_password?: bool|array{
 *         enabled?: bool|Param, // When disabled, compromised passwords will be accepted as valid. // Default: true
 *         endpoint?: scalar|Param|null, // API endpoint for the NotCompromisedPassword Validator. // Default: null
 *     },
 *     disable_translation?: bool|Param, // Default: false
 *     property_metadata_existence_check?: bool|Param, // When enabled, validateProperty() and validatePropertyValue() throw an exception if no metadata is found for the given property. // Default: false
 *     auto_mapping?: array<string, array{ // Default: []
 *         services?: list<scalar|Param|null>,
 *     }>,
 * }
 * @psalm-type TranslationConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     fallbacks?: Param|string|list<scalar|Param|null>,
 *     logging?: bool|Param, // Default: false
 *     formatter?: scalar|Param|null, // Default: "translator.formatter.default"
 *     cache_dir?: scalar|Param|null, // Default: "%kernel.cache_dir%/translations"
 *     default_path?: scalar|Param|null, // The default path used to load translations. // Default: "%kernel.project_dir%/translations"
 *     paths?: list<scalar|Param|null>,
 *     pseudo_localization?: bool|array{
 *         enabled?: bool|Param, // Default: false
 *         accents?: bool|Param, // Default: true
 *         expansion_factor?: float|Param, // Default: 1.0
 *         brackets?: bool|Param, // Default: true
 *         parse_html?: bool|Param, // Default: false
 *         localizable_html_attributes?: list<scalar|Param|null>,
 *     },
 *     providers?: array<string, array{ // Default: []
 *         dsn?: scalar|Param|null,
 *         domains?: array<string, scalar|Param|null>,
 *         locales?: list<scalar|Param|null>,
 *     }>,
 *     globals?: array<string, Param|string|array{ // Default: []
 *         value?: mixed,
 *         message?: string|Param,
 *         parameters?: array<string, scalar|Param|null>,
 *         domain?: string|Param,
 *     }>,
 * }
 * @psalm-type MessengerConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     routing?: array<string, Param|string|list<scalar|Param|null>>,
 *     serializer?: array{
 *         default_serializer?: scalar|Param|null, // Service id to use as the default serializer for the transports. // Default: "messenger.transport.native_php_serializer"
 *         signing_secret?: Param|string|list<scalar|Param|null>,
 *         symfony_serializer?: array{
 *             service?: scalar|Param|null, // Service id of the Symfony serializer behind the messenger.transport.symfony_serializer service, e.g. "serializer.api" for the named serializer "api". // Default: null
 *             format?: scalar|Param|null, // Serialization format for the messenger.transport.symfony_serializer service (which is not the serializer used by default). // Default: "json"
 *             context?: array<string, mixed>,
 *         },
 *     },
 *     transports?: array<string, Param|string|array{ // Default: []
 *         dsn?: scalar|Param|null,
 *         serializer?: scalar|Param|null, // Service id of a custom serializer to use. // Default: null
 *         sign?: bool|Param, // Whether to sign every message sent to this transport with its trust level, and to refuse any message received from it that is unsigned, or signed as unverified when this is not a failure transport. When false, only the messages whose handlers ask for it are signed. // Default: false
 *         claim_check?: array{
 *             cache_pool?: scalar|Param|null, // Service id of the dedicated cache pool used to store claims. Pools declared under "framework.cache.pools" must define a "default_lifetime".
 *             max_size?: int|Param, // Maximum encoded message size in bytes before using a claim check.
 *         },
 *         options?: array<string, mixed>,
 *         failure_transport?: scalar|Param|null, // Transport name to send failed messages to (after all retries have failed). // Default: null
 *         outbox?: scalar|Param|null, // Name of the transport that stores the messages inside the current database transaction; consume that transport to forward them to this one. // Default: null
 *         retry_strategy?: Param|string|array{
 *             service?: scalar|Param|null, // Service id to override the retry strategy entirely. // Default: null
 *             max_retries?: int|Param, // Default: 3
 *             delay?: int|Param, // Time in ms to delay (or the initial value when multiplier is used). // Default: 1000
 *             multiplier?: float|Param, // If greater than 1, delay will grow exponentially for each retry: this delay = (delay * (multiple ^ retries)). // Default: 2
 *             max_delay?: int|Param, // Max time in ms that a retry should ever be delayed (0 = infinite). // Default: 0
 *             jitter?: float|Param, // Randomness to apply to the delay (between 0 and 1). // Default: 0.1
 *         },
 *         rate_limiter?: scalar|Param|null, // Rate limiter name to use when processing messages. // Default: null
 *         priority?: int|Param, // Order in which "messenger:consume --all" consumes this transport, higher comes first. // Default: 0
 *     }>,
 *     failure_transport?: scalar|Param|null, // Transport name to send failed messages to (after all retries have failed). // Default: null
 *     stop_worker_on_signals?: Param|int|string|list<scalar|Param|null>,
 *     reject_redelivered_messages?: bool|Param, // Whether redeliveries should be rejected and retried through a new message instead of being handled directly. This mostly makes sense for AMQP, which redelivers messages that were neither acknowledged nor rejected. Disabling it avoids losing a message when the retry or the failure transport is unreachable, at the risk of a redelivery loop that blocks the queue. // Default: true
 *     deduplication?: array{
 *         lock_factory?: scalar|Param|null, // The service ID of the lock factory used to deduplicate messages, "lock.factory" when not set. // Default: null
 *     },
 *     identity_stamps?: bool|Param, // Adds a message id and a causation id to dispatched messages, and a correlation id at the start of each flow. // Default: false
 *     default_bus?: scalar|Param|null, // Default: null
 *     buses?: array<string, array{ // Default: {"messenger.bus.default":{"default_middleware":{"enabled":true,"allow_no_handlers":false,"allow_no_senders":true},"middleware":[],"messages":[],"unwrap_exceptions":false}}
 *         default_middleware?: Param|bool|string|array{
 *             enabled?: bool|Param, // Default: true
 *             allow_no_handlers?: bool|Param, // Default: false
 *             allow_no_senders?: bool|Param, // Default: true
 *         },
 *         middleware?: Param|string|list<Param|string|array{ // Default: []
 *             id?: scalar|Param|null,
 *             arguments?: list<mixed>,
 *         }>,
 *         messages?: Param|string|list<scalar|Param|null>,
 *         unwrap_exceptions?: bool|Param, // Whether the application gets the exception of the failing handler instead of a HandlerFailedException when it dispatches a message. // Default: false
 *     }>,
 * }
 * @psalm-type TypeInfoConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     aliases?: array<string, scalar|Param|null>,
 * }
 * @psalm-type PropertyAccessConfig = bool|array{ // Property access configuration
 *     enabled?: bool|Param, // Default: true
 *     magic_call?: bool|Param, // Default: false
 *     magic_get?: bool|Param, // Default: true
 *     magic_set?: bool|Param, // Default: true
 *     throw_exception_on_invalid_index?: bool|Param, // Default: false
 *     throw_exception_on_invalid_property_path?: bool|Param, // Default: true
 *     wildcard_reads?: bool|Param, // Enables reading every element of a collection through a "[*]" wildcard. // Default: false
 * }
 * @psalm-type PropertyInfoConfig = bool|array{ // Property info configuration
 *     enabled?: bool|Param, // Default: true
 *     with_constructor_extractor?: bool|Param, // Registers the constructor extractor. // Default: true
 * }
 * @psalm-type UidConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     default_uuid_version?: 7|6|4|1|Param, // Default: 7
 *     name_based_uuid_version?: 5|3|Param, // Default: 5
 *     name_based_uuid_namespace?: scalar|Param|null,
 *     time_based_uuid_version?: 7|6|1|Param, // Default: 7
 *     time_based_uuid_node?: scalar|Param|null,
 *     uuid47_secret?: scalar|Param|null, // A high-entropy secret used by the "uuid47_transformer" service. Defaults to the "kernel.secret" parameter; the service is not registered when neither is defined. // Default: null
 * }
 * @psalm-type SchedulerConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     use_messenger_routing?: bool|Param|null, // Whether scheduled messages are routed to the Messenger senders configured for their class, as any other dispatched message is. A class with no sender configured still runs in the scheduler worker, and a "transports" option set on a task still wins. // Default: null
 *     schedules?: array<string, array{ // Default: []
 *         stateful?: bool|Param, // Whether the schedule keeps its state in the "cache.scheduler" pool and, when locks are enabled, runs in only one worker at a time. // Default: false
 *         cache_pool?: scalar|Param|null, // The cache pool that stores the state of the schedule, so that a restarted worker resumes where the previous one stopped. // Default: null
 *         lock_factory?: scalar|Param|null, // The service ID of the lock factory used to run the schedule in only one worker at a time. // Default: null
 *         process_only_last_missed_run?: bool|Param, // Whether a task that missed several runs runs only once instead of once per missed run. // Default: false
 *     }>,
 * }
 * @psalm-type AssetMapperConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     paths?: Param|string|array<string, scalar|Param|null>,
 *     excluded_patterns?: list<scalar|Param|null>,
 *     exclude_dotfiles?: bool|Param, // If true, any files starting with "." will be excluded from the asset mapper. // Default: true
 *     server?: bool|Param, // If true, a "dev server" will return the assets from the public directory (true in "debug" mode only by default). // Default: "%kernel.debug%"
 *     public_prefix?: scalar|Param|null, // The public path where the assets will be written to (and served from when "server" is true). // Default: "/assets/"
 *     metadata_dir?: scalar|Param|null, // The directory where "asset-map:compile" writes manifest.json, importmap.json and entrypoint.*.json. These files are read by PHP only, so they do not need to be exposed to the browser. // Default: null
 *     missing_import_mode?: "strict"|"warn"|"ignore"|Param, // Behavior if an asset cannot be found when imported from JavaScript or CSS files - e.g. "import './non-existent.js'". "strict" means an exception is thrown, "warn" means a warning is logged, "ignore" means the import is left as-is. // Default: "warn"
 *     extensions?: array<string, scalar|Param|null>,
 *     importmap_path?: scalar|Param|null, // The path of the importmap.php file. // Default: "%kernel.project_dir%/importmap.php"
 *     importmap_polyfill?: scalar|Param|null, // The importmap name that will be used to load the polyfill. Set to false to disable. // Default: "es-module-shims"
 *     importmap_entries?: "all"|"reachable"|Param, // Which entries end up in the rendered importmap: "all" of them, or only the ones "reachable" from the rendered entrypoints (their eager and lazy import chains) plus the polyfill. // Default: "all"
 *     importmap_script_attributes?: array<string, scalar|Param|null>,
 *     importmap_integrity_algorithms?: list<"sha256"|"sha384"|"sha512"|Param>,
 *     vendor_dir?: scalar|Param|null, // The directory to store JavaScript vendors. // Default: "%kernel.project_dir%/assets/vendor"
 *     minimum_release_age?: int|Param, // Minimum age in seconds a package version must have to be considered when checking for updates (0 disables the check). Enabling it makes update checks download the full npm metadata document, which is larger than the abbreviated one. // Default: 0
 *     precompress?: bool|array{ // Precompress assets with Brotli, Zstandard and gzip.
 *         enabled?: bool|Param, // Default: false
 *         formats?: list<scalar|Param|null>,
 *         extensions?: list<scalar|Param|null>,
 *     },
 * }
 * @psalm-type RateLimiterConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     builder?: array{ // Configuration for the RateLimiterBuilder service.
 *         lock_factory?: scalar|Param|null, // The service ID of the lock factory to use with the RateLimiterBuilder. // Default: "auto"
 *         cache_pool?: scalar|Param|null, // The cache pool to use with RateLimiterBuilder. // Default: "cache.rate_limiter"
 *         storage_service?: scalar|Param|null, // The service ID of a custom storage implementation, this precedes any configured "cache_pool". // Default: null
 *     },
 *     limiters?: array<string, array{ // Default: []
 *         lock_factory?: scalar|Param|null, // The service ID of the lock factory used by this limiter (or null to disable locking). // Default: "auto"
 *         cache_pool?: scalar|Param|null, // The cache pool to use for storing the current limiter state. // Default: "cache.rate_limiter"
 *         storage_service?: scalar|Param|null, // The service ID of a custom storage implementation, this precedes any configured "cache_pool". // Default: null
 *         policy?: "fixed_window"|"token_bucket"|"sliding_window"|"compound"|"no_limit"|Param, // The algorithm to be used by this limiter.
 *         limiters?: Param|string|array<string, array{ // Default: []
 *             key?: scalar|Param|null, // The key to pass to this limiter, instead of the one passed to the compound limiter's create() method. // Default: null
 *         }>,
 *         limit?: int|Param, // The maximum allowed hits in a fixed interval or burst.
 *         interval?: scalar|Param|null, // Configures the fixed interval if "policy" is set to "fixed_window" or "sliding_window". The value must be a number followed by "second", "minute", "hour", "day", "week" or "month" (or their plural equivalent).
 *         rate?: array{ // Configures the fill rate if "policy" is set to "token_bucket".
 *             interval?: scalar|Param|null, // Configures the rate interval. The value must be a number followed by "second", "minute", "hour", "day", "week" or "month" (or their plural equivalent).
 *             amount?: int|Param, // Amount of tokens to add each interval. // Default: 1
 *         },
 *         anchor_at?: scalar|Param|null, // Aligns the "fixed_window" policy to a calendar (e.g. "2024-01-05 00:00:00 UTC" combined with `interval: 1 month` resets the counter on the 5th of each month). UTC if not specified. // Default: null
 *     }>,
 * }
 * @psalm-type HttpClientConfig = bool|array{
 *     enabled?: bool|Param, // Default: true
 *     max_host_connections?: int|Param, // The maximum number of connections to a single host.
 *     recorder?: bool|array{ // Record HTTP exchanges into HAR files and replay them in tests (see RecorderHttpClient).
 *         enabled?: bool|Param, // Default: false
 *         redactor?: scalar|Param|null, // Service id of a RedactorInterface; when set, "redact" and "redact_except" are ignored. // Default: null
 *         redact?: list<scalar|Param|null>,
 *         redact_except?: list<scalar|Param|null>,
 *     },
 *     default_options?: array{
 *         vars?: array<string, mixed>,
 *         headers?: array<string, mixed>,
 *         max_redirects?: int|Param, // The maximum number of redirects to follow.
 *         http_version?: scalar|Param|null, // The default HTTP version, typically 1.1 or 2.0, leave to null for the best version.
 *         resolve?: array<string, scalar|Param|null>,
 *         proxy?: scalar|Param|null, // The URL of the proxy to pass requests through or null for automatic detection.
 *         no_proxy?: scalar|Param|null, // A comma separated list of hosts that do not require a proxy to be reached.
 *         timeout?: float|Param, // The idle timeout, defaults to the "default_socket_timeout" ini parameter.
 *         max_duration?: float|Param, // The maximum execution time for the request+response as a whole.
 *         max_connect_duration?: float|Param, // The maximum duration allowed for DNS + TCP + TLS connection; a value lower than or equal to 0 means unlimited.
 *         bindto?: scalar|Param|null, // A network interface name, IP address, a host name or a UNIX socket to bind to.
 *         verify_peer?: bool|Param, // Indicates if the peer should be verified in a TLS context.
 *         verify_host?: bool|Param, // Indicates if the host should exist as a certificate common name.
 *         cafile?: scalar|Param|null, // A certificate authority file.
 *         capath?: scalar|Param|null, // A directory that contains multiple certificate authority files.
 *         local_cert?: scalar|Param|null, // A PEM formatted certificate file.
 *         local_pk?: scalar|Param|null, // A private key file.
 *         passphrase?: scalar|Param|null, // The passphrase used to encrypt the "local_pk" file.
 *         ciphers?: scalar|Param|null, // A list of TLS ciphers separated by colons, commas or spaces (e.g. "RC3-SHA:TLS13-AES-128-GCM-SHA256"...).
 *         peer_fingerprint?: array{ // Associative array: hashing algorithm => hash(es).
 *             sha1?: mixed,
 *             pin-sha256?: mixed,
 *             md5?: mixed,
 *         },
 *         crypto_method?: scalar|Param|null, // The minimum version of TLS to accept; must be one of STREAM_CRYPTO_METHOD_TLSv*_CLIENT constants.
 *         extra?: array<string, mixed>,
 *         rate_limiter?: scalar|Param|null, // Rate limiter name to use for throttling requests. // Default: null
 *         caching?: bool|array{ // Caching configuration.
 *             enabled?: bool|Param, // Default: false
 *             cache_pool?: string|Param, // The taggable cache pool to use for storing the responses. // Default: "cache.http_client"
 *             shared?: bool|Param, // Indicates whether the cache is shared (public) or private. // Default: true
 *             max_ttl?: int|Param, // The maximum TTL (in seconds) allowed for cached responses. // Default: 86400
 *         },
 *         retry_failed?: bool|array{
 *             enabled?: bool|Param, // Default: false
 *             base_uris?: Param|string|list<string|Param>,
 *             retry_strategy?: scalar|Param|null, // service id to override the retry strategy. // Default: null
 *             http_codes?: Param|int|string|array<string, array{ // Default: []
 *                 code?: int|Param,
 *                 methods?: Param|string|list<string|Param>,
 *             }>,
 *             max_retries?: int|Param, // Default: 3
 *             delay?: int|Param, // Time in ms to delay (or the initial value when multiplier is used). // Default: 1000
 *             multiplier?: float|Param, // If greater than 1, delay will grow exponentially for each retry: delay * (multiple ^ retries). // Default: 2
 *             max_delay?: int|Param, // Max time in ms that a retry should ever be delayed (0 = infinite). // Default: 0
 *             jitter?: float|Param, // Randomness in percent (between 0 and 1) to apply to the delay. // Default: 0.1
 *         },
 *     },
 *     mock_response_factory?: scalar|Param|null, // `true` to always return empty 200 responses, or the id of the service to use to generate mock responses - which should be either an invokable or an iterable.
 *     scoped_clients?: array<string, Param|string|array{ // Default: []
 *         scope?: scalar|Param|null, // The regular expression that the request URL must match before adding the other options. When none is provided, the base URI is used instead.
 *         base_uri?: scalar|Param|null, // The URI to resolve relative URLs, following rules in RFC 3985, section 2.
 *         auth_basic?: scalar|Param|null, // An HTTP Basic authentication "username:password".
 *         auth_bearer?: scalar|Param|null, // A token enabling HTTP Bearer authorization.
 *         auth_ntlm?: scalar|Param|null, // A "username:password" pair to use Microsoft NTLM authentication (requires the cURL extension).
 *         query?: array<string, scalar|Param|null>,
 *         mock_response_factory?: scalar|Param|null, // `true` to always return empty 200 responses, `false` to disable mocking, or the id of the service to use to generate mock responses (invokable or iterable).
 *         headers?: array<string, mixed>,
 *         max_redirects?: int|Param, // The maximum number of redirects to follow.
 *         http_version?: scalar|Param|null, // The default HTTP version, typically 1.1 or 2.0, leave to null for the best version.
 *         resolve?: array<string, scalar|Param|null>,
 *         proxy?: scalar|Param|null, // The URL of the proxy to pass requests through or null for automatic detection.
 *         no_proxy?: scalar|Param|null, // A comma separated list of hosts that do not require a proxy to be reached.
 *         timeout?: float|Param, // The idle timeout, defaults to the "default_socket_timeout" ini parameter.
 *         max_duration?: float|Param, // The maximum execution time for the request+response as a whole.
 *         max_connect_duration?: float|Param, // The maximum duration allowed for DNS + TCP + TLS connection; a value lower than or equal to 0 means unlimited.
 *         bindto?: scalar|Param|null, // A network interface name, IP address, a host name or a UNIX socket to bind to.
 *         verify_peer?: bool|Param, // Indicates if the peer should be verified in a TLS context.
 *         verify_host?: bool|Param, // Indicates if the host should exist as a certificate common name.
 *         cafile?: scalar|Param|null, // A certificate authority file.
 *         capath?: scalar|Param|null, // A directory that contains multiple certificate authority files.
 *         local_cert?: scalar|Param|null, // A PEM formatted certificate file.
 *         local_pk?: scalar|Param|null, // A private key file.
 *         passphrase?: scalar|Param|null, // The passphrase used to encrypt the "local_pk" file.
 *         ciphers?: scalar|Param|null, // A list of TLS ciphers separated by colons, commas or spaces (e.g. "RC3-SHA:TLS13-AES-128-GCM-SHA256"...).
 *         peer_fingerprint?: array{ // Associative array: hashing algorithm => hash(es).
 *             sha1?: mixed,
 *             pin-sha256?: mixed,
 *             md5?: mixed,
 *         },
 *         crypto_method?: scalar|Param|null, // The minimum version of TLS to accept; must be one of STREAM_CRYPTO_METHOD_TLSv*_CLIENT constants.
 *         extra?: array<string, mixed>,
 *         rate_limiter?: scalar|Param|null, // Rate limiter name to use for throttling requests. // Default: null
 *         caching?: bool|array{ // Caching configuration.
 *             enabled?: bool|Param, // Default: false
 *             cache_pool?: string|Param, // The taggable cache pool to use for storing the responses. // Default: "cache.http_client"
 *             shared?: bool|Param, // Indicates whether the cache is shared (public) or private. // Default: true
 *             max_ttl?: int|Param, // The maximum TTL (in seconds) allowed for cached responses. // Default: 86400
 *         },
 *         retry_failed?: bool|array{
 *             enabled?: bool|Param, // Default: false
 *             base_uris?: Param|string|list<string|Param>,
 *             retry_strategy?: scalar|Param|null, // service id to override the retry strategy. // Default: null
 *             http_codes?: Param|int|string|array<string, array{ // Default: []
 *                 code?: int|Param,
 *                 methods?: Param|string|list<string|Param>,
 *             }>,
 *             max_retries?: int|Param, // Default: 3
 *             delay?: int|Param, // Time in ms to delay (or the initial value when multiplier is used). // Default: 1000
 *             multiplier?: float|Param, // If greater than 1, delay will grow exponentially for each retry: delay * (multiple ^ retries). // Default: 2
 *             max_delay?: int|Param, // Max time in ms that a retry should ever be delayed (0 = infinite). // Default: 0
 *             jitter?: float|Param, // Randomness in percent (between 0 and 1) to apply to the delay. // Default: 0.1
 *         },
 *     }>,
 * }
 * @psalm-type KeyManagementConfig = Param|bool|string|array{
 *     enabled?: bool|Param, // Default: true
 *     default_client?: scalar|Param|null, // Name of the default client (must match an entry of "clients"); inferred when only one client is registered. // Default: null
 *     clients?: Param|string|array<string, Param|string|array{ // Default: []
 *         dsn?: string|Param,
 *         members?: array<string, scalar|Param|null>,
 *         retired?: list<scalar|Param|null>,
 *     }>,
 *     store?: array{ // Data key store: payloads then refer to a stored data key instead of carrying it, so the KMS is reached once per key and per process, and that key can be rewrapped under another provider without rewriting a payload.
 *         connection?: scalar|Param|null, // Service id of the DBAL connection holding the table. // Default: "doctrine.dbal.default_connection"
 *         client?: scalar|Param|null, // Name of the client wrapping the data keys this store creates (must match an entry of "clients"); defaults to the default client. // Default: null
 *         allowed_clients?: list<scalar|Param|null>,
 *         key_id?: scalar|Param|null, // Master key wrapping the data keys this store creates (backend-specific: alias, ARN, key URL, ...).
 *         secret?: Param|string|list<scalar|Param|null>,
 *         table?: scalar|Param|null, // Name of the table holding the wrapped data keys. // Default: "key_management_data_keys"
 *         read_self_contained?: bool|Param, // Whether a payload carrying its own wrapped data key is still read, through the default client. On while migrating to the stored format, off afterwards: such a payload resolves no row, so nothing the store checks applies to it. // Default: false
 *         bind_wrapping_context?: bool|Param, // Whether the backend authenticates the reference and the scope of each data key as it wraps it. Off by default: not every backend accepts authenticated data, and turning it on needs the stored keys rewrapped. // Default: false
 *         max_age?: mixed, // Seconds after which the current data key of a scope is retired; this does not enforce a usage limit. The default is 30 days; 0 forces rotation on every call and null disables retirement. // Default: 2592000
 *     },
 *     doctrine_dbal?: array{
 *         types?: array<string, array{ // Default: []
 *             type?: string|Param, // Doctrine type converting the value before it is encrypted.
 *             key?: string|Param, // Master key encrypting the values, or the scope of their data key when "store" is configured.
 *         }>,
 *     },
 * }
 * @psalm-type FrameworkConfig = array{
 *     secret?: scalar|Param|null, // A secret that must not change. The options that sign data default to it and take a list of secrets to rotate theirs.
 *     http_method_override?: bool|Param, // Set true to enable support for the '_method' request parameter to determine the intended HTTP method on POST requests. // Default: false
 *     allowed_http_method_override?: null|list<string|Param>,
 *     trust_x_sendfile_type_header?: scalar|Param|null, // Set true to enable support for xsendfile in binary file responses. // Default: "%env(bool:default::SYMFONY_TRUST_X_SENDFILE_TYPE_HEADER)%"
 *     ide?: scalar|Param|null, // Deprecated: Setting the "framework.ide.ide" configuration option is deprecated, use the "SYMFONY_IDE" env var instead. // Default: null
 *     test?: bool|Param,
 *     default_locale?: scalar|Param|null, // Default: "en"
 *     set_locale_from_accept_language?: bool|Param, // Whether to use the Accept-Language HTTP header to set the Request locale (only when the "_locale" request attribute is not passed). // Default: false
 *     set_content_language_from_locale?: bool|Param, // Whether to set the Content-Language HTTP header on the Response using the Request locale. // Default: false
 *     enabled_locales?: list<scalar|Param|null>,
 *     trusted_hosts?: Param|string|list<scalar|Param|null>,
 *     trusted_proxies?: mixed, // Default: ["%env(default::SYMFONY_TRUSTED_PROXIES)%"]
 *     trusted_headers?: Param|string|list<scalar|Param|null>,
 *     error_controller?: scalar|Param|null, // Default: "error_controller"
 *     handle_all_throwables?: bool|Param, // HttpKernel will handle all kinds of \Throwable. // Default: true
 *     csrf_protection?: bool|array{
 *         enabled?: scalar|Param|null, // Default: null
 *         stateless_token_ids?: list<scalar|Param|null>,
 *         check_header?: scalar|Param|null, // Whether to check the CSRF token in a header in addition to a cookie when using stateless protection. // Default: false
 *         cookie_name?: scalar|Param|null, // The name of the cookie to use when using stateless protection. // Default: "csrf-token"
 *     },
 *     form?: bool|array{ // Form configuration
 *         enabled?: bool|Param, // Default: true
 *         csrf_protection?: bool|array{
 *             enabled?: scalar|Param|null, // Default: null
 *             token_id?: scalar|Param|null, // Default: null
 *             field_name?: scalar|Param|null, // Default: "_token"
 *             field_attr?: array<string, scalar|Param|null>,
 *         },
 *     },
 *     http_cache?: bool|array{ // HTTP cache configuration
 *         enabled?: bool|Param, // Default: false
 *         debug?: bool|Param, // Default: "%kernel.debug%"
 *         trace_level?: "none"|"short"|"full"|Param,
 *         trace_header?: scalar|Param|null,
 *         cache_status?: scalar|Param|null, // Enables the RFC 9211 "Cache-Status" response header and names this cache in it, e.g. "Symfony". No header is added when null.
 *         default_ttl?: int|Param,
 *         private_headers?: list<scalar|Param|null>,
 *         skip_response_headers?: list<scalar|Param|null>,
 *         allow_reload?: bool|Param,
 *         allow_revalidate?: bool|Param,
 *         stale_while_revalidate?: int|Param,
 *         stale_if_error?: int|Param,
 *         terminate_on_cache_hit?: bool|Param, // Deprecated: Setting the "framework.http_cache.terminate_on_cache_hit.terminate_on_cache_hit" configuration option is deprecated. It will be removed in version 9.0.
 *     },
 *     esi?: bool|array{ // ESI configuration
 *         enabled?: bool|Param, // Default: false
 *     },
 *     ssi?: bool|array{ // SSI configuration
 *         enabled?: bool|Param, // Default: false
 *     },
 *     fragments?: bool|array{ // Fragments configuration
 *         enabled?: bool|Param, // Default: false
 *         hinclude_default_template?: scalar|Param|null, // Deprecated: Setting the "framework.fragments.hinclude_default_template.hinclude_default_template" configuration option is deprecated. It will be removed in version 9.0. // Default: null
 *         path?: scalar|Param|null, // Default: "/_fragment"
 *     },
 *     uri_signer?: array{ // URI signer configuration
 *         secret?: Param|string|list<scalar|Param|null>,
 *         expiration?: int|Param, // Default expiration of signed URIs, in seconds. // Default: null
 *     },
 *     profiler?: bool|array{ // Profiler configuration
 *         enabled?: bool|Param, // Default: false
 *         collect?: bool|Param, // Default: true
 *         collect_parameter?: scalar|Param|null, // The name of the parameter to use to enable or disable collection on a per request basis. // Default: null
 *         only_exceptions?: bool|Param, // Default: false
 *         only_main_requests?: bool|Param, // Default: false
 *         excluded_paths?: Param|string|list<scalar|Param|null>,
 *         excluded_http_codes?: Param|int|string|list<Param|string|list<scalar|Param|null>>,
 *         dsn?: scalar|Param|null, // Default: "file:%kernel.cache_dir%/profiler"
 *         collect_serializer_data?: true|Param, // Deprecated: Setting the "framework.profiler.collect_serializer_data.collect_serializer_data" configuration option is deprecated. It will be removed in version 9.0. // Default: true
 *     },
 *     workflows?: mixed,
 *     router?: RouterConfig,
 *     assets?: AssetConfig,
 *     asset_mapper?: AssetMapperConfig,
 *     translator?: TranslationConfig,
 *     validation?: ValidationConfig,
 *     serializer?: SerializerConfig,
 *     property_access?: PropertyAccessConfig,
 *     type_info?: TypeInfoConfig,
 *     property_info?: PropertyInfoConfig,
 *     cache?: CacheConfig,
 *     web_link?: mixed,
 *     lock?: mixed,
 *     semaphore?: mixed,
 *     messenger?: MessengerConfig,
 *     scheduler?: SchedulerConfig,
 *     http_client?: HttpClientConfig,
 *     mailer?: mixed,
 *     notifier?: mixed,
 *     rate_limiter?: RateLimiterConfig,
 *     uid?: UidConfig,
 *     html_sanitizer?: mixed,
 *     webhook?: mixed,
 *     remote_event?: mixed,
 *     json_streamer?: mixed,
 *     session?: bool|array{ // Session configuration
 *         enabled?: bool|Param, // Default: false
 *         storage_factory_id?: scalar|Param|null, // Default: "session.storage.factory.native"
 *         handler_id?: scalar|Param|null, // Defaults to using the native session handler, or to the native *file* session handler if "save_path" is not null.
 *         name?: scalar|Param|null,
 *         cookie_lifetime?: scalar|Param|null,
 *         cookie_path?: scalar|Param|null,
 *         cookie_domain?: scalar|Param|null,
 *         cookie_secure?: true|false|"auto"|Param, // Default: "auto"
 *         cookie_httponly?: bool|Param, // Default: true
 *         cookie_samesite?: null|"lax"|"strict"|"none"|Param, // Default: "lax"
 *         use_cookies?: bool|Param,
 *         gc_divisor?: scalar|Param|null,
 *         gc_probability?: scalar|Param|null,
 *         gc_maxlifetime?: scalar|Param|null,
 *         save_path?: scalar|Param|null, // Defaults to "%kernel.cache_dir%/sessions" if the "handler_id" option is not null.
 *         metadata_update_threshold?: int|Param, // Seconds to wait between 2 session metadata updates. // Default: 0
 *         isolate_attributes?: bool|Param, // Whether to deep-clone the values read from and passed to session attributes, so that only values passed to set() are saved. // Default: false
 *     },
 *     request?: bool|array{ // Request configuration
 *         enabled?: bool|Param, // Default: false
 *         formats?: array<string, Param|string|list<scalar|Param|null>>,
 *         serializer?: scalar|Param|null, // Service id of the serializer that maps request payloads and query strings to controller arguments with #[MapRequestPayload] and #[MapQueryString], e.g. "serializer.api" for the named serializer "api". // Default: null
 *     },
 *     response?: array{ // Response configuration
 *         serializer?: scalar|Param|null, // Service id of the serializer that serializes the values returned by controllers with #[Serialize], e.g. "serializer.api" for the named serializer "api". // Default: null
 *     },
 *     php_errors?: array{ // PHP errors handling configuration
 *         log?: mixed, // Use the application logger instead of the PHP logger for logging PHP errors. // Default: true
 *         throw?: bool|Param|null, // Throw PHP errors as \ErrorException instances. Enabled by default when debug is enabled. // Default: null
 *     },
 *     exceptions?: array<string, array{ // Default: []
 *         log_level?: scalar|Param|null, // The level of log message. Null to let Symfony decide. // Default: null
 *         status_code?: scalar|Param|null, // The status code of the response. Null or 0 to let Symfony decide. // Default: null
 *         log_channel?: scalar|Param|null, // The channel of log message. Null to let Symfony decide. // Default: null
 *     }>,
 *     disallow_search_engine_index?: bool|Param|null, // Enabled by default when debug is enabled. // Default: null
 *     secrets?: bool|array{
 *         enabled?: bool|Param, // Default: true
 *         vault_directory?: scalar|Param|null, // Default: "%kernel.project_dir%/config/secrets/%kernel.runtime_environment%"
 *         local_dotenv_file?: scalar|Param|null, // Default: "%kernel.project_dir%/.env.%kernel.environment%.local"
 *         decryption_env_var?: scalar|Param|null, // Default: "base64:default::SYMFONY_DECRYPTION_SECRET"
 *     },
 * }
 * @psalm-type DoctrineConfig = array{
 *     dbal?: array{
 *         default_connection?: scalar|Param|null,
 *         types?: array<string, Param|string|array{ // Default: []
 *             class?: scalar|Param|null,
 *         }>,
 *         driver_schemes?: array<string, scalar|Param|null>,
 *         connections?: array<string, array{ // Default: []
 *             url?: scalar|Param|null, // A URL with connection information; any parameter value parsed from this string will override explicitly set parameters
 *             dbname?: scalar|Param|null,
 *             host?: scalar|Param|null, // Defaults to "localhost" at runtime.
 *             port?: scalar|Param|null, // Defaults to null at runtime.
 *             user?: scalar|Param|null, // Defaults to "root" at runtime.
 *             password?: scalar|Param|null, // Defaults to null at runtime.
 *             dbname_suffix?: scalar|Param|null, // Adds the given suffix to the configured database name, this option has no effects for the SQLite platform
 *             application_name?: scalar|Param|null,
 *             charset?: scalar|Param|null,
 *             path?: scalar|Param|null,
 *             memory?: bool|Param,
 *             unix_socket?: scalar|Param|null, // The unix socket to use for MySQL
 *             persistent?: bool|Param, // True to use as persistent connection for the ibm_db2 driver
 *             protocol?: scalar|Param|null, // The protocol to use for the ibm_db2 driver (default to TCPIP if omitted)
 *             service?: bool|Param, // True to use SERVICE_NAME as connection parameter instead of SID for Oracle
 *             servicename?: scalar|Param|null, // Overrules dbname parameter if given and used as SERVICE_NAME or SID connection parameter for Oracle depending on the service parameter.
 *             sessionMode?: scalar|Param|null, // The session mode to use for the oci8 driver
 *             server?: scalar|Param|null, // The name of a running database server to connect to for SQL Anywhere.
 *             default_dbname?: scalar|Param|null, // Override the default database (postgres) to connect to for PostgreSQL connection.
 *             sslmode?: scalar|Param|null, // Determines whether or with what priority a SSL TCP/IP connection will be negotiated with the server for PostgreSQL.
 *             sslrootcert?: scalar|Param|null, // The name of a file containing SSL certificate authority (CA) certificate(s). If the file exists, the server's certificate will be verified to be signed by one of these authorities.
 *             sslcert?: scalar|Param|null, // The path to the SSL client certificate file for PostgreSQL.
 *             sslkey?: scalar|Param|null, // The path to the SSL client key file for PostgreSQL.
 *             sslcrl?: scalar|Param|null, // The file name of the SSL certificate revocation list for PostgreSQL.
 *             pooled?: bool|Param, // True to use a pooled server with the oci8/pdo_oracle driver
 *             MultipleActiveResultSets?: bool|Param, // Configuring MultipleActiveResultSets for the pdo_sqlsrv driver
 *             instancename?: scalar|Param|null, // Optional parameter, complete whether to add the INSTANCE_NAME parameter in the connection. It is generally used to connect to an Oracle RAC server to select the name of a particular instance.
 *             connectstring?: scalar|Param|null, // Complete Easy Connect connection descriptor, see https://docs.oracle.com/database/121/NETAG/naming.htm.When using this option, you will still need to provide the user and password parameters, but the other parameters will no longer be used. Note that when using this parameter, the getHost and getPort methods from Doctrine\DBAL\Connection will no longer function as expected.
 *             driver?: scalar|Param|null, // Default: "pdo_mysql"
 *             auto_commit?: bool|Param,
 *             schema_filter?: scalar|Param|null,
 *             logging?: bool|Param, // Default: true
 *             profiling?: bool|Param, // Default: true
 *             profiling_collect_backtrace?: bool|Param, // Enables collecting backtraces when profiling is enabled // Default: false
 *             profiling_collect_schema_errors?: bool|Param, // Enables collecting schema errors when profiling is enabled // Default: true
 *             server_version?: scalar|Param|null,
 *             idle_connection_ttl?: int|Param, // Default: 600
 *             driver_class?: scalar|Param|null,
 *             wrapper_class?: scalar|Param|null,
 *             keep_replica?: bool|Param,
 *             options?: array<string, mixed>,
 *             mapping_types?: array<string, scalar|Param|null>,
 *             default_table_options?: array<string, scalar|Param|null>,
 *             schema_manager_factory?: scalar|Param|null, // Default: "doctrine.dbal.default_schema_manager_factory"
 *             result_cache?: scalar|Param|null,
 *             replicas?: array<string, array{ // Default: []
 *                 url?: scalar|Param|null, // A URL with connection information; any parameter value parsed from this string will override explicitly set parameters
 *                 dbname?: scalar|Param|null,
 *                 host?: scalar|Param|null, // Defaults to "localhost" at runtime.
 *                 port?: scalar|Param|null, // Defaults to null at runtime.
 *                 user?: scalar|Param|null, // Defaults to "root" at runtime.
 *                 password?: scalar|Param|null, // Defaults to null at runtime.
 *                 dbname_suffix?: scalar|Param|null, // Adds the given suffix to the configured database name, this option has no effects for the SQLite platform
 *                 application_name?: scalar|Param|null,
 *                 charset?: scalar|Param|null,
 *                 path?: scalar|Param|null,
 *                 memory?: bool|Param,
 *                 unix_socket?: scalar|Param|null, // The unix socket to use for MySQL
 *                 persistent?: bool|Param, // True to use as persistent connection for the ibm_db2 driver
 *                 protocol?: scalar|Param|null, // The protocol to use for the ibm_db2 driver (default to TCPIP if omitted)
 *                 service?: bool|Param, // True to use SERVICE_NAME as connection parameter instead of SID for Oracle
 *                 servicename?: scalar|Param|null, // Overrules dbname parameter if given and used as SERVICE_NAME or SID connection parameter for Oracle depending on the service parameter.
 *                 sessionMode?: scalar|Param|null, // The session mode to use for the oci8 driver
 *                 server?: scalar|Param|null, // The name of a running database server to connect to for SQL Anywhere.
 *                 default_dbname?: scalar|Param|null, // Override the default database (postgres) to connect to for PostgreSQL connection.
 *                 sslmode?: scalar|Param|null, // Determines whether or with what priority a SSL TCP/IP connection will be negotiated with the server for PostgreSQL.
 *                 sslrootcert?: scalar|Param|null, // The name of a file containing SSL certificate authority (CA) certificate(s). If the file exists, the server's certificate will be verified to be signed by one of these authorities.
 *                 sslcert?: scalar|Param|null, // The path to the SSL client certificate file for PostgreSQL.
 *                 sslkey?: scalar|Param|null, // The path to the SSL client key file for PostgreSQL.
 *                 sslcrl?: scalar|Param|null, // The file name of the SSL certificate revocation list for PostgreSQL.
 *                 pooled?: bool|Param, // True to use a pooled server with the oci8/pdo_oracle driver
 *                 MultipleActiveResultSets?: bool|Param, // Configuring MultipleActiveResultSets for the pdo_sqlsrv driver
 *                 instancename?: scalar|Param|null, // Optional parameter, complete whether to add the INSTANCE_NAME parameter in the connection. It is generally used to connect to an Oracle RAC server to select the name of a particular instance.
 *                 connectstring?: scalar|Param|null, // Complete Easy Connect connection descriptor, see https://docs.oracle.com/database/121/NETAG/naming.htm.When using this option, you will still need to provide the user and password parameters, but the other parameters will no longer be used. Note that when using this parameter, the getHost and getPort methods from Doctrine\DBAL\Connection will no longer function as expected.
 *                 ...<string, mixed>
 *             }>,
 *             ...<string, mixed>
 *         }>,
 *         ...<string, mixed>
 *     },
 *     orm?: array{
 *         default_entity_manager?: scalar|Param|null,
 *         enable_native_lazy_objects?: bool|Param, // Deprecated: The "enable_native_lazy_objects" option is deprecated and will be removed in DoctrineBundle 4.0, as native lazy objects are now always enabled. // Default: true
 *         controller_resolver?: bool|array{
 *             enabled?: bool|Param, // Default: true
 *             auto_mapping?: bool|Param, // Deprecated: The "doctrine.orm.controller_resolver.auto_mapping.auto_mapping" option is deprecated and will be removed in DoctrineBundle 4.0, as it only accepts `false` since 3.0. // Set to true to enable using route placeholders as lookup criteria when the primary key doesn't match the argument name // Default: false
 *             evict_cache?: bool|Param, // Set to true to fetch the entity from the database instead of using the cache, if any // Default: false
 *         },
 *         entity_managers?: array<string, array{ // Default: []
 *             query_cache_driver?: Param|string|array{
 *                 type?: scalar|Param|null, // Default: null
 *                 id?: scalar|Param|null,
 *                 pool?: scalar|Param|null,
 *             },
 *             metadata_cache_driver?: Param|string|array{
 *                 type?: scalar|Param|null, // Default: null
 *                 id?: scalar|Param|null,
 *                 pool?: scalar|Param|null,
 *             },
 *             result_cache_driver?: Param|string|array{
 *                 type?: scalar|Param|null, // Default: null
 *                 id?: scalar|Param|null,
 *                 pool?: scalar|Param|null,
 *             },
 *             entity_listeners?: array{
 *                 entities?: array<string, array{ // Default: []
 *                     listeners?: array<string, array{ // Default: []
 *                         events?: list<array{ // Default: []
 *                             type?: scalar|Param|null,
 *                             method?: scalar|Param|null, // Default: null
 *                         }>,
 *                     }>,
 *                 }>,
 *                 ...<string, mixed>
 *             },
 *             connection?: scalar|Param|null,
 *             class_metadata_factory_name?: scalar|Param|null, // Default: "Doctrine\\ORM\\Mapping\\ClassMetadataFactory"
 *             default_repository_class?: scalar|Param|null, // Default: "Doctrine\\ORM\\EntityRepository"
 *             auto_mapping?: scalar|Param|null, // Default: false
 *             naming_strategy?: scalar|Param|null, // Default: "doctrine.orm.naming_strategy.default"
 *             quote_strategy?: scalar|Param|null, // Default: "doctrine.orm.quote_strategy.default"
 *             typed_field_mapper?: scalar|Param|null, // Default: "doctrine.orm.typed_field_mapper.default"
 *             entity_listener_resolver?: scalar|Param|null, // Default: null
 *             fetch_mode_subselect_batch_size?: scalar|Param|null,
 *             repository_factory?: scalar|Param|null, // Default: "doctrine.orm.container_repository_factory"
 *             schema_ignore_classes?: list<scalar|Param|null>,
 *             validate_xml_mapping?: bool|Param, // Set to "true" to opt-in to the new mapping driver mode that was added in Doctrine ORM 2.14 and will be mandatory in ORM 3.0. See https://github.com/doctrine/orm/pull/6728. // Default: false
 *             second_level_cache?: array{
 *                 region_cache_driver?: Param|string|array{
 *                     type?: scalar|Param|null, // Default: null
 *                     id?: scalar|Param|null,
 *                     pool?: scalar|Param|null,
 *                 },
 *                 region_lock_lifetime?: scalar|Param|null, // Default: 60
 *                 log_enabled?: bool|Param, // Default: true
 *                 region_lifetime?: scalar|Param|null, // Default: 3600
 *                 enabled?: bool|Param, // Default: true
 *                 factory?: scalar|Param|null,
 *                 regions?: array<string, array{ // Default: []
 *                     cache_driver?: Param|string|array{
 *                         type?: scalar|Param|null, // Default: null
 *                         id?: scalar|Param|null,
 *                         pool?: scalar|Param|null,
 *                     },
 *                     lock_path?: scalar|Param|null, // Default: "%kernel.cache_dir%/doctrine/orm/slc/filelock"
 *                     lock_lifetime?: scalar|Param|null, // Default: 60
 *                     type?: scalar|Param|null, // Default: "default"
 *                     lifetime?: scalar|Param|null, // Default: null
 *                     service?: scalar|Param|null,
 *                     name?: scalar|Param|null,
 *                 }>,
 *                 loggers?: array<string, array{ // Default: []
 *                     name?: scalar|Param|null,
 *                     service?: scalar|Param|null,
 *                 }>,
 *             },
 *             hydrators?: array<string, scalar|Param|null>,
 *             mappings?: array<string, Param|bool|string|array{ // Default: []
 *                 mapping?: scalar|Param|null, // Default: true
 *                 type?: scalar|Param|null,
 *                 dir?: scalar|Param|null,
 *                 alias?: scalar|Param|null,
 *                 prefix?: scalar|Param|null,
 *                 is_bundle?: bool|Param,
 *             }>,
 *             dql?: array{
 *                 string_functions?: array<string, scalar|Param|null>,
 *                 numeric_functions?: array<string, scalar|Param|null>,
 *                 datetime_functions?: array<string, scalar|Param|null>,
 *             },
 *             filters?: array<string, Param|string|array{ // Default: []
 *                 class?: scalar|Param|null,
 *                 enabled?: bool|Param, // Default: false
 *                 parameters?: array<string, mixed>,
 *                 ...<string, mixed>
 *             }>,
 *             identity_generation_preferences?: array<string, scalar|Param|null>,
 *         }>,
 *         resolve_target_entities?: array<string, scalar|Param|null>,
 *         ...<string, mixed>
 *     },
 * }
 * @psalm-type DoctrineMigrationsConfig = array{
 *     enable_service_migrations?: bool|Param, // Whether to enable fetching migrations from the service container. // Default: false
 *     migrations_paths?: array<string, scalar|Param|null>,
 *     services?: array<string, scalar|Param|null>,
 *     factories?: array<string, scalar|Param|null>,
 *     storage?: array{ // Storage to use for migration status metadata.
 *         table_storage?: array{ // The default metadata storage, implemented as a table in the database.
 *             table_name?: scalar|Param|null, // Default: null
 *             version_column_name?: scalar|Param|null, // Default: null
 *             version_column_length?: scalar|Param|null, // Default: null
 *             executed_at_column_name?: scalar|Param|null, // Default: null
 *             execution_time_column_name?: scalar|Param|null, // Default: null
 *         },
 *     },
 *     migrations?: list<scalar|Param|null>,
 *     connection?: scalar|Param|null, // Connection name to use for the migrations database. // Default: null
 *     em?: scalar|Param|null, // Entity manager name to use for the migrations database (available when doctrine/orm is installed). // Default: null
 *     all_or_nothing?: scalar|Param|null, // Run all migrations in a transaction. // Default: false
 *     check_database_platform?: scalar|Param|null, // Adds an extra check in the generated migrations to allow execution only on the same platform as they were initially generated on. // Default: true
 *     custom_template?: scalar|Param|null, // Custom template path for generated migration classes. // Default: null
 *     organize_migrations?: scalar|Param|null, // Organize migrations mode. Possible values are: "BY_YEAR", "BY_YEAR_AND_MONTH", false // Default: false
 *     enable_profiler?: bool|Param, // Whether or not to enable the profiler collector to calculate and visualize migration status. This adds some queries overhead. // Default: false
 *     transactional?: bool|Param, // Whether or not to wrap migrations in a single transaction. // Default: true
 * }
 * @psalm-type MonologConfig = array{
 *     use_microseconds?: scalar|Param|null, // Default: true
 *     timezone?: string|Param, // The timezone used for the timestamp of every log record (e.g. "UTC" or "Europe/Paris"). Defaults to the PHP default timezone. // Default: null
 *     channels?: list<scalar|Param|null>,
 *     handlers?: array<string, array{ // Default: []
 *         type?: scalar|Param|null,
 *         id?: scalar|Param|null,
 *         enabled?: bool|Param, // Default: true
 *         priority?: scalar|Param|null, // Default: 0
 *         level?: scalar|Param|null, // Default: "DEBUG"
 *         bubble?: bool|Param, // Default: true
 *         interactive_only?: bool|Param, // Default: false
 *         app_name?: scalar|Param|null, // Default: null
 *         include_stacktraces?: bool|Param, // Default: false
 *         base_path?: scalar|Param|null, // Default: null
 *         process_psr_3_messages?: array{
 *             enabled?: bool|Param|null, // Default: null
 *             date_format?: scalar|Param|null,
 *             remove_used_context_fields?: bool|Param,
 *             ...<string, mixed>
 *         },
 *         path?: scalar|Param|null, // Default: "%kernel.logs_dir%/%kernel.environment%.log"
 *         file_permission?: scalar|Param|null, // Default: null
 *         use_locking?: bool|Param, // Default: false
 *         filename_format?: scalar|Param|null, // Default: "{filename}-{date}"
 *         date_format?: scalar|Param|null, // Default: "Y-m-d"
 *         ident?: scalar|Param|null, // Default: "php"
 *         logopts?: scalar|Param|null, // Default: 1
 *         facility?: scalar|Param|null, // Default: "user"
 *         max_files?: scalar|Param|null, // Default: 0
 *         action_level?: scalar|Param|null, // Default: "WARNING"
 *         activation_strategy?: scalar|Param|null, // Default: null
 *         stop_buffering?: bool|Param, // Default: true
 *         passthru_level?: scalar|Param|null, // Default: null
 *         excluded_http_codes?: list<array{ // Default: []
 *             code?: scalar|Param|null,
 *             urls?: list<scalar|Param|null>,
 *         }>,
 *         accepted_levels?: list<scalar|Param|null>,
 *         min_level?: scalar|Param|null, // Default: "DEBUG"
 *         max_level?: scalar|Param|null, // Default: "EMERGENCY"
 *         buffer_size?: scalar|Param|null, // Default: 0
 *         flush_on_overflow?: bool|Param, // Default: false
 *         handler?: scalar|Param|null,
 *         url?: scalar|Param|null,
 *         exchange?: scalar|Param|null,
 *         exchange_name?: scalar|Param|null, // Default: "log"
 *         channel?: scalar|Param|null, // Default: null
 *         bot_name?: scalar|Param|null, // Default: "Monolog"
 *         use_attachment?: scalar|Param|null, // Default: true
 *         use_short_attachment?: scalar|Param|null, // Default: false
 *         include_extra?: scalar|Param|null, // Default: false
 *         icon_emoji?: scalar|Param|null, // Default: null
 *         webhook_url?: scalar|Param|null,
 *         exclude_fields?: list<scalar|Param|null>,
 *         token?: scalar|Param|null,
 *         region?: scalar|Param|null,
 *         source?: scalar|Param|null,
 *         use_ssl?: bool|Param, // Default: true
 *         user?: mixed,
 *         title?: scalar|Param|null, // Default: null
 *         host?: scalar|Param|null, // Default: null
 *         port?: scalar|Param|null, // Default: 514
 *         rfc?: scalar|Param|null, // Default: 1
 *         config?: list<scalar|Param|null>,
 *         members?: list<scalar|Param|null>,
 *         connection_string?: scalar|Param|null,
 *         timeout?: scalar|Param|null,
 *         time?: scalar|Param|null, // Default: 60
 *         deduplication_level?: scalar|Param|null, // Default: 400
 *         store?: scalar|Param|null, // Default: null
 *         connection_timeout?: scalar|Param|null,
 *         persistent?: bool|Param,
 *         message_type?: scalar|Param|null, // Default: 0
 *         expand_newlines?: bool|Param, // Default: false
 *         parse_mode?: scalar|Param|null, // Default: null
 *         disable_webpage_preview?: bool|Param|null, // Default: null
 *         disable_notification?: bool|Param|null, // Default: null
 *         split_long_messages?: bool|Param, // Default: false
 *         delay_between_messages?: bool|Param, // Default: false
 *         topic?: int|Param, // Default: null
 *         factor?: int|Param, // Default: 1
 *         tags?: Param|string|list<scalar|Param|null>,
 *         console_formatter_options?: mixed, // Default: []
 *         formatter?: scalar|Param|null,
 *         nested?: bool|Param, // Default: false
 *         publisher?: Param|string|array{
 *             id?: scalar|Param|null,
 *             hostname?: scalar|Param|null,
 *             port?: scalar|Param|null, // Default: 12201
 *             chunk_size?: scalar|Param|null, // Default: 1420
 *             encoder?: "json"|"compressed_json"|Param,
 *         },
 *         mongodb?: Param|string|array{
 *             id?: scalar|Param|null, // ID of a MongoDB\Client service
 *             uri?: scalar|Param|null,
 *             username?: scalar|Param|null,
 *             password?: scalar|Param|null,
 *             database?: scalar|Param|null, // Default: "monolog"
 *             collection?: scalar|Param|null, // Default: "logs"
 *         },
 *         elasticsearch?: Param|string|array{
 *             id?: scalar|Param|null,
 *             hosts?: list<scalar|Param|null>,
 *             host?: scalar|Param|null,
 *             port?: scalar|Param|null, // Default: 9200
 *             transport?: scalar|Param|null, // Default: "Http"
 *             user?: scalar|Param|null, // Default: null
 *             password?: scalar|Param|null, // Default: null
 *         },
 *         index?: scalar|Param|null, // Default: "monolog"
 *         document_type?: scalar|Param|null, // Default: "logs"
 *         ignore_error?: scalar|Param|null, // Default: false
 *         redis?: Param|string|array{
 *             id?: scalar|Param|null,
 *             host?: scalar|Param|null,
 *             password?: scalar|Param|null, // Default: null
 *             port?: scalar|Param|null, // Default: 6379
 *             database?: scalar|Param|null, // Default: 0
 *             key_name?: scalar|Param|null, // Default: "monolog_redis"
 *         },
 *         predis?: Param|string|array{ // Deprecated: The "predis" option is deprecated and ignored, use the "redis" option to configure the Predis client.
 *             id?: scalar|Param|null,
 *             host?: scalar|Param|null,
 *         },
 *         from_email?: scalar|Param|null,
 *         to_email?: Param|string|list<scalar|Param|null>,
 *         subject?: scalar|Param|null,
 *         content_type?: scalar|Param|null, // Default: null
 *         headers?: list<scalar|Param|null>,
 *         parameters?: list<scalar|Param|null>,
 *         mailer?: scalar|Param|null, // Default: null
 *         email_prototype?: Param|string|array{
 *             id?: scalar|Param|null,
 *             method?: scalar|Param|null, // Default: null
 *         },
 *         verbosity_levels?: array{
 *             VERBOSITY_QUIET?: scalar|Param|null, // Default: "ERROR"
 *             VERBOSITY_NORMAL?: scalar|Param|null, // Default: "WARNING"
 *             VERBOSITY_VERBOSE?: scalar|Param|null, // Default: "NOTICE"
 *             VERBOSITY_VERY_VERBOSE?: scalar|Param|null, // Default: "INFO"
 *             VERBOSITY_DEBUG?: scalar|Param|null, // Default: "DEBUG"
 *         },
 *         channels?: Param|string|array{
 *             type?: scalar|Param|null,
 *             elements?: list<scalar|Param|null>,
 *             ...<string, mixed>
 *         },
 *     }>,
 * }
 * @psalm-type SecurityConfig = array{
 *     access_denied_url?: scalar|Param|null, // Default: null
 *     recent_authentication_lifetime?: int|Param, // Number of seconds an interactive authentication keeps granting IS_AUTHENTICATED_RECENTLY. Use it to make sensitive actions require the user to authenticate again. // Default: 7200
 *     very_recent_authentication_lifetime?: int|Param, // Number of seconds an interactive authentication keeps granting IS_AUTHENTICATED_VERY_RECENTLY, a stricter bar than IS_AUTHENTICATED_RECENTLY for the most sensitive actions. // Default: 300
 *     session_fixation_strategy?: "none"|"migrate"|"invalidate"|Param, // Default: "migrate"
 *     expose_security_errors?: \Symfony\Component\Security\Http\Authentication\ExposeSecurityLevel::None|\Symfony\Component\Security\Http\Authentication\ExposeSecurityLevel::AccountStatus|\Symfony\Component\Security\Http\Authentication\ExposeSecurityLevel::All|Param, // Default: "none"
 *     erase_credentials?: bool|Param, // Deprecated: Setting the "security.erase_credentials.erase_credentials" configuration option is deprecated. It will be removed in Symfony 9.0, as the "eraseCredentials()" method was removed in Symfony 8.0. // Default: true
 *     access_decision_manager?: array{
 *         strategy?: "affirmative"|"consensus"|"unanimous"|"priority"|Param,
 *         service?: scalar|Param|null,
 *         strategy_service?: scalar|Param|null,
 *         allow_if_all_abstain?: bool|Param, // Default: false
 *         allow_if_equal_granted_denied?: bool|Param, // Default: true
 *     },
 *     password_hashers?: array<string, Param|string|array{ // Default: []
 *         algorithm?: scalar|Param|null,
 *         migrate_from?: Param|string|list<scalar|Param|null>,
 *         hash_algorithm?: scalar|Param|null, // Name of hashing algorithm for PBKDF2 (i.e. sha256, sha512, etc..) See hash_algos() for a list of supported algorithms. // Default: "sha512"
 *         key_length?: scalar|Param|null, // Default: 40
 *         ignore_case?: bool|Param, // Default: false
 *         encode_as_base64?: bool|Param, // Default: true
 *         iterations?: scalar|Param|null, // Default: 5000
 *         cost?: int|Param, // Default: null
 *         memory_cost?: scalar|Param|null, // Default: null
 *         time_cost?: scalar|Param|null, // Default: null
 *         id?: scalar|Param|null,
 *     }>,
 *     providers?: array<string, array{ // Default: []
 *         id?: scalar|Param|null,
 *         chain?: array{
 *             providers?: Param|string|list<scalar|Param|null>,
 *         },
 *         entity?: array{
 *             class?: scalar|Param|null, // The full entity class name of your user class.
 *             property?: scalar|Param|null, // Default: null
 *             manager_name?: scalar|Param|null, // Default: null
 *         },
 *         memory?: array{
 *             users?: array<string, array{ // Default: []
 *                 password?: scalar|Param|null, // Default: null
 *                 roles?: Param|string|list<scalar|Param|null>,
 *             }>,
 *         },
 *         ldap?: array{
 *             service?: scalar|Param|null,
 *             base_dn?: scalar|Param|null,
 *             search_dn?: scalar|Param|null, // Default: null
 *             search_password?: scalar|Param|null, // Default: null
 *             extra_fields?: list<scalar|Param|null>,
 *             default_roles?: Param|string|list<scalar|Param|null>,
 *             role_fetcher?: scalar|Param|null, // Default: null
 *             uid_key?: scalar|Param|null, // Default: "sAMAccountName"
 *             filter?: scalar|Param|null, // Default: "({uid_key}={user_identifier})"
 *             password_attribute?: scalar|Param|null, // Default: null
 *         },
 *         oidc?: array{
 *             enabled?: bool|Param, // Internal marker; the OIDC provider has no configuration options. // Default: true
 *             ...<string, mixed>
 *         },
 *     }>,
 *     firewalls?: array<string, array{ // Default: []
 *         pattern?: scalar|Param|null,
 *         host?: scalar|Param|null,
 *         methods?: Param|string|list<scalar|Param|null>,
 *         security?: bool|Param, // Default: true
 *         user_checker?: scalar|Param|null, // The UserChecker to use when authenticating users in this firewall. // Default: "security.user_checker"
 *         user_checker_on_refresh?: bool|Param, // Whether to run this firewall's UserChecker again when the user is refreshed from the session, so that an account disabled during the session is rejected on the next request. It then runs on every request of this firewall, so enable it only if that checker is safe to call that often. // Default: false
 *         request_matcher?: scalar|Param|null,
 *         access_denied_url?: scalar|Param|null,
 *         access_denied_handler?: scalar|Param|null,
 *         entry_point?: scalar|Param|null, // An enabled authenticator name or a service id that implements "Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface".
 *         re_authentication_entry_point?: scalar|Param|null, // An enabled authenticator name or a service id implementing "Symfony\Component\Security\Http\EntryPoint\ReAuthenticationEntryPointInterface", asking an already authenticated user to prove possession of their credentials again when IS_AUTHENTICATED_RECENTLY or IS_AUTHENTICATED_VERY_RECENTLY is denied. Defaults to the firewall entry point when that one implements it.
 *         provider?: scalar|Param|null,
 *         stateless?: bool|Param, // Default: false
 *         lazy?: bool|Param, // Default: false
 *         context?: scalar|Param|null,
 *         logout?: array{
 *             enable_csrf?: bool|Param|null, // Default: null
 *             csrf_token_id?: scalar|Param|null, // Default: "logout"
 *             csrf_parameter?: scalar|Param|null, // Default: "_csrf_token"
 *             csrf_token_manager?: scalar|Param|null,
 *             path?: scalar|Param|null, // Default: "/logout"
 *             target?: scalar|Param|null, // Default: "/"
 *             invalidate_session?: bool|Param, // Default: true
 *             clear_site_data?: Param|string|list<"*"|"cache"|"cookies"|"storage"|"clientHints"|"executionContexts"|"prefetchCache"|"prerenderCache"|Param>,
 *             delete_cookies?: Param|string|array<string, array{ // Default: []
 *                 path?: scalar|Param|null, // Default: null
 *                 domain?: scalar|Param|null, // Default: null
 *                 secure?: scalar|Param|null, // Default: false
 *                 samesite?: scalar|Param|null, // Default: null
 *                 partitioned?: scalar|Param|null, // Default: false
 *             }>,
 *         },
 *         switch_user?: array{
 *             provider?: scalar|Param|null,
 *             parameter?: scalar|Param|null, // Default: "_switch_user"
 *             role?: scalar|Param|null, // Default: "ROLE_ALLOWED_TO_SWITCH"
 *             target_route?: scalar|Param|null, // Default: null
 *             path?: scalar|Param|null, // Restrict user switching to this path (a path or route name). Declaring the route POST-only is up to the application. The parameter is no longer read from the request headers in this mode. // Default: null
 *             enable_csrf?: bool|Param|null, // Default: null
 *             csrf_token_id?: scalar|Param|null, // Default: "switch_user"
 *             csrf_parameter?: scalar|Param|null, // Default: "_csrf_token"
 *             csrf_token_manager?: scalar|Param|null,
 *         },
 *         required_badges?: list<scalar|Param|null>,
 *         custom_authenticators?: list<scalar|Param|null>,
 *         login_throttling?: array{
 *             limiter?: scalar|Param|null, // A service id implementing "Symfony\Component\HttpFoundation\RateLimiter\RequestRateLimiterInterface".
 *             max_attempts?: int|Param, // Default: 5
 *             interval?: scalar|Param|null, // Default: "1 minute"
 *             lock_factory?: scalar|Param|null, // The service ID of the lock factory used by the login rate limiter ("auto" to use the default one when the Lock component is configured, or null to disable locking). // Default: "auto"
 *             cache_pool?: string|Param, // The cache pool to use for storing the limiter state // Default: "cache.rate_limiter"
 *             storage_service?: string|Param, // The service ID of a custom storage implementation, this precedes any configured "cache_pool" // Default: null
 *         },
 *         x509?: array{
 *             provider?: scalar|Param|null,
 *             user?: scalar|Param|null, // Default: "SSL_CLIENT_S_DN_Email"
 *             credentials?: scalar|Param|null, // Default: "SSL_CLIENT_S_DN"
 *             user_identifier?: scalar|Param|null, // Default: "emailAddress"
 *         },
 *         remote_user?: array{
 *             provider?: scalar|Param|null,
 *             user?: scalar|Param|null, // Default: "REMOTE_USER"
 *         },
 *         login_link?: array{
 *             check_route?: scalar|Param|null, // Route that will validate the login link - e.g. "app_login_link_verify".
 *             check_post_only?: scalar|Param|null, // If true, only HTTP POST requests to "check_route" will be handled by the authenticator. // Default: false
 *             signature_properties?: list<scalar|Param|null>,
 *             lifetime?: int|Param, // The lifetime of the login link in seconds. // Default: 600
 *             max_uses?: int|Param, // Max number of times a login link can be used - null means unlimited within lifetime. // Default: null
 *             used_link_cache?: scalar|Param|null, // Cache service id used to expired links of max_uses is set.
 *             success_handler?: scalar|Param|null, // A service id that implements Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface.
 *             failure_handler?: scalar|Param|null, // A service id that implements Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface.
 *             provider?: scalar|Param|null, // The user provider to load users from.
 *             secret?: Param|string|list<scalar|Param|null>,
 *             always_use_default_target_path?: bool|Param, // Default: false
 *             default_target_path?: scalar|Param|null, // Default: "/"
 *             login_path?: scalar|Param|null, // Default: "/login"
 *             target_path_parameter?: scalar|Param|null, // Default: "_target_path"
 *             use_referer?: bool|Param, // Default: false
 *             failure_path?: scalar|Param|null, // Default: null
 *             failure_forward?: bool|Param, // Default: false
 *             failure_path_parameter?: scalar|Param|null, // Default: "_failure_path"
 *         },
 *         oidc_login?: array{
 *             provider?: scalar|Param|null,
 *             remember_me?: bool|Param, // Deprecated: Setting the "security.firewalls..oidc_login.remember_me.remember_me" configuration option has no effect and is deprecated. It will be removed in Symfony 9.0. // Default: true
 *             success_handler?: scalar|Param|null,
 *             failure_handler?: scalar|Param|null,
 *             check_path?: scalar|Param|null, // The firewall path where the OIDC provider redirects after authentication. Must match a redirect URI registered with the provider. A route is declared for this path by the "security.authenticator.oidc_login.route_loader" service, which the application must import (see the OIDC login documentation), as it does for the logout routes. A route name is accepted too, in which case no route is declared for it. // Default: "/oidc/callback"
 *             use_forward?: bool|Param, // Default: false
 *             login_path?: scalar|Param|null, // Default: "/login"
 *             always_use_default_target_path?: bool|Param, // Default: false
 *             default_target_path?: scalar|Param|null, // Default: "/"
 *             target_path_parameter?: scalar|Param|null, // Default: "_target_path"
 *             use_referer?: bool|Param, // Default: false
 *             failure_path?: scalar|Param|null, // Default: null
 *             failure_forward?: bool|Param, // Default: false
 *             failure_path_parameter?: scalar|Param|null, // Default: "_failure_path"
 *             provider_uri?: scalar|Param|null, // The OIDC Issuer URL (e.g. "https://accounts.example.com"). Used for .well-known/openid-configuration discovery.
 *             http_client?: scalar|Param|null, // The id of the HttpClient service every call to the provider is made with: discovery, JWKS, token and UserInfo endpoints. Defaults to "http_client". A scoped client must scope every host the provider announces, not only the issuer. // Default: null
 *             client_id?: scalar|Param|null, // The OIDC client identifier.
 *             client_certificate?: Param|string|array{ // The TLS client certificate presented to the token and UserInfo endpoints.
 *                 certificate?: scalar|Param|null, // Path to the PEM file of the certificate.
 *                 key?: scalar|Param|null, // Path to the PEM file of the private key, when not in the certificate file. // Default: null
 *                 passphrase?: scalar|Param|null, // Passphrase of the private key. // Default: null
 *             },
 *             client_authentication?: Param|string|array{ // How the client authenticates at the token endpoint, which RFC 7591, Section 2 names in its "token_endpoint_auth_method" metadata. Set the method Symfony ships with its parameters, or the id of a service implementing "Symfony\Component\Security\Http\OAuth2\ClientAuthentication\ClientAuthenticationInterface" for a scheme it does not. Exactly one of them.
 *                 client_secret_basic?: scalar|Param|null, // Send the client secret as HTTP Basic credentials, the "client_secret_basic" method of RFC 6749, Section 2.3.1, which the RFC recommends. Takes the client secret.
 *                 client_secret_post?: scalar|Param|null, // Send the client secret in the body of the token request, the "client_secret_post" method of RFC 6749, Section 2.3.1. Takes the client secret. Use it for the providers that support nothing else.
 *                 none?: bool|Param, // Declare a public client (a SPA, a mobile or a native application), which holds no secret and relies on PKCE to protect the code exchange. It can disable neither PKCE nor the ID token signature check.
 *                 client_secret_jwt?: Param|string|array{ // Authenticate with a JWT assertion keyed with the client secret, the "client_secret_jwt" method of OIDC Core 1.0, Section 9. The secret keys an HMAC and is never sent, but the provider holds it too and could sign an assertion in the name of the client: prefer "private_key_jwt", which nobody but the client can sign. Takes the client secret, or a mapping to also set "algorithm" and "lifetime".
 *                     secret?: scalar|Param|null, // The client secret, whose octets key the HMAC. It must be at least as long as the digest the algorithm produces, which RFC 7518, Section 3.2 requires and the algorithm itself checks: 32 bytes for "HS256", 48 for "HS384", 64 for "HS512".
 *                     algorithm?: "HS256"|"HS384"|"HS512"|Param, // The MAC algorithm the assertion is signed with, which must be one your provider announces in "token_endpoint_auth_signing_alg_values_supported". // Default: "HS256"
 *                     lifetime?: int|Param, // How long an assertion is valid, in seconds. It is built for one request and sent right away, so keep it short: it is the window a provider that does not track the "jti" would accept a captured assertion in. // Default: 60
 *                     audience?: "issuer"|"token_endpoint"|Param, // The audience of the assertion: the issuer of the provider, or its token endpoint for a provider that refuses the issuer. // Default: "issuer"
 *                 },
 *                 private_key_jwt?: Param|string|array{ // Authenticate with a JWT assertion signed with the private key of the client, the "private_key_jwt" method of OIDC Core 1.0, Section 9, and the one FAPI 2.0 asks for. The provider only holds the public half, registered as the client "jwks" or fetched from its "jwks_uri", so it learns nothing it could authenticate as the client with.
 *                     key?: scalar|Param|null, // JSON-encoded JWK of the private key the assertion is signed with. Give it a "kid" when the client publishes several keys, so that the provider knows which one verifies the signature without trying them all.
 *                     algorithm?: "RS256"|"RS384"|"RS512"|"ES256"|"ES384"|"ES512"|"PS256"|"PS384"|"PS512"|Param, // The signature algorithm the assertion is signed with, which must be one your provider announces in "token_endpoint_auth_signing_alg_values_supported". FAPI 2.0 asks for "PS256" or "ES256". // Default: "RS256"
 *                     lifetime?: int|Param, // How long an assertion is valid, in seconds. It is built for one request and sent right away, so keep it short: it is the window a provider that does not track the "jti" would accept a captured assertion in. // Default: 60
 *                     audience?: "issuer"|"token_endpoint"|Param, // The audience of the assertion: the issuer of the provider, or its token endpoint for a provider that refuses the issuer. // Default: "issuer"
 *                 },
 *                 tls_client_auth?: bool|Param, // Authenticate with "client_certificate", issued by a certificate authority.
 *                 self_signed_tls_client_auth?: bool|Param, // Authenticate with "client_certificate", self-signed.
 *                 id?: scalar|Param|null, // The id of a service implementing "ClientAuthenticationInterface", for a scheme Symfony does not ship. The method it reports is only known once it is built, so the rules a public client cannot bend are then checked on the first request to this firewall instead of while the container compiles.
 *             },
 *             dpop?: Param|string|array{ // Binds the tokens the provider issues to a key held by this client (DPoP); a token the provider did not bind is refused.
 *                 key?: scalar|Param|null, // The private key the proofs are signed with, as a JSON-encoded JWK.
 *                 algorithm?: "ES256"|"ES384"|"ES512"|"PS256"|"PS384"|"PS512"|"RS256"|"RS384"|"RS512"|Param, // The algorithm the proofs are signed with, among the "dpop_signing_alg_values_supported" of the provider. // Default: "ES256"
 *             },
 *             scope?: list<scalar|Param|null>,
 *             start_path?: scalar|Param|null, // The path where the route loader declares a route that starts the flow by redirecting to the provider; link to it e.g. from the login page of a firewall offering several ways to log in. A route name is accepted too, in which case no route is declared for it. // Default: "/oidc/start"
 *             discovery_cache_ttl?: int|Param, // TTL in seconds for caching the OIDC discovery configuration, and for the provider JWKS when it advertises no cache lifetime itself. // Default: 3600
 *             allowed_time_drift?: int|Param, // Allowed clock skew in seconds when validating ID token time claims. // Default: 0
 *             user_data_source?: "userinfo"|"id_token"|Param, // Where the user claims are read from: "userinfo" (default) fetches them from the UserInfo endpoint; "id_token" reads them from the validated ID token instead, for providers that put the requested claims there, some of which expose no UserInfo endpoint at all, which is then not required to be announced. // Default: "userinfo"
 *             user_identifier_claim?: scalar|Param|null, // The claim the user identifier is read from. "sub" (default) is the only claim OIDC guarantees stable and unique for the user. Only pick another claim, e.g. "email", when the provider guarantees its value unique, verified and stable too: whoever controls the value of that claim at the provider owns the matching account here. // Default: "sub"
 *             id_token_signature?: array{
 *                 required?: bool|Param, // When true (default), the ID token signature is verified against the provider JWKS. Setting it to false decodes the ID token without verifying it, which OIDC Core 1.0, Section 3.1.3.7, item 6 only allows because the token comes from the token endpoint over TLS: it is then only as safe as the TLS verification of the HTTP client used for that request, so never turn it off with a client configured with "verify_peer: false" or "verify_host: false", nor behind a TLS-terminating proxy. A public client, whose "client_authentication" reports the "none" method, cannot turn it off at all. // Default: true
 *                 algorithms?: list<scalar|Param|null>,
 *                 enforce_key_usage_verification?: bool|Param, // When enabled (default), only keys explicitly designated for signature (via "use":"sig" or a "key_ops" entry containing "sign"/"verify") are accepted. When disabled, keys without any usage designation are also accepted; keys explicitly restricted to encryption are still rejected. // Default: true
 *             },
 *             pkce?: array{
 *                 enabled?: bool|Param, // Whether to use PKCE (Proof Key for Code Exchange, RFC 7636), which any current provider should support; only disable it for one that rejects the "code_challenge" parameter. A public client, whose "client_authentication" reports the "none" method, cannot disable it at all. // Default: true
 *                 method?: "S256"|"plain"|Param, // The PKCE code challenge method. RFC 7636, Section 4.2 mandates "S256" for every client able to compute it, so only ever pick "plain" for a provider that supports nothing else. // Default: "S256"
 *             },
 *             max_age?: int|Param, // Maximum elapsed seconds since the end-user authentication, sent as the "max_age" authorization parameter; the ID token must then carry an "auth_time" claim, which is checked against this value, "allowed_time_drift" included.
 *             authorization_params?: array<string, scalar|Param|null>,
 *             refresh_access_token?: bool|array{ // Renew the access token with the refresh token grant of RFC 6749, Section 6, so that it stays usable to call an API on behalf of the logged-in user. The provider only issues a refresh token when it was asked for one, e.g. with the "offline_access" scope, and the renewal needs the "expires_in" it is optional for the provider to report. Whether this is enabled or not, the tokens are held as the "oidc_refresh_token", "oidc_access_token" and "oidc_access_token_expires_at" attributes of the security token, and the "security.authenticator.oidc_login.token_refresher.<firewall>" service renews them on demand. A provider rotating refresh tokens expects the previous one never to be replayed, which a session handler locking the session guarantees, and the default one does.
 *                 enabled?: bool|Param, // Default: false
 *                 leeway?: int|Param, // How many seconds before its expiry the access token is renewed, so that one handed to a call in flight does not expire on the way. // Default: 30
 *             },
 *             enable_end_session?: bool|Param, // Enable RP-Initiated Logout via the OIDC end_session_endpoint. // Default: false
 *             post_logout_redirect_path?: scalar|Param|null, // Path or route to redirect to after OIDC logout. // Default: "/"
 *             backchannel_logout?: bool|array{ // Accept the logout tokens the OIDC provider posts when one of its sessions ends.
 *                 enabled?: bool|Param, // Default: false
 *                 path?: scalar|Param|null, // Path where the OIDC provider posts its logout tokens. // Default: "/oidc/backchannel-logout"
 *                 cache?: scalar|Param|null, // Id of the cache pool remembering the ended provider sessions, shared by every server of the application. // Default: "cache.app"
 *                 lifetime?: int|Param, // How long an ended provider session is remembered, in seconds; at least how long a session can stay idle. // Default: 86400
 *             },
 *         },
 *         form_login?: array{
 *             provider?: scalar|Param|null,
 *             remember_me?: bool|Param, // Deprecated: Setting the "security.firewalls..form_login.remember_me.remember_me" configuration option has no effect and is deprecated. It will be removed in Symfony 9.0. // Default: true
 *             success_handler?: scalar|Param|null,
 *             failure_handler?: scalar|Param|null,
 *             check_path?: scalar|Param|null, // Default: "/login_check"
 *             use_forward?: bool|Param, // Default: false
 *             login_path?: scalar|Param|null, // Default: "/login"
 *             username_parameter?: scalar|Param|null, // Default: "_username"
 *             password_parameter?: scalar|Param|null, // Default: "_password"
 *             csrf_parameter?: scalar|Param|null, // Default: "_csrf_token"
 *             csrf_token_id?: scalar|Param|null, // Default: "authenticate"
 *             enable_csrf?: bool|Param, // Default: false
 *             post_only?: bool|Param, // Default: true
 *             form_only?: bool|Param, // Default: false
 *             always_use_default_target_path?: bool|Param, // Default: false
 *             default_target_path?: scalar|Param|null, // Default: "/"
 *             target_path_parameter?: scalar|Param|null, // Default: "_target_path"
 *             use_referer?: bool|Param, // Default: false
 *             failure_path?: scalar|Param|null, // Default: null
 *             failure_forward?: bool|Param, // Default: false
 *             failure_path_parameter?: scalar|Param|null, // Default: "_failure_path"
 *         },
 *         form_login_ldap?: array{
 *             provider?: scalar|Param|null,
 *             remember_me?: bool|Param, // Deprecated: Setting the "security.firewalls..form_login_ldap.remember_me.remember_me" configuration option has no effect and is deprecated. It will be removed in Symfony 9.0. // Default: true
 *             success_handler?: scalar|Param|null,
 *             failure_handler?: scalar|Param|null,
 *             check_path?: scalar|Param|null, // Default: "/login_check"
 *             use_forward?: bool|Param, // Default: false
 *             login_path?: scalar|Param|null, // Default: "/login"
 *             username_parameter?: scalar|Param|null, // Default: "_username"
 *             password_parameter?: scalar|Param|null, // Default: "_password"
 *             csrf_parameter?: scalar|Param|null, // Default: "_csrf_token"
 *             csrf_token_id?: scalar|Param|null, // Default: "authenticate"
 *             enable_csrf?: bool|Param, // Default: false
 *             post_only?: bool|Param, // Default: true
 *             form_only?: bool|Param, // Default: false
 *             always_use_default_target_path?: bool|Param, // Default: false
 *             default_target_path?: scalar|Param|null, // Default: "/"
 *             target_path_parameter?: scalar|Param|null, // Default: "_target_path"
 *             use_referer?: bool|Param, // Default: false
 *             failure_path?: scalar|Param|null, // Default: null
 *             failure_forward?: bool|Param, // Default: false
 *             failure_path_parameter?: scalar|Param|null, // Default: "_failure_path"
 *             service?: scalar|Param|null, // Default: "ldap"
 *             dn_string?: scalar|Param|null, // Default: "{user_identifier}"
 *             query_string?: scalar|Param|null,
 *             search_dn?: scalar|Param|null, // Default: ""
 *             search_password?: scalar|Param|null, // Default: ""
 *             ldap_users_only?: bool|Param, // Only bind users of class "Symfony\Component\Ldap\Security\LdapUser" against the LDAP server, and leave any other user to the regular password checker. // Default: false
 *         },
 *         json_login?: array{
 *             provider?: scalar|Param|null,
 *             remember_me?: bool|Param, // Deprecated: Setting the "security.firewalls..json_login.remember_me.remember_me" configuration option has no effect and is deprecated. It will be removed in Symfony 9.0. // Default: true
 *             success_handler?: scalar|Param|null,
 *             failure_handler?: scalar|Param|null,
 *             check_path?: scalar|Param|null, // Default: "/login_check"
 *             use_forward?: bool|Param, // Default: false
 *             login_path?: scalar|Param|null, // Default: "/login"
 *             username_path?: scalar|Param|null, // Default: "username"
 *             password_path?: scalar|Param|null, // Default: "password"
 *         },
 *         json_login_ldap?: array{
 *             provider?: scalar|Param|null,
 *             remember_me?: bool|Param, // Deprecated: Setting the "security.firewalls..json_login_ldap.remember_me.remember_me" configuration option has no effect and is deprecated. It will be removed in Symfony 9.0. // Default: true
 *             success_handler?: scalar|Param|null,
 *             failure_handler?: scalar|Param|null,
 *             check_path?: scalar|Param|null, // Default: "/login_check"
 *             use_forward?: bool|Param, // Default: false
 *             login_path?: scalar|Param|null, // Default: "/login"
 *             username_path?: scalar|Param|null, // Default: "username"
 *             password_path?: scalar|Param|null, // Default: "password"
 *             service?: scalar|Param|null, // Default: "ldap"
 *             dn_string?: scalar|Param|null, // Default: "{user_identifier}"
 *             query_string?: scalar|Param|null,
 *             search_dn?: scalar|Param|null, // Default: ""
 *             search_password?: scalar|Param|null, // Default: ""
 *             ldap_users_only?: bool|Param, // Only bind users of class "Symfony\Component\Ldap\Security\LdapUser" against the LDAP server, and leave any other user to the regular password checker. // Default: false
 *         },
 *         access_token?: array{
 *             provider?: scalar|Param|null,
 *             remember_me?: bool|Param, // Deprecated: Setting the "security.firewalls..access_token.remember_me.remember_me" configuration option has no effect and is deprecated. It will be removed in Symfony 9.0. // Default: true
 *             success_handler?: scalar|Param|null,
 *             failure_handler?: scalar|Param|null,
 *             realm?: scalar|Param|null, // Default: null
 *             token_extractors?: Param|string|list<scalar|Param|null>,
 *             token_handler?: Param|string|array{
 *                 id?: scalar|Param|null,
 *                 oidc_user_info?: Param|string|array{
 *                     base_uri?: scalar|Param|null, // Base URI of the userinfo endpoint on the OIDC server, or the OIDC server URI to use the discovery (require "discovery" to be configured). The latter must end with a slash when it has a path, as the discovery path is resolved against it as a relative URL.
 *                     discovery?: array{ // Enable the OIDC discovery.
 *                         cache?: array{
 *                             id?: scalar|Param|null, // Cache service id to use to cache the OIDC discovery configuration.
 *                         },
 *                     },
 *                     claim?: scalar|Param|null, // Claim which contains the user identifier (e.g. sub, email, etc.). // Default: "sub"
 *                     client?: scalar|Param|null, // HttpClient service id to use to call the OIDC server.
 *                 },
 *                 oidc?: array{
 *                     discovery?: array{ // Enable the OIDC discovery.
 *                         base_uri?: Param|string|list<scalar|Param|null>,
 *                         cache?: array{
 *                             id?: scalar|Param|null, // Cache service id to use to cache the OIDC discovery configuration.
 *                         },
 *                         enforce_key_usage_verification?: bool|Param, // When enabled (default), only keys explicitly designated for signature (via "use":"sig" or a "key_ops" entry containing "sign"/"verify") are accepted. When disabled, keys without any usage designation are also accepted; keys explicitly restricted to encryption are still rejected. // Default: true
 *                         check_issuer?: bool|null|array<string, string|Param>,
 *                     },
 *                     claim?: scalar|Param|null, // Claim which contains the user identifier (e.g.: sub, email..). // Default: "sub"
 *                     audience?: Param|string|list<scalar|Param|null>,
 *                     issuers?: list<scalar|Param|null>,
 *                     algorithms?: list<scalar|Param|null>,
 *                     keyset?: scalar|Param|null, // JSON-encoded JWKSet used to sign the token (must contain a list of valid public keys).
 *                     encryption?: bool|array{
 *                         enabled?: bool|Param, // Default: false
 *                         enforce?: bool|Param, // When enabled, the token shall be encrypted. // Default: false
 *                         algorithms?: list<scalar|Param|null>,
 *                         keyset?: scalar|Param|null, // JSON-encoded JWKSet used to decrypt the token (must contain a list of valid private keys).
 *                     },
 *                     allowed_time_drift?: int|Param, // Allowed time drift in seconds for token validation (iat, nbf, exp claims). // Default: 0
 *                     enforce_at_jwt_type?: bool|Param|null, // When enabled, the "typ" header of the token must be "at+jwt" or "application/at+jwt", as RFC 9068 requires from a JWT access token. This rejects the ID tokens issued for the same audience. Disable it only for providers that do not follow the profile. Defaults to false in 8.2 and to true as of 9.0. // Default: null
 *                 },
 *                 cas?: array{
 *                     validation_url?: scalar|Param|null, // CAS server validation URL
 *                     prefix?: scalar|Param|null, // CAS prefix // Default: "cas"
 *                     http_client?: scalar|Param|null, // HTTP Client service // Default: null
 *                 },
 *                 oauth2?: Param|string|array{
 *                     http_client?: scalar|Param|null, // HttpClient service id the introspection endpoint is called with. Declare it as a scoped client whose "base_uri" is the introspection endpoint of your authorization server and whose "auth_basic" holds the credentials it authenticates with. Those are sent as given, where the "client_secret_basic" of RFC 6749 §2.3.1 form-urlencodes both halves, so encode a client id or a secret holding a colon, a plus or a space yourself.
 *                     audience?: Param|string|list<scalar|Param|null>,
 *                     issuer?: scalar|Param|null, // Identifier of the authorization server, checked against the "iss" of the introspection response. // Default: null
 *                     claim?: scalar|Param|null, // Claim which contains the user identifier (e.g.: sub, username, email...). Defaults to "sub", falling back to "username". // Default: null
 *                     allowed_time_drift?: int|Param, // Allowed time drift in seconds when validating the "iat", "nbf" and "exp" of the introspection response. // Default: 0
 *                     cache?: array{ // Cache the introspection responses of active tokens, never beyond their "exp".
 *                         id?: scalar|Param|null, // Cache service id to use to cache the introspection responses.
 *                         ttl?: int|Param, // Maximum lifetime in seconds of a cached introspection response. The shorter it is, the sooner a revoked token stops being accepted. // Default: 60
 *                     },
 *                     response_signature?: bool|array{ // Ask the authorization server for a signed introspection response (RFC 9701) and verify it.
 *                         enabled?: bool|Param, // Default: false
 *                         enforce?: bool|Param, // When enabled (default), a plain JSON introspection response is refused. // Default: true
 *                         algorithms?: list<scalar|Param|null>,
 *                         discovery?: bool|array{ // Read the keys the introspection response is verified against from the RFC 8414 metadata of the authorization server, whose URL is derived from the "issuer" this handler already declares. Only the "jwks_uri" is read from it: which algorithms are accepted stays declared here, so that an authorization server cannot widen it by announcing more.
 *                             enabled?: bool|Param, // Default: false
 *                             cache?: array{
 *                                 id?: scalar|Param|null, // Cache service id the metadata document and the keys it points at are stored in. // Default: "cache.app"
 *                             },
 *                         },
 *                         keyset?: scalar|Param|null, // JSON-encoded JWKSet holding the public keys of your authorization server, the ones it announces at its "jwks_uri", which the introspection response is verified against. // Default: null
 *                     },
 *                 },
 *             },
 *             resource_metadata?: array{ // Declaring this node serves the RFC 9728 protected resource metadata document of the firewall at "/.well-known/oauth-protected-resource" and advertises its URL in the "resource_metadata" parameter of the "WWW-Authenticate" header, which is how a client discovers where to get a token this firewall accepts. The route is declared by the "security.authenticator.access_token.route_loader" service, which the application must import as it does for the logout routes; make sure it is reachable without a token.
 *                 resource?: scalar|Param|null, // The resource identifier of this firewall: an HTTPS URL, without a fragment (e.g. "https://api.example.com" or "https://example.com/api"). Its path component is inserted after the well-known path, as RFC 9728, Section 3.1 prescribes, so that one host can serve the metadata of several protected resources. Defaults to the origin the document is served from, which is what a firewall covering a whole application wants. // Default: null
 *                 authorization_servers?: Param|string|list<scalar|Param|null>,
 *                 jwks_uri?: scalar|Param|null, // URL of the JWK Set holding the keys this resource signs its own responses with. Unrelated to the keys the access tokens are verified against, which belong to the authorization server. // Default: null
 *                 scopes_supported?: Param|string|list<scalar|Param|null>,
 *                 bearer_methods_supported?: Param|string|list<"header"|"body"|"query"|Param>,
 *                 resource_name?: scalar|Param|null, // Human-readable name of this resource, meant to be displayed to the end user. // Default: null
 *                 resource_documentation?: scalar|Param|null, // URL of the developer documentation of this resource. // Default: null
 *                 resource_policy_uri?: scalar|Param|null, // URL of the policy telling how the client may use the data this resource exposes. // Default: null
 *                 resource_tos_uri?: scalar|Param|null, // URL of the terms of service of this resource. // Default: null
 *             },
 *             dpop?: bool|array{ // Accepts only the access tokens bound to a key the request proves it holds (DPoP), presented under the "DPoP" scheme.
 *                 enabled?: bool|Param, // Default: false
 *                 algorithms?: list<scalar|Param|null>,
 *                 cache?: scalar|Param|null, // The cache pool proofs are remembered in to refuse a replay, shared by all the instances of the application. // Default: "cache.app"
 *                 proof_lifetime?: int|Param, // How long a proof is accepted after its "iat", in seconds. // Default: 60
 *                 allowed_time_drift?: int|Param, // Allowed time drift in seconds for the "iat" of a proof, both ways. // Default: 5
 *             },
 *         },
 *         http_basic?: array{
 *             provider?: scalar|Param|null,
 *             realm?: scalar|Param|null, // Default: "Secured Area"
 *         },
 *         http_basic_ldap?: array{
 *             provider?: scalar|Param|null,
 *             realm?: scalar|Param|null, // Default: "Secured Area"
 *             service?: scalar|Param|null, // Default: "ldap"
 *             dn_string?: scalar|Param|null, // Default: "{user_identifier}"
 *             query_string?: scalar|Param|null,
 *             search_dn?: scalar|Param|null, // Default: ""
 *             search_password?: scalar|Param|null, // Default: ""
 *             ldap_users_only?: bool|Param, // Only bind users of class "Symfony\Component\Ldap\Security\LdapUser" against the LDAP server, and leave any other user to the regular password checker. // Default: false
 *         },
 *         remember_me?: array{
 *             secret?: Param|string|list<scalar|Param|null>,
 *             service?: scalar|Param|null,
 *             user_providers?: Param|string|list<scalar|Param|null>,
 *             catch_exceptions?: bool|Param, // Default: true
 *             signature_properties?: list<scalar|Param|null>,
 *             token_provider?: Param|string|array{
 *                 service?: scalar|Param|null, // The service ID of a custom remember-me token provider.
 *                 doctrine?: bool|array{
 *                     enabled?: bool|Param, // Default: false
 *                     connection?: scalar|Param|null, // Default: null
 *                 },
 *             },
 *             token_verifier?: scalar|Param|null, // The service ID of a custom rememberme token verifier.
 *             name?: scalar|Param|null, // Default: "REMEMBERME"
 *             lifetime?: int|Param, // Default: 31536000
 *             path?: scalar|Param|null, // Default: "/"
 *             domain?: scalar|Param|null, // Default: null
 *             secure?: true|false|"auto"|Param, // Defaults to the value of "framework.session.cookie_secure", or to "auto".
 *             httponly?: bool|Param, // Default: true
 *             samesite?: null|"lax"|"strict"|"none"|Param, // Defaults to the value of "framework.session.cookie_samesite", or to "lax".
 *             always_remember_me?: bool|Param, // Default: false
 *             remember_me_parameter?: scalar|Param|null, // Default: "_remember_me"
 *         },
 *     }>,
 *     access_control?: list<array{ // Default: []
 *         request_matcher?: scalar|Param|null, // Default: null
 *         requires_channel?: scalar|Param|null, // Default: null
 *         path?: scalar|Param|null, // Use the urldecoded format. // Default: null
 *         host?: scalar|Param|null, // Default: null
 *         port?: int|Param, // Default: null
 *         ips?: Param|string|list<scalar|Param|null>,
 *         attributes?: array<string, scalar|Param|null>,
 *         route?: scalar|Param|null, // Default: null
 *         methods?: Param|string|list<scalar|Param|null>,
 *         allow_if?: scalar|Param|null, // Default: null
 *         roles?: Param|string|list<scalar|Param|null>,
 *     }>,
 *     role_hierarchy?: array<string, Param|string|list<scalar|Param|null>>,
 * }
 * @psalm-type TwigConfig = array{
 *     form_themes?: list<scalar|Param|null>,
 *     globals?: array<string, array{ // Default: []
 *         id?: scalar|Param|null,
 *         type?: scalar|Param|null,
 *         value?: mixed,
 *         ...<string, mixed>
 *     }>,
 *     autoescape_service?: scalar|Param|null, // Default: null
 *     autoescape_service_method?: scalar|Param|null, // Default: null
 *     cache?: scalar|Param|null, // Default: true
 *     charset?: scalar|Param|null, // Default: "%kernel.charset%"
 *     debug?: bool|Param, // Default: "%kernel.debug%"
 *     strict_variables?: bool|Param, // Default: "%kernel.debug%"
 *     auto_reload?: scalar|Param|null,
 *     optimizations?: int|Param,
 *     default_path?: scalar|Param|null, // The default path used to load templates. // Default: "%kernel.project_dir%/templates"
 *     file_name_pattern?: Param|string|list<scalar|Param|null>,
 *     paths?: array<string, mixed>,
 *     date?: array{ // The default format options used by the date filter.
 *         format?: scalar|Param|null, // Default: "F j, Y H:i"
 *         interval_format?: scalar|Param|null, // Default: "%d days"
 *         timezone?: scalar|Param|null, // The timezone used when formatting dates, when set to null, the timezone returned by date_default_timezone_get() is used. // Default: null
 *     },
 *     number_format?: array{ // The default format options for the number_format filter.
 *         decimals?: int|Param, // Default: 0
 *         decimal_point?: scalar|Param|null, // Default: "."
 *         thousands_separator?: scalar|Param|null, // Default: ","
 *     },
 *     mailer?: array{
 *         html_to_text_converter?: scalar|Param|null, // A service implementing the "Symfony\Component\Mime\HtmlToTextConverter\HtmlToTextConverterInterface". // Default: null
 *     },
 * }
 * @psalm-type BeffroiConfig = array{
 *     tenant?: array{ // The one tenant of this deployment: the key is already a tenant, a table comes later.
 *         issuer?: scalar|Param|null, // Issuer identifier (OIDC Discovery §3): an absolute HTTPS URL, no query, no fragment, no trailing slash; plain HTTP on a loopback host only.
 *         slug?: scalar|Param|null, // Stable name of the tenant, from which its identifier is derived; renaming it is creating another tenant. // Default: "default"
 *         name?: scalar|Param|null, // Display name; the host of the issuer when absent. // Default: null
 *         look?: array{ // What this tenant shows of itself on every page of its provider besides its name (issue #449). A deployment that declares none of it is served the pages it has always been served.
 *             logo_uri?: scalar|Param|null, // Where the logo of the tenant is served from: an absolute HTTPS URL, no fragment, no credentials; plain HTTP on a loopback host only. The browser of the visitor loads it, never the provider, and the pages name its origin in their Content-Security-Policy. // Default: null
 *             primary_color?: scalar|Param|null, // The colour the buttons and the links of the pages are drawn in: three or six hexadecimal digits behind a hash, as "#1b4b8f". It needs "primary_content_color", a colour being unusable without the colour of what is written on it. // Default: null
 *             primary_content_color?: scalar|Param|null, // The colour of what is written on "primary_color", the two being declared together or not at all. // Default: null
 *         },
 *         self_served_claims?: list<scalar|Param|null>,
 *         authentication_classes?: array<string, scalar|Param|null>,
 *     },
 *     keys?: array{ // Where the keys of the tenants live: sealed by the KMS named here, stored as files until a table takes over (architecture §3.3).
 *         kms?: scalar|Param|null, // Name of the KMS client that seals the private keys, an entry of "key_management.clients" of the framework configuration (a DSN there, or the members of a composite client); the KMS keeps, it never signs.
 *         key_id?: scalar|Param|null, // The key of that KMS the keys of the tenants are sealed under (backend-specific: the id of a sodium key, a Vault transit key name, an ARN); "{tenant}" stands for the slug of the tenant, one master key each.
 *         data_key_secrets?: list<scalar|Param|null>,
 *         storage?: scalar|Param|null, // Directory of the sealed keys, one file per key and per tenant, and of the pairwise salt of each tenant, one file beside them (OIDC Core section 8.1). // Default: "%kernel.project_dir%/var/keys"
 *         jwks_max_age?: int|Param, // How long a relying party may cache the JWK Set, in seconds (RFC 7517 §5, architecture §4.8); the staging window of a rotation derives from it, so that the two cannot drift apart (§3.3). // Default: 300
 *         staging_delay?: int|Param, // How long a new key is published before it signs, in seconds (architecture §3.3, §9), for every family of keys but the SAML signing key, which has its own ("saml.identity_provider.staging_delay"); unless set, jwks_max_age plus the 60 s refetch cooldown of oidc_login: the max-age is what a relying party with a warm cache needs to see the new key, the cooldown what one served by a shared HTTP cache needs to refetch it. // Default: null
 *         age?: int|Param, // How long a key works before the planning stages a successor for it, in seconds, counted from its activation (architecture §3.3), for every family of keys but the SAML signing key, which has its own ("saml.identity_provider.age"): ninety days by default, which is inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key and short enough that the rotation path is walked four times a year rather than first walked during an incident. It has to be longer than the window a retiring key holds the JWK Set open for, which is the longest lifetime of what a key of that use is bound to, or every rotation would leave a key behind; the rotation refuses an age that is not. // Default: 7776000
 *     },
 *     webauthn?: array{ // What the passkey ceremonies read besides the tenant (architecture §3.4).
 *         metadata_storage?: scalar|Param|null, // Directory of the FIDO metadata the ceremonies check an attestation against: the documents "beffroi:webauthn:mds-refresh" verified and "beffroi:webauthn:mds-import" stored, next to the keys; empty until one of them ran, which the enrolment of the provider does not need. // Default: "%kernel.project_dir%/var/webauthn"
 *     },
 *     mutual_tls?: array{ // Where a client that presents a certificate reaches the endpoints (RFC 8705 §5). The certificate itself comes from the edge, which is infrastructure and not configuration (architecture §6); what a deployment says here is the host its listener asks for one on.
 *         origin?: scalar|Param|null, // Scheme and authority of that host, without a path ("https://mtls.op.example"). The endpoints are announced under it in "mtls_endpoint_aliases", with the paths they are served at. Absent, the document announces no alias and a client authenticating by mutual TLS reaches the ordinary endpoints, which is what a deployment serving one host does. // Default: null
 *     },
 *     tokens?: array{ // Lifetimes in seconds. The defaults are the choices of architecture §9.
 *         authorization_code_ttl?: int|Param, // RFC 6749 §4.1.2 recommends ten minutes at most; sixty seconds bound the injection window. // Default: 60
 *         access_token_ttl?: int|Param, // Both shapes of access token (architecture §4.6): the self-contained one cannot be revoked, and a short lifetime bounds the exposure; the opaque one gets the same, a revocation is a facility and not a reason to live longer. // Default: 600
 *         id_token_ttl?: int|Param, // Default: 600
 *         request_uri_ttl?: int|Param, // Seconds a request_uri answered by the pushed authorization request endpoint lives (RFC 9126 §2.2); sixty is the example of the specification, and the browser is sent the moment the client holds the reference. // Default: 60
 *         device_code_ttl?: int|Param, // Seconds a device code and the user code beside it live (RFC 8628 §3.2); ten minutes is what a user needs to read a code off one screen and type it on another. // Default: 600
 *         device_code_interval?: int|Param, // Seconds a client waits between two polls of the token endpoint (RFC 8628 §3.2); five is the default of the specification, and a client that polls faster is told to add five. // Default: 5
 *         backchannel_authentication_ttl?: int|Param, // Seconds a backchannel authentication request lives when the client asks for nothing (CIBA Core §7.3); five minutes is what somebody needs to be reached and to answer. // Default: 300
 *         backchannel_authentication_max_requested_expiry?: int|Param, // Seconds the longest lifetime a client may ask for with "requested_expiry" (CIBA Core §7.1); a request that asks for more is served this, not refused. // Default: 1800
 *         backchannel_authentication_interval?: int|Param, // Seconds a client waits between two polls of the token endpoint for a backchannel request (CIBA Core §7.3); five is the default of the specification, and a client that polls faster is told to add five. // Default: 5
 *         refresh_token_ttl?: int|Param, // Sliding lifetime of a refresh token, renewed at each rotation. // Default: 2592000
 *         refresh_token_absolute_ttl?: int|Param, // Lifetime of a refresh token family from the authorization that started it; no rotation extends it. // Default: 7776000
 *     },
 *     load?: array{ // How many requests the provider takes in a window, by origin and by authenticated client (decision 0014). Both budgets always exist; these are their numbers, which depend on the size of the deployment. A number too low on /token or on /jwks is an outage a deployment inflicts on itself, so they are measured on what its own clients send.
 *         origin?: array{ // What one client address may send, whatever it asks for and whether or not it has proved anything. It is not scoped to a tenant: what it bounds is the load on the machine, which every tenant of a deployment shares.
 *             limit?: int|Param, // Requests taken from one address in the window. // Default: 2400
 *             interval?: int|Param, // Seconds the window covers. // Default: 60
 *         },
 *         client?: array{ // What one client may ask once its authentication has succeeded, by tenant and by client. This is the one a tenant reads when one of its applications goes into a loop.
 *             limit?: int|Param, // Requests taken from one authenticated client in the window. // Default: 1200
 *             interval?: int|Param, // Seconds the window covers. // Default: 60
 *         },
 *     },
 *     journal?: array{ // The acts of the provider, written down and forgotten again (issue #454): who did what, when and from where. Nothing turns it on; what is configured is how long an act is kept.
 *         retention?: int|Param, // Days an act is kept before the timed step forgets it; six months by default, the duration the deliberation 2021-122 of the CNIL holds for a log of connections. A deployment under another obligation says its own. // Default: 180
 *     },
 *     history?: array{ // What a claim of a person used to say, and what they made it say (issue #482). Nothing turns it on; what is configured is how long a change is kept.
 *         retention?: int|Param, // Days a change is kept before the timed step forgets it; the duration the journal keeps an act, a change and the act that announced it being two halves of one answer. // Default: 180
 *     },
 *     geoip?: array{ // The databases of addresses the enrichment of a provenance reads (architecture §3.5): where they are kept and what they are downloaded under.
 *         storage?: scalar|Param|null, // Directory of the GeoLite2 databases the enrichment reads, next to the keys: the files "beffroi:geoip:refresh" and the weekly step store, empty until one of them ran, which every flow of the provider is served without. // Default: "%kernel.project_dir%/var/geoip"
 *         license_key?: scalar|Param|null, // Licence key of the MaxMind account the GeoLite2 editions are downloaded under; empty by default, and a deployment that leaves it empty downloads nothing and says no place. The databases are published by MaxMind under their own licence, which is why nothing is shipped and nothing is fetched without this. // Default: ""
 *     },
 *     passwords?: array{ // What a password posed here is compared against before it is written (architecture §3.4): the list of compromised passwords, and nothing else; how long a password has to be and how hard to guess are rules of the core and not options.
 *         breached?: array{ // The list of values known to be commonly used, expected or compromised a prospective password is compared against (NIST SP 800-63B §3.1.1.2).
 *             endpoint?: scalar|Param|null, // Base URL of a range endpoint in the shape of Pwned Passwords (https://api.pwnedpasswords.com/range/), to which the first five hexadecimal characters of the SHA-1 of a password are appended; the comparison of the thirty-five that are left is local, and no API key is needed. Empty by default, and a deployment that leaves it empty asks nobody: it poses passwords and signs people in on the rules of the core alone, no password and no prefix of one ever leaving it. // Default: ""
 *             timeout?: float|Param, // How long a request to the list may take, in seconds, for the whole exchange. It bounds the console that writes a password for somebody and the page where a person replaces their own, where the answer is waited for; the lookup of a password already posed is a lane and waits on nothing. // Default: 2.0
 *         },
 *     },
 *     interaction?: array{ // The pages a browser is sent to while an authorization request waits for a login or a consent (architecture §4.3).
 *         login_hint?: "sub"|"username"|"none"|Param, // What a "login_hint" of an authorization request names for this tenant, read one way and never searched for (OIDC Core §3.1.2.1): "sub" the subject this provider issued to that client, "username" the name the user signs in with, "none" for a deployment that tags a reader of its own. The login page offers the name of the user the hint names and nothing at all when it names nobody, the value itself being one the person never typed. These are the names the backchannel flow reads its own hint by. // Default: "sub"
 *     },
 *     back_channel_logout?: array{ // How a logout token reaches a client that registered a backchannel_logout_uri (Back-Channel Logout 1.0 §2.5), and for how long. These values are what the transport of the notifications does with a send that failed, the application giving that transport the policy of the bundle, and what a signing key is held back for while a logout token it signed may still be on its way (issue #155).
 *         timeout?: float|Param, // Seconds one attempt is given, connection included. A relying party that hangs must not hold a worker; five seconds is long for a request that reads nothing back, and a client that needs longer is a client that is down, which the retries cover. // Default: 5.0
 *         retries?: int|Param, // How many times a send that did not reach its client comes back. A relying party that is restarting answers for a minute and then works; beyond the schedule below, it is down, and the provider says so rather than trying for ever. // Default: 6
 *         retry_delay?: int|Param, // Seconds before the first retry. // Default: 2
 *         retry_multiplier?: int|Param, // What each wait is multiplied by to give the next one. // Default: 3
 *         retry_max_delay?: int|Param, // Seconds a wait never exceeds, whatever the multiplier makes of it. // Default: 60
 *     },
 *     backchannel_authentication?: array{ // The flow where a client asks for a user it names and the user approves on a device they already hold (CIBA Core §7). A client takes part in it by registering a grant and a delivery mode, one client at a time; nothing here turns it on for anybody.
 *         login_hint?: "sub"|"username"|"none"|Param, // What a "login_hint" of a backchannel authentication request names for this tenant, read one way and never searched for (CIBA Core §7.1): "sub" the subject this provider issued to that client, "username" the name the user signs in with, "none" for a deployment that tags a reader of its own. CIBA Core §15 asks for an identifier that says nothing outside this provider, which "sub" is and a username is not. These are the names the login page reads its own hint by. // Default: "sub"
 *         client_notification_timeout?: float|Param, // Seconds one call to a client notification endpoint is given, connection included (CIBA Core §10.2). A client that hangs must not hold a worker; how many times the call is tried again is the retry policy of the notifications lane, as it is for a logout token. // Default: 3.0
 *     },
 *     web_push?: array{ // Reaching a user through the push service of a browser they signed in with (RFC 8030, architecture §5.6). Absent, nothing of it is wired: no push leaves this deployment and the page where a browser would subscribe says so.
 *         subject?: scalar|Param|null, // The "sub" of the token this provider signs for a push service (RFC 8292 §2.1): a "mailto:" or "https:" URI at which the operator of this deployment can be reached about what it sends. Naming one is what turns web push on; absent, nothing of it is wired. // Default: null
 *         timeout?: float|Param, // Seconds one push to one push service is given, connection included. A push service that hangs must not hold a worker; how many times it is tried again is the retry policy of the notifications lane, as it is for a logout token. // Default: 3.0
 *     },
 *     client_authentication?: array{ // How a client proves who it is at the endpoints that authenticate one (RFC 6749 §2.3, OIDC Core §9). Which methods the provider takes is the wiring, not this: a method is a tagged service, and what is tagged is what is announced.
 *         assertion_max_lifetime?: int|Param, // Seconds ahead of the request the "exp" of a client assertion may be (RFC 7523 §3). An assertion is minted for one request; a long one is a bearer token nobody watches. // Default: 300
 *         assertion_leeway?: int|Param, // Seconds allowed of the clock of a client, both ways. // Default: 30
 *         jwks_timeout?: float|Param, // Seconds one read of a jwks_uri is given, connection included. A client that hangs must not hold a worker: an endpoint authenticating it is waiting. // Default: 3.0
 *         jwks_max_size?: int|Param, // Bytes a jwks_uri may answer before the read stops; a JWK Set of a client holds a handful of public keys. // Default: 65536
 *         jwks_ttl?: int|Param, // Seconds the keys read back from a jwks_uri are kept in the pool the workers share. // Default: 86400
 *         jwks_refetch_cooldown?: int|Param, // Seconds between two reads of the same jwks_uri when an assertion names a "kid" the kept set does not hold. A client that rotates a key is followed within one request; a client that signs with a key it never published cannot make the provider call it on every request. // Default: 300
 *     },
 *     request_objects?: array{ // How a request the client carried in a JWT is read (RFC 9101 §4, OIDC Core §6). Which algorithm verifies it is the wiring and the registration of the client, not this; an unsigned object is read from a client that registered "none" and from no other.
 *         max_lifetime?: int|Param, // Seconds a request object may stand, from its "nbf" (RFC 9101 §4). An object is a request made now; a long one is an authorization a client keeps. // Default: 3600
 *         leeway?: int|Param, // Seconds allowed of the clock of a client, both ways. // Default: 30
 *         timeout?: float|Param, // Seconds one read of a request_uri is given, connection included. The browser of a user is waiting on it; no redirect is followed and only a URL the client registered is ever read. // Default: 3.0
 *         max_size?: int|Param, // Bytes a request_uri may answer before the read stops; a request object carries the parameters of one request. // Default: 65536
 *     },
 *     dpop?: array{ // How a proof of possession is read (RFC 9449 §4.3). What a proof may be signed with is the wiring, the same algorithms the provider signs with, and what the document announces in "dpop_signing_alg_values_supported"; nothing here weakens a proof, and a client that sends none is not concerned.
 *         proof_max_age?: int|Param, // Seconds a proof stands, from its "iat" (RFC 9449 §4.3). A proof is a signature over one request being sent; a long window is a window a proof taken off the wire may be sent again in. // Default: 60
 *         leeway?: int|Param, // Seconds allowed of the clock of a client, both ways. // Default: 30
 *         nonce?: array{ // Whether this provider asks a proof to carry a nonce of its own (RFC 9449 §8), which is the server's to decide: the "iat" of a proof is what its client says, a nonce is what the provider knows. A client that speaks DPoP handles the refusal that hands it one; one that does not is not concerned either way.
 *             required?: bool|Param, // Default: false
 *             ttl?: int|Param, // Seconds a nonce is accepted once issued. // Default: 300
 *         },
 *     },
 *     trusted_issuers?: array<string, array{ // Default: []
 *         jwks?: mixed, // The JWK Set of the issuer, inline (RFC 7517 §5): public keys only, and the only keys an assertion of this issuer is ever verified against, whatever its header names (RFC 8725 §3.10). Either this or "jwks_uri", never both and never neither. // Default: null
 *         jwks_uri?: scalar|Param|null, // Where the JWK Set of the issuer is read back from instead (RFC 7517 §5), which is how an issuer that rotates its keys publishes them: one GET over HTTPS, no redirect followed, read once and kept in a pool the workers share, and read again at most once per cooldown when an assertion names a "kid" the kept set does not hold. Either this or "jwks", never both and never neither. // Default: null
 *         signing_algorithms?: list<scalar|Param|null>,
 *         clients?: list<scalar|Param|null>,
 *         identity_provider?: scalar|Param|null, // The source of the linked identities the subjects of its assertions name (decision 0002): the "sub" of an assertion is a user of this tenant only when a linked identity of that source says so, and no user is ever created here. // Default: null
 *         trusted_scopes?: list<scalar|Param|null>,
 *     }>,
 *     clients?: array<string, array{ // Default: []
 *         client_name?: scalar|Param|null, // Shown on the consent page (OIDC Registration §2); the client identifier when absent. // Default: null
 *         client_uri?: scalar|Param|null, // The home page of the client (OIDC Registration §2), linked from the consent page; HTTPS, or plain HTTP on a loopback host. // Default: null
 *         logo_uri?: scalar|Param|null, // The logo the consent page shows for this client (OIDC Registration §2); HTTPS, or plain HTTP on a loopback host. // Default: null
 *         policy_uri?: scalar|Param|null, // How this client uses the data it is given (OIDC Registration §2), linked from the consent page; HTTPS, or plain HTTP on a loopback host. // Default: null
 *         tos_uri?: scalar|Param|null, // The terms of service of this client (OIDC Registration §2), linked from the consent page; HTTPS, or plain HTTP on a loopback host. // Default: null
 *         contacts?: list<scalar|Param|null>,
 *         secret?: scalar|Param|null, // At least 32 visible ASCII characters, generated, never chosen; absent for a public client. // Default: null
 *         redirect_uris?: list<scalar|Param|null>,
 *         post_logout_redirect_uris?: list<scalar|Param|null>,
 *         grant_types?: list<scalar|Param|null>,
 *         response_types?: list<scalar|Param|null>,
 *         scope?: scalar|Param|null, // The closed list of scopes this client may ask for (RFC 7591 §2), space-delimited as a request writes it (RFC 6749 §3.3); a scope it did not register is refused with invalid_scope. Left out, it takes the three an application that signs a user in comes for. // Default: "openid profile email"
 *         token_endpoint_auth_method?: scalar|Param|null, // How this client authenticates at the endpoints that authenticate a client (OIDC Core §9), among the methods the provider is wired with; left out, it takes the first wired one. A name nothing authenticates with fails at boot. // Default: null
 *         requires_consent?: bool|Param, // Consent is the rule; a first-party application is the named exception. // Default: true
 *         requires_pkce?: bool|Param, // PKCE S256 is the rule; a confidential client that cannot send a code_challenge is the named exception of decision 0008, refused for a public client. A challenge the client sends is verified all the same. // Default: true
 *         require_pushed_authorization_requests?: bool|Param, // The only way this client starts an authorization request is by pushing it (RFC 9126 §6), which is what FAPI 2.0 asks of one; an ordinary request from it is refused on a page before its redirect URI is even read. Per client, nothing global: the document announces the requirement when every registered client carries it. // Default: false
 *         require_sender_constrained_tokens?: bool|Param, // The tokens of this client are bound to what the request proves it holds, or the request is refused (FAPI 2.0 Security Profile §5.3.1): a token request that proves neither a certificate (RFC 8705 §3) nor a key (RFC 9449 §5) is answered with an error rather than with bearer tokens. Per client, nothing global. // Default: false
 *         tls_client_certificate_bound_access_tokens?: bool|Param, // The tokens of this client are bound to the certificate it presents at the TLS handshake, whichever way it authenticated (RFC 8705 §3.4), which is what FAPI 1.0 Advanced Final §5.2.2 asks of a client authenticating with an assertion on a profile that binds. A token request of this client that proves no certificate is refused rather than answered with tokens bound to nothing, before anything is read of what it came to spend. A client recognised by its certificate gets bound tokens anyway (§3); per client, nothing global. // Default: false
 *         require_signed_request_object?: bool|Param, // A request of this client is only read from a request object it signed (RFC 9101 §10.5, require_signed_request_object; FAPI 2.0 Message Signing §5.3.1; FAPI-CIBA §5.2.2), whether the object arrives in the query, behind a request_uri, inside the record it pushed or in the body of a backchannel authentication request. An unsigned authorization request is refused on a page before its redirect URI is read, exactly as a request that was not pushed is; an unsigned backchannel one is refused invalid_request. // Default: false
 *         id_token_signed_response_alg?: scalar|Param|null, // The JWS algorithm the ID tokens and the logout tokens of this client are signed with (OIDC Registration §2), among those the provider is wired with; left out, the provider signs them with its default. A name nothing signs under fails at boot. // Default: null
 *         id_token_encrypted_response_alg?: scalar|Param|null, // The JWE key management algorithm the ID tokens of this client are encrypted to one of its keys with, once signed (OIDC Core §3.1.3.7), among those the provider is wired with. It comes with id_token_encrypted_response_enc, never alone, and the client publishes a key it can be addressed to; left out, the ID token travels signed and in clear, which is what every client does today. // Default: null
 *         id_token_encrypted_response_enc?: scalar|Param|null, // The JWE content encryption algorithm the payload of that ID token is encrypted with (OIDC Core §3.1.3.7), among those the provider is wired with. OIDC Registration §2 defaults it to a value this provider is not wired with, so it is named or it is refused at boot. // Default: null
 *         userinfo_signed_response_alg?: scalar|Param|null, // The JWS algorithm the UserInfo answer of this client is signed with (OIDC Core §5.3.2), among those the provider is wired with; the answer is then served as "application/jwt" and carries an "iss" and an "aud" beside the claims. Left out, the answer is the plain JSON, which is what every client that asks for nothing receives. // Default: null
 *         userinfo_encrypted_response_alg?: scalar|Param|null, // The JWE key management algorithm the UserInfo answer of this client is encrypted to one of its keys with (OIDC Core §5.3.2), among those the provider is wired with. It comes with userinfo_encrypted_response_enc, never alone. Without userinfo_signed_response_alg, what is encrypted is the plain JSON of the claims, §5.3.2 allowing an answer to be encrypted without being signed. // Default: null
 *         userinfo_encrypted_response_enc?: scalar|Param|null, // The JWE content encryption algorithm the payload of that UserInfo answer is encrypted with (OIDC Core §5.3.2), among those the provider is wired with. // Default: null
 *         authorization_signed_response_alg?: scalar|Param|null, // The JWS algorithm the signed authorization responses of this client are signed with (JARM §3), among those the provider is wired with; left out, the provider signs them with its default. It applies to the answers this client asks for with response_mode=jwt, query.jwt or form_post.jwt, a refusal as well as a code. // Default: null
 *         authorization_encrypted_response_alg?: scalar|Param|null, // The JWE key management algorithm the signed authorization responses of this client are encrypted to one of its keys with, once signed (JARM §3), among those the provider is wired with. It comes with authorization_encrypted_response_enc, never alone. // Default: null
 *         authorization_encrypted_response_enc?: scalar|Param|null, // The JWE content encryption algorithm the payload of that authorization response is encrypted with (JARM §3), among those the provider is wired with. // Default: null
 *         access_token_format?: scalar|Param|null, // The shape the access tokens of this client are written in, among those the provider is wired to write: "jwt" (RFC 9068, verified offline against the JWK Set) or "opaque" (a reference the resource server introspects, RFC 7662, revocable at once). Left out, it takes the first wired one. A name nothing writes fails at boot. Per client, nothing global. // Default: null
 *         backchannel_logout_uri?: scalar|Param|null, // Where the provider posts a logout token when a session this client signed in ends (Back-Channel Logout 1.0 §2.2); HTTPS, or plain HTTP on a loopback host. Absent for a client the provider does not tell. // Default: null
 *         backchannel_logout_session_required?: bool|Param, // The client reads the "sid" of the logout token to know which session ended (Back-Channel Logout 1.0 §2.2); it needs a backchannel_logout_uri. The provider sends "sid" either way. // Default: false
 *         frontchannel_logout_uri?: scalar|Param|null, // Loaded in a frame of the logout page when a session this client signed in ends (Front-Channel Logout 1.0 §3); HTTPS, or plain HTTP on a loopback host. Absent for a client the page does not load. It reaches the client only if the browser sends that client its cookies. // Default: null
 *         frontchannel_logout_session_required?: bool|Param, // The client reads "iss" and "sid" on its logout URI to know which session ended (Front-Channel Logout 1.0 §2); it needs a frontchannel_logout_uri. The two parameters are added for this client only, §2 making them conditional. // Default: false
 *         jwks?: mixed, // The JWK Set of the client, inline (RFC 7591 §2): public keys only, and exclusive with jwks_uri. A client that authenticates with private_key_jwt publishes one of the two. // Default: null
 *         jwks_uri?: scalar|Param|null, // Where the JWK Set of the client is read back from (RFC 7591 §2); HTTPS, or plain HTTP on a loopback host, no redirect followed. Exclusive with jwks. // Default: null
 *         subject_type?: scalar|Param|null, // The kind of "sub" this client sees for a user (OIDC Core §8), under the name the resolver of that kind gives itself, among the kinds this provider assigns one for, which is what subject_types_supported announces. Left out, the client registers none and sees the kind the provider assigns by default. // Default: null
 *         sector_identifier_uri?: scalar|Param|null, // The document naming every redirection URI of the clients that share a "sub" with this one (OIDC Core §8.1); HTTPS, no redirect followed. // Default: null
 *         initiate_login_uri?: scalar|Param|null, // Where a third party sends a user to have this provider begin a login at this client (OIDC Core §4, OIDC Registration §2); HTTPS, on a loopback host as anywhere else: §2 gives this member none of the tolerance the other URIs of a client keep. // Default: null
 *         request_object_signing_alg?: scalar|Param|null, // The JWS algorithm the request objects of this client are signed with (OIDC Registration §2), among those the provider is wired with; left out, any of them verifies one. The value "none" is the named exception of decision 0006: the objects of that client carry no signature and are read all the same, which no FAPI client registers and a client with require_signed_request_object cannot (RFC 9101 §10.5). A client that names an algorithm publishes its keys in jwks or behind a jwks_uri. // Default: null
 *         backchannel_token_delivery_mode?: scalar|Param|null, // How this client is told that a backchannel authentication request has been answered (CIBA Core §4), among the modes the provider is wired with: "poll" for a client that asks the token endpoint again until it is answered, "ping" for one this provider calls back first. There is no default: a client that registers none is not a client of that flow, and the endpoint where it starts refuses it. A name nothing serves fails at boot. // Default: null
 *         backchannel_client_notification_endpoint?: scalar|Param|null, // Where this provider posts the identifier of a backchannel request once it has been answered (CIBA Core §7.1, §10.2); HTTPS, or plain HTTP on a loopback host, no redirect followed. It goes with a delivery mode where the provider calls the client, never alone, and never without one. // Default: null
 *         resources?: list<scalar|Param|null>,
 *         authorization_details_types?: list<scalar|Param|null>,
 *         token_exchange?: array{ // What this client may do at the token exchange (RFC 8693 §2.1), for a client registered for that grant and for no other. A closed declaration: a client presenting something it did not register for is refused whatever the thing says. Which resources the new token may be addressed to is the resources option above, as it is for every other grant.
 *             subject_token_types?: list<scalar|Param|null>,
 *             may_act_for_a_user?: bool|Param, // Whether this client may present a token somebody signed in for. False for a service that only ever exchanges tokens of its own (RFC 6749 §4.4): a gateway carrying a user's token is not the same party, and a deployment says which of the two it registered. // Default: false
 *         },
 *         may_act?: scalar|Param|null, // Who may act for the subject of a token issued to this client (RFC 8693 §4.4), as a subject: it is written on every token this client receives, and an exchange asked for by anybody else is refused. Absent, the token says nothing and what decides is the registration of whoever asks. // Default: null
 *         request_uris?: list<scalar|Param|null>,
 *         tls_client_auth_subject_dn?: scalar|Param|null, // The subject distinguished name of the certificate this client presents (RFC 8705 §2.1.2), in the string form of RFC 4514; it is written back at boot the way the provider writes the name it reads out of a certificate, so a name as "openssl x509 -noout -subject -nameopt RFC2253" prints it is registered as it is. One of the five keys below, and one only, for a client that authenticates with tls_client_auth. // Default: null
 *         tls_client_auth_san_dns?: scalar|Param|null, // The dNSName entry of the subject alternative name extension this client is recognised by (RFC 8705 §2.1.2), compared without regard to case (RFC 4343 §1). // Default: null
 *         tls_client_auth_san_uri?: scalar|Param|null, // The uniformResourceIdentifier entry this client is recognised by (RFC 8705 §2.1.2), compared as the text it is. // Default: null
 *         tls_client_auth_san_ip?: scalar|Param|null, // The iPAddress entry this client is recognised by (RFC 8705 §2.1.2), in dotted decimal or colon-delimited hexadecimal; it is compared as the octets it stands for, not as the text. // Default: null
 *         tls_client_auth_san_email?: scalar|Param|null, // The rfc822Name entry this client is recognised by (RFC 8705 §2.1.2), compared as it is written (RFC 5321 §2.4). // Default: null
 *     }>,
 *     client_registration?: array{ // How a client that nobody declared comes to exist here (RFC 7591, decision 0009). Absent, the tenant registers nobody, which is the default and what a deployment that writes nothing gets.
 *         mode?: scalar|Param|null, // What authorises a registration, by the name the class that is that mode gives itself. This provider is wired with "initial_access_token", a credential the tenant issues, names, limits in number and duration and revokes (RFC 7591 section 1.2), with "open", which registers whoever asks with no credential at all (RFC 7591 section 1.3) and is written by a tenant that has no real user, and with "software_statement", a statement signed by an authority this tenant pins under "statement_issuers" below (RFC 7591 section 2.3), which is the mode that crosses the boundary of an organisation since the provider issues nothing. Left out, the tenant has no registration endpoint at all: it is not a mode of refusing, it is the absence of the endpoint. It is named per tenant and nothing here opens a mode for more than the tenant that names it. // Default: null
 *         keep_a_client_unused_for?: int|Param, // Seconds a client that was used may go without being used again before it is deleted (decision 0009). Ninety days by default, which is the absolute lifetime of a refresh token family this provider is configured with by default: past it, nothing that client was ever issued can still be presented, so deleting it takes nothing away from anybody. // Default: 7776000
 *         keep_a_client_never_used_for?: int|Param, // Seconds a client that was never used lives at all (decision 0009). Seven days by default, a working week, so that a registration made on a Friday afternoon is still there the next Friday; a client that was never used holds nothing, so the only question is how long whoever registered it may take to make its first request. The mode that registers strangers makes it the shorter of the two. // Default: 604800
 *         sector_identifier_timeout?: float|Param, // Seconds one read of a sector_identifier_uri is given, connection included (OIDC Registration section 5). It is read once, when a client registers or replaces itself, and the registration waits for it. // Default: 3.0
 *         sector_identifier_max_size?: int|Param, // Bytes a sector_identifier_uri may answer before the read stops; the document is the JSON array of the redirection URIs of the clients of one sector. // Default: 65536
 *         statement_issuers?: array<string, array{ // Default: []
 *             jwks?: mixed, // The JWK Set of the authority, inline (RFC 7517 section 5): public keys only, and the only keys a statement of this authority is ever verified against, whatever its header names (RFC 8725 section 3.10). // Default: null
 *             signing_algorithms?: list<scalar|Param|null>,
 *         }>,
 *         statement_max_lifetime?: int|Param, // Seconds ahead of the request the "exp" of a software statement may be (RFC 7591 section 2.3). A statement is signed for one registration, so it is not a credential for a year; RFC 7591 requires no "exp" at all, and this provider requires one as it does of every signed thing it takes back (decision 0006). // Default: 300
 *         statement_leeway?: int|Param, // Seconds allowed of the clock of the authority, both ways, when its statement is judged. // Default: 30
 *         default_scope?: scalar|Param|null, // What a client that registers itself and names no scope is registered with (RFC 7591 section 2: "If omitted, an authorization server MAY register a client with a default set of scopes"), space-delimited as a request writes one (RFC 6749 section 3.3). Left out, such a client is registered with "openid" alone, which is less than this tenant hands out and is a default nobody chose. It is held to what the tenant announces like every registered scope, so a scope written here that the tenant does not offer refuses every registration rather than granting one, and it is read at the boot that declares it. A client that names its own scopes keeps them. // Default: null
 *         exempt_confidential_clients_from_pkce?: bool|Param, // The named exception of decision 0017, for the tenant that writes it and no other: the confidential clients this policy registers are registered without the PKCE requirement, because the Dynamic OP profile of OIDC Core sends no code_challenge and offers no way to. A public client is never exempted whatever this says, "plain" never exists, and a code_challenge a client does send is verified like any other. Write it with the reason a tenant has for it beside it; a tenant with real users has none. // Default: false
 *     },
 *     saml?: array{ // SAML 2.0 (beffroi/saml, decision 0013): the roles the tenant of this deployment plays.
 *         identity_provider?: bool|array{ // The tenant as a SAML identity provider (spec/saml.md section 6.1). Disabled, nothing of it is wired: it serves no metadata, and the tenant draws no SAML key unless its service provider is enabled, the key of both roles (S-40, S-41). Enabled, its key is drawn with "beffroi:keys:generate --algorithm=SAML-SIGNING" and rotates as every key of the tenant, by the figures of its own family below.
 *             enabled?: bool|Param, // Default: false
 *             want_authn_requests_signed?: bool|Param, // What the metadata says in WantAuthnRequestsSigned (SAML Metadata section 2.4.3): true asks every service provider to sign its requests, which is what a broker configured from the metadata does (spec/model.md section 6.9). Turned off, the requests of service providers that cannot sign are accepted where their configuration says so, and the logout of a broker that signs only when asked is lost. // Default: true
 *             staging_delay?: int|Param, // How long a new SAML signing key is published in the metadata before it signs, in seconds (spec/saml.md S-12, section 7): seven days by default, seven times the cacheDuration of the metadata, so that a service provider whose refresh fails a few times still fetches the next certificate before it is used, and a calendar week for an administrator of a service provider that holds an uploaded certificate (Entra without the metadata URL it may be given, or one Microsoft cannot reach) to put the next one in place; AD FS, in the sample of its documentation, gives its partners five days. The keys of every other family keep "keys.staging_delay". // Default: 604800
 *             age?: int|Param, // How long a SAML signing key works before the planning stages a successor for it, in seconds, counted from its activation (spec/saml.md S-12, section 7): 365 days by default, every rotation being a step for whoever pinned its certificate, and inside the one to three years NIST SP 800-57 Part 1 Rev. 5 §5.3.6 gives a private signature key. The keys of every other family keep "keys.age". // Default: 31536000
 *             cache_duration?: int|Param, // How long a service provider may keep the metadata before it fetches it again, in seconds, written as its cacheDuration (SAML Metadata section 2.3.2, spec/saml.md S-12): one day by default, how often SimpleSAMLphp's metarefresh and a Shibboleth SP refresh it, and strictly shorter than "staging_delay", which the configuration refuses otherwise. // Default: 86400
 *         },
 *         service_provider?: bool|array{ // The tenant as a SAML service provider to the identity providers upstream of it (spec/saml.md section 6.9). Disabled, nothing of it is wired: its metadata answer that there are none. Enabled, it signs with the SAML signing key of the identity provider, drawn and rotated by the figures of "identity_provider" whichever role is enabled (S-40), and its metadata are served at /saml/sp/metadata.
 *             enabled?: bool|Param, // Default: false
 *             entity_id?: string|Param, // The entity ID of the service provider (spec/saml.md S-38): the URL of its metadata when left out, as the identity provider is named by the URL of its own; another URI for a service provider its upstream identity providers already know by a name it keeps, absolute, at most 1024 characters, with no whitespace, control, format or invisible character (M-6). Never the entity ID of the identity provider of the tenant. Refused when the container is compiled, or at its first use when it or the issuer holds an environment variable. // Default: null
 *         },
 *         service_providers?: array<string, array{ // Default: []
 *             metadata?: scalar|Param|null, // Where the metadata are read from: an https URL, fetched without following a redirect, or the absolute path of a file of the deployment. Nothing else, a plain http URL included. The channel is what vouches for them unless metadata_signers pins who signs them.
 *             metadata_signers?: list<scalar|Param|null>,
 *             attributes?: array<string, array{ // Default: []
 *                 claim?: scalar|Param|null, // The name of the claim, as the provider names it (OIDC Core section 5.1).
 *                 name_format?: "uri"|"basic"|"unspecified"|Param, // The name format of the attribute (Core section 8.2): "uri", the default the SAML V2.0 interoperability profiles ask for, under which the name is an absolute URI; "basic"; or "unspecified". // Default: "uri"
 *                 friendly_name?: scalar|Param|null, // A name a person reads (Core section 2.7.3.1), which nothing compares. // Default: null
 *             }>,
 *             encrypt_assertions?: bool|Param, // The assertions of this service provider are encrypted to a key of its metadata, which must then hold one for encryption, or the metadata are refused (spec/saml.md S-7). // Default: false
 *             signs_authn_requests?: bool|Param, // This service provider signs its authentication requests. Turned off for one that cannot, Entra among them, whose unsigned requests are then the only ones accepted (issue #730); a provider that signs is refused while its metadata hold no key for signing (S-11); there is no switch for the tenant or for the deployment. // Default: true
 *         }>,
 *         identity_providers?: array<string, array{ // Default: []
 *             metadata?: scalar|Param|null, // Where the metadata are read from: an https URL, fetched without following a redirect, or the absolute path of a file of the deployment. Nothing else, a plain http URL included. The channel is what vouches for them unless metadata_signers pins who signs them.
 *             metadata_signers?: list<scalar|Param|null>,
 *             domains?: list<scalar|Param|null>,
 *             email_attribute?: scalar|Param|null, // The name of the attribute of an assertion that carries the e-mail address of a person (spec/saml.md S-45), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" for Entra.
 *             profile?: array<string, scalar|Param|null>,
 *             subject_attribute?: scalar|Param|null, // The name of the attribute that names a person when the NameID of an assertion is not persistent (spec/saml.md S-45): a value the identity provider keeps for that person and never one the person changes, "http://schemas.microsoft.com/identity/claims/objectidentifier" for Entra rather than an address. Left out, a person is named by a persistent NameID only. // Default: null
 *             require_encrypted_assertions?: bool|Param, // An assertion of this identity provider arrives encrypted for the key it is given, or it is refused, whatever signs it (spec/saml.md S-67). The certificate it encrypts for is in the metadata of the service provider given to it alone, at /saml/sp/metadata/ followed by its entity ID in base64url, once its key is drawn with "beffroi:keys:generate --algorithm=SAML-ENCRYPTION:" and its entity ID (S-64, S-65). // Default: false
 *             address_parameter?: scalar|Param|null, // The query parameter of the single sign-on service of this identity provider that takes the address a person gave the login page, which it prefills its sign-in with: "login_hint" for Entra. One to 64 unreserved characters of RFC 3986, none of the parameters of the binding (SAMLRequest, SAMLResponse, SAMLEncoding, RelayState, SigAlg, Signature) in any case (spec/saml.md S-68). Left out, no address is sent. The address is a hint and nothing more: the person is who the signed assertion names. // Default: null
 *             groups?: array{ // The attribute of an assertion that carries the groups of a person, and the group of the tenant each of its values stands for (spec/saml.md S-45). A value the map does not name is no group, and no group is created from what an identity provider sends.
 *                 attribute?: scalar|Param|null, // The name of the attribute that carries the groups.
 *                 map?: array<string, scalar|Param|null>,
 *             },
 *         }>,
 *     },
 * }
 * @psalm-type SymfonycastsTailwindConfig = array{
 *     input_css?: list<scalar|Param|null>,
 *     config_file?: scalar|Param|null, // Path to the tailwind.config.js file // Default: "%kernel.project_dir%/tailwind.config.js"
 *     binary?: scalar|Param|null, // The tailwind binary to use instead of downloading a new one // Default: null
 *     binary_version?: scalar|Param|null, // Tailwind CLI version to download - required unless "binary" is set (run "tailwind:init" to configure) // Default: null
 *     binary_platform?: "auto"|"linux-arm64"|"linux-arm64-musl"|"linux-x64"|"linux-x64-musl"|"macos-arm64"|"macos-x64"|"windows-x64"|Param, // Tailwind CLI platform to download - "auto" will try to detect the platform automatically // Default: "auto"
 *     postcss_config_file?: scalar|Param|null, // Path to PostCSS config file which is passed to the Tailwind CLI // Default: null
 *     strict_mode?: bool|Param|null, // When enabled, an exception will be thrown if there are no built assets (default: false in `test` env, true otherwise) // Default: null
 *     process_timeout?: int|Param, // Timeout in seconds for the Tailwind build process - use "0" to disable // Default: 60
 * }
 * @psalm-type DebugConfig = array{
 *     max_items?: int|Param, // Max number of displayed items past the first level, -1 means no limit. // Default: 2500
 *     min_depth?: int|Param, // Minimum tree depth to clone all the items, 1 is default. // Default: 1
 *     max_string_length?: int|Param, // Max length of displayed strings, -1 means no limit. // Default: -1
 *     dump_destination?: scalar|Param|null, // A stream URL where dumps should be written to. // Default: null
 *     theme?: "dark"|"light"|Param, // Changes the color of the dump() output when rendered directly on the templating. "dark" (default) or "light". // Default: "dark"
 * }
 * @psalm-type WebProfilerConfig = array{
 *     toolbar?: bool|array{ // Profiler toolbar configuration
 *         enabled?: bool|Param, // Default: false
 *         ajax_replace?: bool|Param, // Replace toolbar on AJAX requests // Default: false
 *     },
 *     intercept_redirects?: bool|Param, // Default: false
 *     excluded_ajax_paths?: scalar|Param|null, // Default: "^/((index|app(_[\\w]+)?)\\.php/)?_wdt"
 * }
 * @psalm-type NelmioCorsConfig = array{
 *     defaults?: array{
 *         allow_credentials?: bool|Param, // Default: false
 *         allow_origin?: list<scalar|Param|null>,
 *         allow_headers?: list<scalar|Param|null>,
 *         allow_methods?: list<scalar|Param|null>,
 *         allow_private_network?: bool|Param, // Default: false
 *         expose_headers?: list<scalar|Param|null>,
 *         max_age?: scalar|Param|null, // Default: 0
 *         hosts?: list<scalar|Param|null>,
 *         origin_regex?: bool|Param, // Default: false
 *         forced_allow_origin_value?: scalar|Param|null, // Default: null
 *         skip_same_as_origin?: bool|Param, // Default: true
 *     },
 *     paths?: array<string, array{ // Default: []
 *         allow_credentials?: bool|Param,
 *         allow_origin?: list<scalar|Param|null>,
 *         allow_headers?: list<scalar|Param|null>,
 *         allow_methods?: list<scalar|Param|null>,
 *         allow_private_network?: bool|Param,
 *         expose_headers?: list<scalar|Param|null>,
 *         max_age?: scalar|Param|null, // Default: 0
 *         hosts?: list<scalar|Param|null>,
 *         origin_regex?: bool|Param,
 *         forced_allow_origin_value?: scalar|Param|null, // Default: null
 *         skip_same_as_origin?: bool|Param,
 *     }>,
 * }
 * @psalm-type NelmioSecurityConfig = array{
 *     signed_cookie?: array{
 *         names?: list<scalar|Param|null>,
 *         secret?: scalar|Param|null, // Default: "%kernel.secret%"
 *         hash_algo?: scalar|Param|null,
 *         legacy_hash_algo?: scalar|Param|null, // Fallback algorithm to allow for frictionless hash algorithm upgrades. Use with caution and as a temporary measure as it allows for downgrade attacks. // Default: null
 *         separator?: scalar|Param|null, // Default: "."
 *     },
 *     clickjacking?: array{
 *         hosts?: list<scalar|Param|null>,
 *         paths?: array<string, array{ // Default: {"^/.*":{"header":"DENY"}}
 *             header?: scalar|Param|null, // Default: "DENY"
 *             ...<string, mixed>
 *         }>,
 *         content_types?: list<scalar|Param|null>,
 *     },
 *     external_redirects?: array{
 *         abort?: bool|Param, // Default: false
 *         override?: scalar|Param|null, // Default: null
 *         forward_as?: scalar|Param|null, // Default: null
 *         log?: bool|Param, // Default: false
 *         allow_list?: list<scalar|Param|null>,
 *     },
 *     flexible_ssl?: bool|array{
 *         enabled?: bool|Param, // Default: false
 *         cookie_name?: scalar|Param|null, // Default: "auth"
 *         unsecured_logout?: bool|Param, // Default: false
 *     },
 *     forced_ssl?: bool|array{
 *         enabled?: bool|Param, // Default: false
 *         hsts_max_age?: scalar|Param|null, // Default: null
 *         hsts_subdomains?: bool|Param, // Default: false
 *         hsts_preload?: bool|Param, // Default: false
 *         allow_list?: list<scalar|Param|null>,
 *         hosts?: list<scalar|Param|null>,
 *         redirect_status_code?: scalar|Param|null, // Default: 302
 *     },
 *     content_type?: array{
 *         nosniff?: bool|Param, // Default: false
 *     },
 *     xss_protection?: array{ // Deprecated: The "xss_protection" option is deprecated, use Content Security Policy without allowing "unsafe-inline" scripts instead.
 *         enabled?: bool|Param, // Default: false
 *         mode_block?: bool|Param, // Default: false
 *         report_uri?: scalar|Param|null, // Default: null
 *     },
 *     csp?: bool|array{
 *         enabled?: bool|Param, // Default: true
 *         request_matcher?: scalar|Param|null, // Default: null
 *         hosts?: list<scalar|Param|null>,
 *         content_types?: list<scalar|Param|null>,
 *         report_endpoint?: array{
 *             log_channel?: scalar|Param|null, // Default: null
 *             log_formatter?: scalar|Param|null, // Default: "nelmio_security.csp_report.log_formatter"
 *             log_level?: "alert"|"critical"|"debug"|"emergency"|"error"|"info"|"notice"|"warning"|Param, // Default: "notice"
 *             filters?: array{
 *                 domains?: bool|Param, // Default: true
 *                 schemes?: bool|Param, // Default: true
 *                 browser_bugs?: bool|Param, // Default: true
 *                 injected_scripts?: bool|Param, // Default: true
 *             },
 *             dismiss?: list<list<"default-src"|"base-uri"|"block-all-mixed-content"|"child-src"|"connect-src"|"font-src"|"form-action"|"frame-ancestors"|"frame-src"|"img-src"|"manifest-src"|"media-src"|"object-src"|"plugin-types"|"script-src"|"style-src"|"upgrade-insecure-requests"|"report-uri"|"worker-src"|"prefetch-src"|"report-to"|"*"|Param>>,
 *         },
 *         compat_headers?: bool|Param, // Default: true
 *         report_logger_service?: scalar|Param|null, // Default: "logger"
 *         hash?: array{
 *             algorithm?: "sha256"|"sha384"|"sha512"|Param, // The algorithm to use for hashes // Default: "sha256"
 *         },
 *         report?: array{
 *             level1_fallback?: bool|Param, // Provides CSP Level 1 fallback when using hash or nonce (CSP level 2) by adding 'unsafe-inline' source. See https://www.w3.org/TR/CSP2/#directive-script-src and https://www.w3.org/TR/CSP2/#directive-style-src // Default: true
 *             browser_adaptive?: bool|array{ // Do not send directives that browser do not support
 *                 enabled?: bool|Param, // Default: false
 *                 parser?: scalar|Param|null, // Default: "nelmio_security.ua_parser.ua_php"
 *             },
 *             default-src?: list<scalar|Param|null>,
 *             base-uri?: list<scalar|Param|null>,
 *             block-all-mixed-content?: bool|Param, // Default: false
 *             child-src?: list<scalar|Param|null>,
 *             connect-src?: list<scalar|Param|null>,
 *             font-src?: list<scalar|Param|null>,
 *             form-action?: list<scalar|Param|null>,
 *             frame-ancestors?: list<scalar|Param|null>,
 *             frame-src?: list<scalar|Param|null>,
 *             img-src?: list<scalar|Param|null>,
 *             manifest-src?: list<scalar|Param|null>,
 *             media-src?: list<scalar|Param|null>,
 *             object-src?: list<scalar|Param|null>,
 *             plugin-types?: list<scalar|Param|null>,
 *             script-src?: list<scalar|Param|null>,
 *             style-src?: list<scalar|Param|null>,
 *             upgrade-insecure-requests?: bool|Param, // Default: false
 *             report-uri?: Param|string|list<scalar|Param|null>,
 *             worker-src?: list<scalar|Param|null>,
 *             prefetch-src?: list<scalar|Param|null>,
 *             report-to?: scalar|Param|null,
 *         },
 *         enforce?: array{
 *             level1_fallback?: bool|Param, // Provides CSP Level 1 fallback when using hash or nonce (CSP level 2) by adding 'unsafe-inline' source. See https://www.w3.org/TR/CSP2/#directive-script-src and https://www.w3.org/TR/CSP2/#directive-style-src // Default: true
 *             browser_adaptive?: bool|array{ // Do not send directives that browser do not support
 *                 enabled?: bool|Param, // Default: false
 *                 parser?: scalar|Param|null, // Default: "nelmio_security.ua_parser.ua_php"
 *             },
 *             default-src?: list<scalar|Param|null>,
 *             base-uri?: list<scalar|Param|null>,
 *             block-all-mixed-content?: bool|Param, // Default: false
 *             child-src?: list<scalar|Param|null>,
 *             connect-src?: list<scalar|Param|null>,
 *             font-src?: list<scalar|Param|null>,
 *             form-action?: list<scalar|Param|null>,
 *             frame-ancestors?: list<scalar|Param|null>,
 *             frame-src?: list<scalar|Param|null>,
 *             img-src?: list<scalar|Param|null>,
 *             manifest-src?: list<scalar|Param|null>,
 *             media-src?: list<scalar|Param|null>,
 *             object-src?: list<scalar|Param|null>,
 *             plugin-types?: list<scalar|Param|null>,
 *             script-src?: list<scalar|Param|null>,
 *             style-src?: list<scalar|Param|null>,
 *             upgrade-insecure-requests?: bool|Param, // Default: false
 *             report-uri?: Param|string|list<scalar|Param|null>,
 *             worker-src?: list<scalar|Param|null>,
 *             prefetch-src?: list<scalar|Param|null>,
 *             report-to?: scalar|Param|null,
 *         },
 *     },
 *     referrer_policy?: bool|array{
 *         enabled?: bool|Param, // Default: false
 *         policies?: Param|string|list<scalar|Param|null>,
 *     },
 *     permissions_policy?: bool|array{
 *         enabled?: bool|Param, // Default: false
 *         policies?: array{
 *             accelerometer?: mixed, // Default: null
 *             ambient_light_sensor?: mixed, // Default: null
 *             attribution_reporting?: mixed, // Default: null
 *             autoplay?: mixed, // Default: null
 *             bluetooth?: mixed, // Default: null
 *             browsing_topics?: mixed, // Default: null
 *             camera?: mixed, // Default: null
 *             captured_surface_control?: mixed, // Default: null
 *             compute_pressure?: mixed, // Default: null
 *             cross_origin_isolated?: mixed, // Default: null
 *             deferred_fetch?: mixed, // Default: null
 *             deferred_fetch_minimal?: mixed, // Default: null
 *             display_capture?: mixed, // Default: null
 *             encrypted_media?: mixed, // Default: null
 *             fullscreen?: mixed, // Default: null
 *             gamepad?: mixed, // Default: null
 *             geolocation?: mixed, // Default: null
 *             gyroscope?: mixed, // Default: null
 *             hid?: mixed, // Default: null
 *             identity_credentials_get?: mixed, // Default: null
 *             idle_detection?: mixed, // Default: null
 *             interest_cohort?: mixed, // Default: null
 *             language_detector?: mixed, // Default: null
 *             local_fonts?: mixed, // Default: null
 *             magnetometer?: mixed, // Default: null
 *             microphone?: mixed, // Default: null
 *             midi?: mixed, // Default: null
 *             otp_credentials?: mixed, // Default: null
 *             payment?: mixed, // Default: null
 *             picture_in_picture?: mixed, // Default: null
 *             publickey_credentials_create?: mixed, // Default: null
 *             publickey_credentials_get?: mixed, // Default: null
 *             screen_wake_lock?: mixed, // Default: null
 *             serial?: mixed, // Default: null
 *             speaker_selection?: mixed, // Default: null
 *             storage_access?: mixed, // Default: null
 *             summarizer?: mixed, // Default: null
 *             translator?: mixed, // Default: null
 *             usb?: mixed, // Default: null
 *             web_share?: mixed, // Default: null
 *             window_management?: mixed, // Default: null
 *             xr_spatial_tracking?: mixed, // Default: null
 *         },
 *     },
 *     cross_origin_isolation?: bool|array{
 *         enabled?: bool|Param, // Default: false
 *         paths?: array<string, array{ // Default: []
 *             coep?: "unsafe-none"|"require-corp"|"credentialless"|Param, // Cross-Origin-Embedder-Policy (COEP) header value
 *             coop?: "unsafe-none"|"same-origin-allow-popups"|"same-origin"|"noopener-allow-popups"|Param, // Cross-Origin-Opener-Policy (COOP) header value
 *             corp?: "same-site"|"same-origin"|"cross-origin"|Param, // Cross-Origin-Resource-Policy (CORP) header value
 *             report_only?: bool|Param, // Use Report-Only headers instead of enforcing (applies to COEP and COOP only) // Default: false
 *             report_to?: scalar|Param|null, // Reporting endpoint name for violations (requires Reporting API configuration, applies to COEP and COOP only) // Default: null
 *         }>,
 *     },
 * }
 * @psalm-type ConfigType = array{
 *     imports?: ImportsConfig,
 *     parameters?: ParametersConfig,
 *     services?: ServicesConfig,
 *     router?: RouterConfig,
 *     cache?: CacheConfig,
 *     asset?: AssetConfig,
 *     serializer?: SerializerConfig,
 *     validation?: ValidationConfig,
 *     translation?: TranslationConfig,
 *     messenger?: MessengerConfig,
 *     type_info?: TypeInfoConfig,
 *     property_access?: PropertyAccessConfig,
 *     property_info?: PropertyInfoConfig,
 *     uid?: UidConfig,
 *     scheduler?: SchedulerConfig,
 *     asset_mapper?: AssetMapperConfig,
 *     rate_limiter?: RateLimiterConfig,
 *     http_client?: HttpClientConfig,
 *     key_management?: KeyManagementConfig,
 *     framework?: FrameworkConfig,
 *     doctrine?: DoctrineConfig,
 *     doctrine_migrations?: DoctrineMigrationsConfig,
 *     monolog?: MonologConfig,
 *     security?: SecurityConfig,
 *     twig?: TwigConfig,
 *     beffroi?: BeffroiConfig,
 *     symfonycasts_tailwind?: SymfonycastsTailwindConfig,
 *     nelmio_cors?: NelmioCorsConfig,
 *     nelmio_security?: NelmioSecurityConfig,
 *     "when@dev"?: array{
 *         imports?: ImportsConfig,
 *         parameters?: ParametersConfig,
 *         services?: ServicesConfig,
 *         router?: RouterConfig,
 *         cache?: CacheConfig,
 *         asset?: AssetConfig,
 *         serializer?: SerializerConfig,
 *         validation?: ValidationConfig,
 *         translation?: TranslationConfig,
 *         messenger?: MessengerConfig,
 *         type_info?: TypeInfoConfig,
 *         property_access?: PropertyAccessConfig,
 *         property_info?: PropertyInfoConfig,
 *         uid?: UidConfig,
 *         scheduler?: SchedulerConfig,
 *         asset_mapper?: AssetMapperConfig,
 *         rate_limiter?: RateLimiterConfig,
 *         http_client?: HttpClientConfig,
 *         key_management?: KeyManagementConfig,
 *         framework?: FrameworkConfig,
 *         doctrine?: DoctrineConfig,
 *         doctrine_migrations?: DoctrineMigrationsConfig,
 *         monolog?: MonologConfig,
 *         security?: SecurityConfig,
 *         twig?: TwigConfig,
 *         beffroi?: BeffroiConfig,
 *         symfonycasts_tailwind?: SymfonycastsTailwindConfig,
 *         debug?: DebugConfig,
 *         web_profiler?: WebProfilerConfig,
 *         nelmio_cors?: NelmioCorsConfig,
 *         nelmio_security?: NelmioSecurityConfig,
 *     },
 *     "when@prod"?: array{
 *         imports?: ImportsConfig,
 *         parameters?: ParametersConfig,
 *         services?: ServicesConfig,
 *         router?: RouterConfig,
 *         cache?: CacheConfig,
 *         asset?: AssetConfig,
 *         serializer?: SerializerConfig,
 *         validation?: ValidationConfig,
 *         translation?: TranslationConfig,
 *         messenger?: MessengerConfig,
 *         type_info?: TypeInfoConfig,
 *         property_access?: PropertyAccessConfig,
 *         property_info?: PropertyInfoConfig,
 *         uid?: UidConfig,
 *         scheduler?: SchedulerConfig,
 *         asset_mapper?: AssetMapperConfig,
 *         rate_limiter?: RateLimiterConfig,
 *         http_client?: HttpClientConfig,
 *         key_management?: KeyManagementConfig,
 *         framework?: FrameworkConfig,
 *         doctrine?: DoctrineConfig,
 *         doctrine_migrations?: DoctrineMigrationsConfig,
 *         monolog?: MonologConfig,
 *         security?: SecurityConfig,
 *         twig?: TwigConfig,
 *         beffroi?: BeffroiConfig,
 *         symfonycasts_tailwind?: SymfonycastsTailwindConfig,
 *         nelmio_cors?: NelmioCorsConfig,
 *         nelmio_security?: NelmioSecurityConfig,
 *     },
 *     "when@test"?: array{
 *         imports?: ImportsConfig,
 *         parameters?: ParametersConfig,
 *         services?: ServicesConfig,
 *         router?: RouterConfig,
 *         cache?: CacheConfig,
 *         asset?: AssetConfig,
 *         serializer?: SerializerConfig,
 *         validation?: ValidationConfig,
 *         translation?: TranslationConfig,
 *         messenger?: MessengerConfig,
 *         type_info?: TypeInfoConfig,
 *         property_access?: PropertyAccessConfig,
 *         property_info?: PropertyInfoConfig,
 *         uid?: UidConfig,
 *         scheduler?: SchedulerConfig,
 *         asset_mapper?: AssetMapperConfig,
 *         rate_limiter?: RateLimiterConfig,
 *         http_client?: HttpClientConfig,
 *         key_management?: KeyManagementConfig,
 *         framework?: FrameworkConfig,
 *         doctrine?: DoctrineConfig,
 *         doctrine_migrations?: DoctrineMigrationsConfig,
 *         monolog?: MonologConfig,
 *         security?: SecurityConfig,
 *         twig?: TwigConfig,
 *         beffroi?: BeffroiConfig,
 *         symfonycasts_tailwind?: SymfonycastsTailwindConfig,
 *         web_profiler?: WebProfilerConfig,
 *         nelmio_cors?: NelmioCorsConfig,
 *         nelmio_security?: NelmioSecurityConfig,
 *     },
 *     ...<string, ExtensionType|array{ // extra keys must follow the when@%env% pattern or match an extension alias
 *         imports?: ImportsConfig,
 *         parameters?: ParametersConfig,
 *         services?: ServicesConfig,
 *         ...<string, ExtensionType>,
 *     }>
 * }
 */
final class App
{
    /**
     * @param ConfigType $config
     *
     * @psalm-return ConfigType
     */
    public static function config(array $config): array
    {
        /** @var ConfigType $config */
        $config = AppReference::config($config);

        return $config;
    }
}

namespace Symfony\Component\Routing\Loader\Configurator;

/**
 * This class provides array-shapes for configuring the routes of an application.
 *
 * Example:
 *
 *     ```php
 *     // config/routes.php
 *     namespace Symfony\Component\Routing\Loader\Configurator;
 *
 *     return Routes::config([
 *         'controllers' => [
 *             'resource' => 'routing.controllers',
 *         ],
 *     ]);
 *     ```
 *
 * @psalm-type RouteConfig = array{
 *     path: string|array<string,string>,
 *     controller?: string,
 *     methods?: string|list<string>,
 *     requirements?: array<string,string>,
 *     defaults?: array<string,mixed>,
 *     options?: array<string,mixed>,
 *     host?: string|array<string,string>,
 *     schemes?: string|list<string>,
 *     condition?: string,
 *     add_condition?: string,
 *     locale?: string,
 *     format?: string,
 *     utf8?: bool,
 *     stateless?: bool,
 *     firewall?: string,
 * }
 * @psalm-type ImportConfig = array{
 *     resource: string,
 *     type?: string,
 *     exclude?: string|list<string>,
 *     prefix?: string|array<string,string>,
 *     name_prefix?: string,
 *     trailing_slash_on_root?: bool,
 *     controller?: string,
 *     methods?: string|list<string>,
 *     requirements?: array<string,string>,
 *     defaults?: array<string,mixed>,
 *     options?: array<string,mixed>,
 *     host?: string|array<string,string>,
 *     schemes?: string|list<string>,
 *     condition?: string,
 *     add_condition?: string,
 *     locale?: string,
 *     format?: string,
 *     utf8?: bool,
 *     stateless?: bool,
 *     firewall?: string,
 * }
 * @psalm-type AliasConfig = array{
 *     alias: string,
 *     deprecated?: array{package:string, version:string, message?:string},
 * }
 * @psalm-type RoutesConfig = array{
 *     "when@dev"?: array<string, RouteConfig|ImportConfig|AliasConfig>,
 *     "when@prod"?: array<string, RouteConfig|ImportConfig|AliasConfig>,
 *     "when@test"?: array<string, RouteConfig|ImportConfig|AliasConfig>,
 *     ...<string, RouteConfig|ImportConfig|AliasConfig>
 * }
 */
final class Routes
{
    /**
     * @param RoutesConfig $config
     *
     * @psalm-return RoutesConfig
     */
    public static function config(array $config): array
    {
        return $config;
    }
}
