<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Process\Process;

const DEV_ENV_LOCAL = 'apps/beffroi/.env.local';

const DEV_USERNAME = 'alice';

/**
 * The same value as BEFFROI_TENANT_SLUG in compose.yaml.
 */
const DEV_TENANT_SLUG = 'default';

/**
 * Every claim of OIDC Core §5.1: the scope modules of the conformance plan warn on a user without them.
 */
const DEV_USER_PROFILE = [
    '--name',
    'Alice Liddell',
    '--given-name',
    'Alice',
    '--family-name',
    'Liddell',
    '--middle-name',
    'Pleasance',
    '--nickname',
    'Ali',
    '--preferred-username',
    'alice',
    '--profile-url',
    'https://op.localhost/alice',
    '--picture',
    'https://op.localhost/alice.png',
    // Not under the provider's URL, which prefixes the logo of the tenant: a search of a dump for this value
    // must match no readable column.
    '--website',
    'https://liddell.example/',
    '--gender',
    'female',
    '--birthdate',
    '1852-05-04',
    '--zoneinfo',
    'Europe/London',
    '--locale',
    'en-GB',
    '--phone-number',
    '+44 1865 000000',
    '--phone-number-verified',
    '--address',
    "1 Wonderland Road\nOxford OX1 1AA\nUnited Kingdom",
    '--street-address',
    '1 Wonderland Road',
    '--locality',
    'Oxford',
    '--region',
    'Oxfordshire',
    '--postal-code',
    'OX1 1AA',
    '--country',
    'United Kingdom',
];

const DEV_MTLS_DIRECTORY = 'var/mtls';

const DEV_MTLS_CLIENT_NAME = 'beffroi-dev-mtls-client';

/**
 * The same value as MTLS_SERVER_NAME in compose.yaml.
 */
const DEV_MTLS_SERVER_NAME = 'mtls.op.localhost';

const DEV_MTLS_CLIENT_DAYS = 90;

const DEV_CONFORMANCE_DIRECTORY = 'var/conformance';

/**
 * Two per run: some modules present what was issued to another client. A FAPI-CIBA client authenticates with
 * "private_key_jwt" and carries a certificate only to bind its tokens, which the profile and the suite require.
 * No two runs share a client: a required request object and a token delivery mode are registrations.
 */
const DEV_FAPI_CLIENTS = [
    'conformance-fapi-private-key-jwt' => [
        'env' => 'CONFORMANCE_FAPI_PRIVATE_KEY_JWT_JWKS',
        'certificate' => false,
    ],
    'conformance-fapi-private-key-jwt-second' => [
        'env' => 'CONFORMANCE_FAPI_PRIVATE_KEY_JWT_SECOND_JWKS',
        'certificate' => false,
    ],
    'conformance-fapi-mtls' => [
        'env' => 'CONFORMANCE_FAPI_MTLS_JWKS',
        'certificate' => true,
    ],
    'conformance-fapi-mtls-second' => [
        'env' => 'CONFORMANCE_FAPI_MTLS_SECOND_JWKS',
        'certificate' => true,
    ],
    'conformance-fapi-signing-private-key-jwt' => [
        'env' => 'CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_JWKS',
        'certificate' => false,
    ],
    'conformance-fapi-signing-private-key-jwt-second' => [
        'env' => 'CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_SECOND_JWKS',
        'certificate' => false,
    ],
    'conformance-fapi-signing-mtls' => [
        'env' => 'CONFORMANCE_FAPI_SIGNING_MTLS_JWKS',
        'certificate' => true,
    ],
    'conformance-fapi-signing-mtls-second' => [
        'env' => 'CONFORMANCE_FAPI_SIGNING_MTLS_SECOND_JWKS',
        'certificate' => true,
    ],
    'conformance-ciba-poll' => [
        'env' => 'CONFORMANCE_CIBA_POLL_JWKS',
        'certificate' => true,
    ],
    'conformance-ciba-poll-second' => [
        'env' => 'CONFORMANCE_CIBA_POLL_SECOND_JWKS',
        'certificate' => true,
    ],
    'conformance-ciba-ping' => [
        'env' => 'CONFORMANCE_CIBA_PING_JWKS',
        'certificate' => true,
    ],
    'conformance-ciba-ping-second' => [
        'env' => 'CONFORMANCE_CIBA_PING_SECOND_JWKS',
        'certificate' => true,
    ],
];

const DEV_MESSAGE_KEY_ALGORITHM = 'MESSAGE-SEAL';

/**
 * ES256 for the clients of the FAPI 2 plans, whose profile refuses RS256.
 */
const DEV_KEY_ALGORITHMS = ['ES256', 'ECDH-ES+A256KW', 'VAPID', 'SAML-SIGNING'];

const DEV_DEMO_DIRECTORY = 'var/demo';

/**
 * RFC 7523 §3
 */
const DEV_DEMO_ISSUER = [
    'issuer' => 'https://issuer.demo.localhost',
    'env' => 'DEMO_ISSUER_JWKS',
    'file' => 'demo-issuer',
    'identity_provider' => 'demo-issuer',
    'subject' => 'alice@issuer.demo.localhost',
];

/**
 * RFC 7591 §2.3
 */
const DEV_DEMO_ATTESTATION_AUTHORITY = [
    'issuer' => 'https://attestation.demo.localhost',
    'env' => 'DEMO_ATTESTATION_JWKS',
    'file' => 'demo-attestation',
];

const DEV_CLIENT_SECRETS = [
    'CONFORMANCE_BASIC_SECRET',
    'CONFORMANCE_BASIC_SECOND_SECRET',
    'CONFORMANCE_POST_SECRET',
    'CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET',
    'CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET',
    'OIDC_DEMO_SECRET',
    'OIDC_DEMO_OPAQUE_SECRET',
    'OIDC_DEMO_SECOND_SECRET',
    'DEMO_SERVICE_SECRET',
    'DEMO_GATEWAY_SECRET',
    'DEMO_CIBA_POLL_SECRET',
    'DEMO_CIBA_PING_SECRET',
    'DEMO_ASSERTION_SECRET',
    'DEMO_RAR_SECRET',
];

/**
 * Written by docker/vault/init.sh from docker/vault/beffroi-op.hcl.
 */
const VAULT_OP_POLICY = 'beffroi-op';

#[AsTask(
    description: 'Provision the development OP after "castor start": the KMS that seals the signing keys and the secrets of the clients (apps/beffroi/.env.local), then the tenant, a signing key (checked against the KMS when there is one already) and the user "alice" with a full profile and a password',
)]
function provision(
    #[AsOption(
        description: 'The KMS to seal the keys of the tenant with when apps/beffroi/.env.local names none yet: sodium (default, a key generated in place), file (the same key in a file of the op container, mode 0600), vault (a token minted under the policy of the OP on the Vault of "castor start --kms vault") or aws (the Floci of "castor start --kms aws"); the backend already there is kept, switching is a change of KMS',
    )]
    ?string $kms = null,
): void {
    io()->title('Provisioning the development OP');

    io()->section('Development secrets');
    $env = provision_env_local($kms);

    io()->section('Schema');
    op_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);

    io()->section('Tenant');
    op_console(['beffroi:tenant:synchronize']);
    // As the entrypoint of the image does: a database written before keeps its tags until then, and nobody is created.
    $reindexed = op_console(['beffroi:user:reindex', '--when-due'], context()->withAllowFailure());
    if (! in_array($reindexed->getExitCode(), [0, 3], true)) {
        exit($reindexed->getExitCode() ?? 1);
    }

    io()->section('Keys');
    // What the tenant holds is read before anything is drawn, and the key messages are sealed to is drawn first:
    // every other key announces its staging on a transport.
    $keys = provision_published_keys();
    $fresh = str_contains($keys, 'no published key');
    provision_key(DEV_MESSAGE_KEY_ALGORITHM);
    if ($fresh) {
        op_console(['beffroi:keys:generate']);
    } else {
        // Vault in dev mode and Floci in memory forget their master key when they restart, and what it sealed is lost.
        $check = op_console(['beffroi:keys:list', '--check'], context()->withAllowFailure());
        if (! $check->isSuccessful()) {
            io()->error(sprintf(
                'The KMS of %s cannot open a published key (above). Run the rotations the check just named, one per algorithm, once the KMS is back with its key or with a new one, then this task again.',
                DEV_ENV_LOCAL,
            ));
            exit(1);
        }
        io()->note('A signing key is published already and opens with the KMS; "castor console beffroi:keys:rotate" rotates it without an outage.');
    }
    foreach (DEV_KEY_ALGORITHMS as $algorithm) {
        provision_key($algorithm);
    }

    io()->section(sprintf('User "%s"', DEV_USERNAME));
    $creation = op_console(
        ['beffroi:user:create', DEV_USERNAME, '--email', DEV_USERNAME . '@op.localhost', '--email-verified'],
        context()->withAllowFailure()->withQuiet(),
    );
    if ($creation->isSuccessful()) {
        io()->write($creation->getOutput());
    } elseif (str_contains($creation->getOutput(), 'already exists')) {
        io()->note(sprintf('The user "%s" exists already; the password below is set again.', DEV_USERNAME));
    } else {
        io()->write($creation->getOutput());
        exit($creation->getExitCode() ?? 1);
    }
    op_console(['beffroi:user:profile', DEV_USERNAME, ...DEV_USER_PROFILE]);
    op_console(
        ['beffroi:user:set-password', DEV_USERNAME, '--password-stdin'],
        context()->withInput($env['BEFFROI_DEV_USER_PASSWORD'] . "\n"),
    );
    $env['BEFFROI_DEV_USER_SUBJECT'] = provision_dev_subject(getcwd() . '/' . DEV_ENV_LOCAL);
    op_console(['beffroi:user:link', DEV_USERNAME, DEV_DEMO_ISSUER['identity_provider'], DEV_DEMO_ISSUER['subject']]);

    io()->section('Data keys');
    op_console(['beffroi:data-keys:list']);

    io()->section('Client certificate');
    provision_mtls_client();

    compose_restart_after_migration();

    // Last: the worker reads everything written above.
    io()->section('Worker');
    provision_start_worker();

    io()->success('The OP is provisioned.');
    io()->definitionList(
        [
            'Discovery' => $env['BEFFROI_ISSUER'] . '/.well-known/openid-configuration',
        ],
        [
            'JWKS' => $env['BEFFROI_ISSUER'] . '/jwks',
        ],
        [
            'KMS' => sprintf('%s, key %s', kms_backend_of($env['BEFFROI_KMS_DSN']) ?? 'unknown', $env['BEFFROI_KMS_KEY_ID']),
        ],
        [
            'Username' => DEV_USERNAME,
        ],
        [
            'Password' => $env['BEFFROI_DEV_USER_PASSWORD'],
        ],
        [
            'Subject' => $env['BEFFROI_DEV_USER_SUBJECT'],
        ],
        ...array_map(static fn (string $name): array => [
            $name => $env[$name],
        ], DEV_CLIENT_SECRETS),
    );
    io()->note(sprintf(
        'These values live in %s; oidc-demo takes OIDC_DEMO_SECRET, "castor conformance" the others. The keys of the %d clients of the FAPI 2 and FAPI-CIBA plans are in %s, whole, and their public half in the same file; the keys of the trusted issuer %s and of the attestation authority %s are in %s, the same way.',
        DEV_ENV_LOCAL,
        count(DEV_FAPI_CLIENTS),
        DEV_CONFORMANCE_DIRECTORY,
        DEV_DEMO_ISSUER['issuer'],
        DEV_DEMO_ATTESTATION_AUTHORITY['issuer'],
        DEV_DEMO_DIRECTORY,
    ));
}

function provision_key(string $algorithm): void
{
    if (preg_match(sprintf('/Algorithm %s /', preg_quote($algorithm, '/')), provision_published_keys()) === 1) {
        io()->note(sprintf(
            'A %1$s key is there already; "castor console beffroi:keys:rotate --algorithm=%1$s" rotates it without an outage.',
            $algorithm,
        ));

        return;
    }
    op_console(['beffroi:keys:generate', '--algorithm=' . $algorithm]);
}

/**
 * Collapsed to one line: the console wraps its blocks, and callers search the output for a sentence.
 */
function provision_published_keys(): string
{
    return (string) preg_replace('/\s+/', ' ', op_console(['beffroi:keys:list'], context()->withQuiet())->getOutput());
}

function provision_dev_subject(string $path): string
{
    $shown = op_console(['beffroi:user:show', DEV_USERNAME, '--no-ansi'], context()->withQuiet())->getOutput();
    if (preg_match('/^\s*Subject\s+(\S+)\s*$/m', $shown, $matches) !== 1) {
        io()->error(sprintf('"beffroi:user:show %s" does not say which subject the user was issued.', DEV_USERNAME));
        exit(1);
    }
    $subject = $matches[1];
    if (provision_env_local_set($path, 'BEFFROI_DEV_USER_SUBJECT', $subject)) {
        io()->text(sprintf('Published the subject of "%s" into %s.', DEV_USERNAME, DEV_ENV_LOCAL));
    }

    return $subject;
}

/**
 * @return array<string, string> the environment of the application
 */
function provision_env_local(?string $kms): array
{
    $env = load_dot_env(getcwd() . '/apps/beffroi/.env');
    $current = kms_backend_of($env['BEFFROI_KMS_DSN'] ?? '');
    if ($current !== null && $kms !== null && $kms !== $current) {
        io()->error([
            sprintf('%s seals the signing keys with %s; "--kms %s" is a change of KMS, which this task never does by itself.', DEV_ENV_LOCAL, $current, $kms),
            sprintf(
                'To switch: remove BEFFROI_KMS_DSN and BEFFROI_KMS_KEY_ID from %s, run this task again with "--kms %s", then "castor console beffroi:keys:rotate --now": the envelopes sealed by %s cannot be opened by %s, the key that signed retires with its window and its public half still verifies what it signed; nothing is deleted.',
                DEV_ENV_LOCAL,
                $kms,
                $current,
                $kms,
            ),
        ]);
        exit(1);
    }
    $kms = $current ?? $kms ?? 'sodium';
    kms_backend($kms);

    $generate = static fn (int $bytes): string => rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    $values = match ($kms) {
        'sodium' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'sodium://?keys[signing]=' . $generate(32),
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'signing',
            // The client "castor rewrap-live" moves the data keys to: a second key under the id of the first.
            'BEFFROI_KMS_DSN_SECOND' => static fn (): string => 'sodium://?keys[signing]=' . $generate(32),
        ],
        'file' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'sodium+dir://' . KMS_FILE_DIRECTORY . '?ext=.key',
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'beffroi-{tenant}',
        ],
        'vault' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'hashicorp-vault-transit://' . vault_mint_op_token() . '@vault:8200?scheme=http',
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'beffroi-{tenant}',
            // The same, a sodium key under the name of the Transit key, which its container creates and a task cannot.
            'BEFFROI_KMS_DSN_SECOND' => static fn (): string => 'sodium://?keys[beffroi-' . DEV_TENANT_SLUG . ']=' . $generate(32),
        ],
        // The alias of the tenant is the one docker/floci/init.sh creates.
        'aws' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'aws-kms://test:test@floci:4566?region=eu-west-3&scheme=http',
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'alias/beffroi-{tenant}',
        ],
    };
    $values['BEFFROI_DEV_USER_PASSWORD'] = static fn (): string => $generate(24);
    // Empty in apps/beffroi/.env, which an image is compiled from: a deployment announces the host it serves or none.
    $values['BEFFROI_MTLS_ORIGIN'] = static fn (): string => 'https://' . DEV_MTLS_SERVER_NAME;
    // Empty in apps/beffroi/.env too, since no image may announce open registration; the Dynamic OP plan needs it.
    $values['BEFFROI_REGISTRATION_MODE'] = static fn (): string => 'open';
    foreach (DEV_CLIENT_SECRETS as $name) {
        $values[$name] = static fn (): string => $generate(32);
    }

    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    if ($kms === 'file') {
        // On every run: a volume recreated with the stack holds no key any more.
        kms_file_write('beffroi-' . DEV_TENANT_SLUG);
    }
    if ($current === 'vault' && ! vault_token_works(vault_token_of($env['BEFFROI_KMS_DSN']))) {
        io()->warning(sprintf(
            'The Vault token of %s no longer works (the dev server forgets its tokens and its keys when it restarts): a new one is minted. The keys sealed before the restart cannot be opened any more, which the check of the published key says below.',
            DEV_ENV_LOCAL,
        ));
        $env['BEFFROI_KMS_DSN'] = $values['BEFFROI_KMS_DSN']();
        provision_env_local_set($path, 'BEFFROI_KMS_DSN', $env['BEFFROI_KMS_DSN']);
    }

    $lines = [];
    foreach ($values as $name => $value) {
        if (($env[$name] ?? '') !== '') {
            continue;
        }
        $env[$name] = $value();
        $lines[] = sprintf('%s="%s"', $name, $env[$name]);
    }
    if ($lines !== []) {
        $existing = file_exists($path) ? rtrim((string) file_get_contents($path), "\n") . "\n\n" : '';
        file_put_contents($path, $existing . "###> castor provision ###\n" . implode("\n", $lines) . "\n###< castor provision ###\n");
        io()->text(sprintf('Wrote %d development value(s) into %s.', count($lines), DEV_ENV_LOCAL));
    }
    // Unlike the values above, these follow the key material they publish, whatever the file holds.
    $published = [
        ...provision_fapi_clients($path),
        ...provision_demo_issuer($path),
        ...provision_demo_attestation_authority($path),
    ];

    if ($lines === [] && $published === []) {
        io()->note(sprintf('%s carries every development value already.', DEV_ENV_LOCAL));

        return $env;
    }
    provision_restart_consumers();

    return $env;
}

function provision_restart_consumers(): void
{
    if (in_array('worker', compose_running_services(), true)) {
        run(['docker', 'compose', ...compose_profiles(), 'restart', 'worker']);
    }

    compose_recreate_redirectors(['worker']);
}

/**
 * Started and never "up", which would create the worker again without the environment "castor start" gave it.
 */
function provision_start_worker(): void
{
    $state = trim(
        run(
            ['docker', 'compose', ...compose_profiles(), 'ps', '--all', '--format', '{{.State}}', 'worker'],
            context: context()->withQuiet(),
        )->getOutput(),
    );
    if ($state === '') {
        return;
    }
    if ($state === 'restarting') {
        run(['docker', 'compose', ...compose_profiles(), 'restart', 'worker']);
    }
    // The window of the healthcheck of compose.yaml and the time the entrypoint takes to trust the suite.
    run(['docker', 'compose', ...compose_profiles(), 'start', '--wait', '--wait-timeout', '180', 'worker']);
    if ($state !== 'running') {
        compose_recreate_redirectors(['worker']);
    }
}

function kms_backend_of(string $dsn): ?string
{
    if ($dsn === '') {
        return null;
    }
    foreach (KMS_BACKENDS as $name => $backend) {
        if (str_starts_with($dsn, $backend['scheme'] . '://')) {
            return $name;
        }
    }

    return null;
}

/**
 * 32 bytes and nothing else: FilesystemKeyLoader reads the file verbatim. An existing key is kept, the sealed
 * keys depend on it.
 */
function kms_file_write(string $name): void
{
    $path = sprintf('%s/%s.key', KMS_FILE_DIRECTORY, $name);
    $written = run(
        [
            'docker',
            'compose',
            'exec',
            '-T',
            'op',
            'sh',
            '-c',
            sprintf(
                'umask 077 && mkdir -p %1$s && chmod 700 %1$s && if [ -e %2$s ]; then echo kept; else head -c 32 /dev/urandom > %2$s && echo written; fi',
                KMS_FILE_DIRECTORY,
                $path,
            ),
        ],
        context: context()->withAllowFailure()->withQuiet(),
    );
    if (! $written->isSuccessful()) {
        io()->error([
            'The key file could not be written in the op container: is the stack running? "castor start" starts it.',
            trim($written->getErrorOutput()),
        ]);
        exit(1);
    }
    io()->text(sprintf(
        '%s the key of the file backend, %s in the op container (volume kms_data, mode 0600).',
        trim($written->getOutput()) === 'kept' ? 'Kept' : 'Wrote',
        $path,
    ));
}

function vault_token_of(string $dsn): string
{
    $token = parse_url($dsn, \PHP_URL_USER);
    if (! is_string($token) || $token === '') {
        io()->error(sprintf('The Vault DSN of %s carries no token.', DEV_ENV_LOCAL));
        exit(1);
    }

    return $token;
}

/**
 * Minted with the root token of the dev server, which never reaches the OP.
 */
function vault_mint_op_token(): string
{
    $minted = vault_cli(['token', 'create', '-policy=' . VAULT_OP_POLICY, '-no-default-policy', '-display-name=' . VAULT_OP_POLICY, '-format=json']);
    if (! $minted->isSuccessful()) {
        io()->error([
            'The token of the OP could not be minted: is Vault running? "castor start --kms vault" starts it and initialises it.',
            trim($minted->getErrorOutput()),
        ]);
        exit(1);
    }
    $token = json_decode($minted->getOutput(), true)['auth']['client_token'] ?? null;
    if (! is_string($token) || $token === '') {
        io()->error('Vault answered without a token.');
        exit(1);
    }
    io()->text(sprintf('Minted a token for the OP on Vault, under the policy "%s".', VAULT_OP_POLICY));

    return $token;
}

function vault_token_works(string $token): bool
{
    return vault_cli(['token', 'lookup'], [
        'VAULT_TOKEN' => $token,
    ])->isSuccessful();
}

/**
 * @param array<string> $args
 * @param array<string, string> $environment
 */
function vault_cli(array $args, array $environment = []): Process
{
    $options = [];
    foreach ($environment as $name => $value) {
        $options[] = '-e';
        $options[] = $name . '=' . $value;
    }

    return run(
        ['docker', 'compose', 'exec', '-T', ...$options, 'vault', 'vault', ...$args],
        context: context()->withAllowFailure()->withQuiet(),
    );
}

/**
 * Self-signed (RFC 8705 §2.2) and kept while valid: a client registered under its thumbprint survives another run.
 */
function provision_mtls_client(): void
{
    $directory = getcwd() . '/' . DEV_MTLS_DIRECTORY;
    $certificateFile = $directory . '/client.crt';
    $keyFile = $directory . '/client.key';
    $certificate = provision_mtls_valid_certificate($certificateFile, $keyFile);
    if ($certificate === null) {
        if (! is_dir($directory) && ! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
        $certificate = provision_mtls_issue($certificateFile, $keyFile);
        io()->text(sprintf('Issued %s, self-signed, valid %d days.', DEV_MTLS_DIRECTORY . '/client.crt', DEV_MTLS_CLIENT_DAYS));
    } else {
        io()->text(sprintf('%s is there and still valid; it is kept.', DEV_MTLS_DIRECTORY . '/client.crt'));
    }
    io()->text(sprintf(
        'Thumbprint (RFC 8705 §3.1, "x5t#S256"): <info>%s</info>. "castor mtls" presents it to https://%s.',
        mtls_thumbprint($certificate),
        DEV_MTLS_SERVER_NAME,
    ));
}

function provision_mtls_valid_certificate(string $certificateFile, string $keyFile): ?string
{
    if (! is_file($certificateFile) || ! is_file($keyFile)) {
        return null;
    }
    $certificate = (string) file_get_contents($certificateFile);
    $parsed = openssl_x509_parse($certificate);
    if ($parsed === false || ! is_int($parsed['validTo_time_t'] ?? null) || $parsed['validTo_time_t'] < time()) {
        return null;
    }

    return $certificate;
}

/**
 * @return string the certificate, PEM
 */
function provision_mtls_issue(string $certificateFile, string $keyFile): string
{
    return provision_self_signed_certificate(DEV_MTLS_CLIENT_NAME, provision_p256_key(), $certificateFile, $keyFile);
}

function provision_p256_key(): OpenSSLAsymmetricKey
{
    $key = openssl_pkey_new([
        'private_key_type' => \OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    if ($key === false) {
        io()->error(sprintf('Cannot generate a P-256 key: %s', openssl_error_string() ?: 'no reason given by OpenSSL'));
        exit(1);
    }

    return $key;
}

/**
 * A server certificate is also its own authority: it is verifiable only as a trust anchor where the client runs.
 *
 * @param string|null $serverName the host a client verifies it against, null for a client certificate
 *
 * @return string the certificate, PEM
 */
function provision_self_signed_certificate(
    string $commonName,
    OpenSSLAsymmetricKey $key,
    string $certificateFile,
    string $keyFile,
    ?string $serverName = null,
): string {
    $options = [
        'digest_alg' => 'sha256',
    ];
    if ($serverName !== null) {
        $options['config'] = provision_server_certificate_configuration($certificateFile, $serverName);
        $options['x509_extensions'] = DEV_SERVER_CERTIFICATE_EXTENSIONS;
    }
    $request = openssl_csr_new(
        [
            'commonName' => $commonName,
        ],
        $key,
        $options,
    );
    $signed = $request === false
        ? false
        : openssl_csr_sign($request, null, $key, DEV_MTLS_CLIENT_DAYS, $options, random_int(1, \PHP_INT_MAX));
    if ($signed === false || ! openssl_x509_export($signed, $certificate) || ! openssl_pkey_export($key, $privateKey, null, $options)) {
        io()->error(sprintf('Cannot issue a certificate: %s', openssl_error_string() ?: 'no reason given by OpenSSL'));
        exit(1);
    }
    file_put_contents($keyFile, $privateKey);
    chmod($keyFile, 0o600);
    file_put_contents($certificateFile, $certificate);

    return $certificate;
}

const DEV_SERVER_CERTIFICATE_EXTENSIONS = 'beffroi_server';

/**
 * OpenSSL reads the extensions of a server certificate from a file: they cannot be given as an array.
 *
 * @return string the path of the configuration
 */
function provision_server_certificate_configuration(string $certificateFile, string $serverName): string
{
    $path = $certificateFile . '.cnf';
    file_put_contents($path, sprintf(
        <<<'CONFIGURATION'
            [ req ]
            distinguished_name = beffroi_dn

            [ beffroi_dn ]

            [ %s ]
            basicConstraints = critical, CA:TRUE
            keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
            extendedKeyUsage = serverAuth
            subjectAltName = DNS:%s

            CONFIGURATION,
        DEV_SERVER_CERTIFICATE_EXTENSIONS,
        $serverName,
    ));

    return $path;
}

/**
 * A set still valid is kept, so that a client the provider knows by its key survives another run.
 *
 * @return list<string> the clients whose variable this run wrote or put back
 */
function provision_fapi_clients(string $path): array
{
    $directory = getcwd() . '/' . DEV_CONFORMANCE_DIRECTORY;
    if (! is_dir($directory) && ! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }
    $published = [];
    foreach (DEV_FAPI_CLIENTS as $clientId => $definition) {
        $key = provision_fapi_key($directory, $clientId, $definition['certificate']);
        $public = $key;
        unset($public['d']);
        $set = json_encode(
            [
                'keys' => [$public],
            ],
            \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES,
        );
        if (provision_env_local_set($path, $definition['env'], base64_encode($set))) {
            $published[] = $clientId;
        }
    }
    if ($published !== []) {
        io()->text(sprintf('Published the public JWK Set of %s into %s.', implode(', ', $published), DEV_ENV_LOCAL));
    }

    return $published;
}

/**
 * @return list<string> the authority, when its public half was written or rewritten
 */
function provision_demo_attestation_authority(string $path): array
{
    $keys = provision_demo_authority_keys(DEV_DEMO_ATTESTATION_AUTHORITY['file']);
    if (! provision_env_local_set($path, DEV_DEMO_ATTESTATION_AUTHORITY['env'], base64_encode(provision_public_set($keys)))) {
        return [];
    }
    io()->text(sprintf(
        'Published the public JWK Set of the attestation authority %s into %s.',
        DEV_DEMO_ATTESTATION_AUTHORITY['issuer'],
        DEV_ENV_LOCAL,
    ));

    return [DEV_DEMO_ATTESTATION_AUTHORITY['issuer']];
}

/**
 * @return list<array<string, mixed>>
 */
function provision_demo_authority_keys(string $file): array
{
    $directory = getcwd() . '/' . DEV_DEMO_DIRECTORY;
    if (! is_dir($directory) && ! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }

    return provision_demo_keys($directory, $file, false);
}

/**
 * @param list<array<string, mixed>> $keys
 */
function provision_public_set(array $keys): string
{
    $public = array_map(static function (array $key): array {
        unset($key['d']);

        return $key;
    }, $keys);

    return json_encode(
        [
            'keys' => $public,
        ],
        \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES,
    );
}

/**
 * @return list<string> the issuer, when its public half was written or rewritten
 */
function provision_demo_issuer(string $path): array
{
    $keys = provision_demo_authority_keys(DEV_DEMO_ISSUER['file']);
    if (! provision_env_local_set($path, DEV_DEMO_ISSUER['env'], base64_encode(provision_public_set($keys)))) {
        return [];
    }
    io()->text(sprintf('Published the public JWK Set of the trusted issuer %s into %s.', DEV_DEMO_ISSUER['issuer'], DEV_ENV_LOCAL));

    return [DEV_DEMO_ISSUER['issuer']];
}

/**
 * @return list<array<string, mixed>>
 */
function provision_demo_keys(string $directory, string $clientId, bool $encryption): array
{
    $file = sprintf('%s/%s.jwks.json', $directory, $clientId);
    $kept = provision_demo_valid_keys($file, $encryption ? 2 : 1);
    if ($kept !== null) {
        return $kept;
    }

    $keys = [provision_fapi_jwk(provision_p256_key())];
    if ($encryption) {
        $keys[] = provision_demo_rsa_jwk();
    }
    $written = json_encode(
        [
            'keys' => $keys,
        ],
        \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT,
    );
    file_put_contents($file, $written . "\n");
    chmod($file, 0o600);
    io()->text(sprintf('Generated %d key(s) of %s, kid %s.', count($keys), $clientId, implode(', ', array_column($keys, 'kid'))));

    return $keys;
}

/**
 * RFC 7518 §6.3, RFC 7638
 *
 * @return array<string, mixed>
 */
function provision_demo_rsa_jwk(): array
{
    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => \OPENSSL_KEYTYPE_RSA,
    ]);
    $details = $key === false ? false : openssl_pkey_get_details($key);
    $rsa = is_array($details) && is_array($details['rsa'] ?? null) ? $details['rsa'] : null;
    if ($rsa === null) {
        io()->error(sprintf('Cannot generate an RSA key: %s', openssl_error_string() ?: 'no reason given by OpenSSL'));
        exit(1);
    }
    $members = [
        'n' => 'n',
        'e' => 'e',
        'd' => 'd',
        'p' => 'p',
        'q' => 'q',
        'dp' => 'dmp1',
        'dq' => 'dmq1',
        'qi' => 'iqmp',
    ];
    $jwk = [
        'kty' => 'RSA',
    ];
    foreach ($members as $member => $name) {
        $jwk[$member] = provision_base64url((string) $rsa[$name]);
    }
    $jwk['use'] = 'enc';
    $jwk['alg'] = 'RSA-OAEP-256';
    $jwk['kid'] = provision_base64url(hash(
        'sha256',
        json_encode(
            [
                'e' => $jwk['e'],
                'kty' => $jwk['kty'],
                'n' => $jwk['n'],
            ],
            \JSON_THROW_ON_ERROR,
        ),
        true,
    ));

    return $jwk;
}

/**
 * @return list<array<string, mixed>>|null
 */
function provision_demo_valid_keys(string $file, int $expected): ?array
{
    if (! is_file($file)) {
        return null;
    }
    $set = json_decode((string) file_get_contents($file), true);
    $keys = is_array($set) && is_array($set['keys'] ?? null) ? array_values($set['keys']) : [];
    if (count($keys) !== $expected) {
        return null;
    }
    foreach ($keys as $key) {
        if (! is_array($key) || ! is_string($key['d'] ?? null) || ! is_string($key['kid'] ?? null)) {
            return null;
        }
    }

    /** @var list<array<string, mixed>> $keys */
    return $keys;
}

/**
 * @return array<string, mixed>
 */
function provision_fapi_key(string $directory, string $clientId, bool $certificate): array
{
    $file = sprintf('%s/%s.jwks.json', $directory, $clientId);
    $certificateFile = sprintf('%s/%s.crt', $directory, $clientId);
    $keyFile = sprintf('%s/%s.key', $directory, $clientId);
    $kept = provision_fapi_valid_key($file, $certificate ? $certificateFile : null, $certificate ? $keyFile : null);
    if ($kept !== null) {
        return $kept;
    }

    $key = provision_p256_key();
    $jwk = provision_fapi_jwk($key);
    if ($certificate) {
        $jwk['x5c'] = [provision_certificate_base64(provision_self_signed_certificate($clientId, $key, $certificateFile, $keyFile))];
    }
    $written = json_encode(
        [
            'keys' => [$jwk],
        ],
        \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT,
    );
    file_put_contents($file, $written . "\n");
    chmod($file, 0o600);
    io()->text(sprintf(
        'Generated the key of %s, kid %s%s.',
        $clientId,
        $jwk['kid'],
        $certificate ? sprintf(', certificate valid %d days', DEV_MTLS_CLIENT_DAYS) : '',
    ));

    return $jwk;
}

/**
 * @return array<string, mixed>|null
 */
function provision_fapi_valid_key(string $file, ?string $certificateFile, ?string $keyFile): ?array
{
    if (! is_file($file)) {
        return null;
    }
    $set = json_decode((string) file_get_contents($file), true);
    $jwk = is_array($set) && is_array($set['keys'][0] ?? null) ? $set['keys'][0] : null;
    if ($jwk === null || ! is_string($jwk['d'] ?? null) || ! is_string($jwk['kid'] ?? null)) {
        return null;
    }
    if ($certificateFile === null || $keyFile === null) {
        return $jwk;
    }
    if (! is_array($jwk['x5c'] ?? null) || ! is_file($keyFile) || provision_mtls_valid_certificate($certificateFile, $keyFile) === null) {
        return null;
    }

    return $jwk;
}

/**
 * RFC 7518 §6.2, RFC 7638, RFC 7517 §4.2, §4.4
 *
 * @return array<string, mixed>
 */
function provision_fapi_jwk(OpenSSLAsymmetricKey $key, string $use = 'sig', string $algorithm = 'ES256'): array
{
    $details = openssl_pkey_get_details($key);
    $coordinates = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : null;
    if ($coordinates === null) {
        io()->error('The generated key is not an elliptic curve key.');
        exit(1);
    }
    $coordinate = static fn (string $name): string => provision_base64url(str_pad((string) $coordinates[$name], 32, "\0", \STR_PAD_LEFT));
    $jwk = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => $coordinate('x'),
        'y' => $coordinate('y'),
        'd' => $coordinate('d'),
        'use' => $use,
        'alg' => $algorithm,
    ];
    $jwk['kid'] = provision_base64url(hash(
        'sha256',
        json_encode(
            [
                'crv' => $jwk['crv'],
                'kty' => $jwk['kty'],
                'x' => $jwk['x'],
                'y' => $jwk['y'],
            ],
            \JSON_THROW_ON_ERROR,
        ),
        true,
    ));

    return $jwk;
}

/**
 * Base64 and not base64url, as RFC 7517 §4.7 wants an "x5c" entry.
 */
function provision_certificate_base64(string $pem): string
{
    return (string) preg_replace('/\s+/', '', (string) preg_replace('/-----[^-]+-----/', '', $pem));
}

function provision_base64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

/**
 * @return bool whether the file changed
 */
function provision_env_local_set(string $path, string $name, string $value): bool
{
    $line = sprintf('%s="%s"', $name, $value);
    $contents = file_exists($path) ? (string) file_get_contents($path) : '';
    $pattern = sprintf('/^%s=.*$/m', preg_quote($name, '/'));
    if (preg_match($pattern, $contents, $matches) === 1) {
        if ($matches[0] === $line) {
            return false;
        }
        file_put_contents($path, preg_replace_callback($pattern, static fn (): string => $line, $contents, 1));

        return true;
    }
    file_put_contents($path, ($contents === '' ? '' : rtrim($contents, "\n") . "\n") . $line . "\n");

    return true;
}

/**
 * RFC 8705 §3.1
 */
function mtls_thumbprint(string $pem): string
{
    $body = (string) preg_replace('/\s+/', '', (string) preg_replace('/-----[^-]+-----/', '', $pem));
    $der = base64_decode($body, true);
    if ($der === false || $der === '') {
        io()->error('The client certificate of the development stack is not a PEM certificate.');
        exit(1);
    }

    return rtrim(strtr(base64_encode(hash('sha256', $der, true)), '+/', '-_'), '=');
}
