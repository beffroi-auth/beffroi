<?php

declare(strict_types=1);

/*
 * The development stack: the OP on FrankenPHP, its database and broker, the optional KMS backends and the
 * conformance suite, up, down, logs and console. What the CI starts before the conformance plans.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\io;
use function Castor\run;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * The KMS backends of the development stack, by the value "--kms" takes: the compose profile that runs
 * the backend, none for a local one, and the scheme of the DSN "castor provision" writes for it. The DSN
 * is the only difference between two of them (architecture §3.3): sodium and file are the same local
 * backend, the key inline in the environment or in a file of its own; vault and aws are a KMS on the
 * network, the master key never leaves it.
 */
const KMS_BACKENDS = [
    'sodium' => [
        'profile' => null,
        'scheme' => 'sodium',
    ],
    'file' => [
        'profile' => null,
        'scheme' => 'sodium+dir',
    ],
    'vault' => [
        'profile' => 'vault',
        'scheme' => 'hashicorp-vault-transit',
    ],
    'aws' => [
        'profile' => 'aws',
        'scheme' => 'aws-kms',
    ],
];

/**
 * Where the key of the file backend lives in the containers: the volume kms_data of compose.yaml, outside
 * the web root and outside the sealed keys, mounted on the process that serves and on the one that rotates.
 */
const KMS_FILE_DIRECTORY = '/app/var/kms';

/**
 * The compose profiles a task that stops or reads the whole stack must name.
 */
const COMPOSE_PROFILES = ['conformance', 'vault', 'aws', 'saml-sp', 'saml-idp'];

/**
 * Where the op container publishes the root of the authority that signed the certificate it serves, in its
 * data directory (XDG_DATA_HOME of the FrankenPHP image): a copy of the mkcert root, or a link to the root
 * of the internal CA of Caddy (docker/op/entrypoint.sh).
 */
const CADDY_ROOT_CERTIFICATE = '/data/beffroi/root.crt';

/**
 * Every name the stack serves over HTTPS, by the variable of compose.yaml that can rename it, or under no key
 * when nothing renames it, and the one list the certificate mkcert issues for the stack is drawn from
 * (stack_certificate()). A site the stack comes to serve is one line here: a name left out is served under the
 * internal CA of Caddy, which the walks, trusting the root of the certificate, refuse.
 *
 * @var array<int|string, string>
 */
const STACK_HOSTS = [
    'SERVER_NAME' => 'op.localhost',
    'MTLS_SERVER_NAME' => 'mtls.op.localhost',
    // The service provider of the SAML judge (docker/saml-sp/saml-sp.Caddyfile), whose configuration names it.
    'saml-sp.localhost',
    // The identity provider of the SAML judge (docker/saml-idp/saml-idp.Caddyfile), whose configuration names it.
    'saml-idp.localhost',
];

/**
 * Where castor keeps the certificate mkcert issues for the stack, its key and a copy of the mkcert root
 * (the certificate, never its key), relative to the root of the repository: under var/, which git ignores,
 * and mounted read-only in the op container by compose.yaml.
 */
const STACK_CERTIFICATE_DIRECTORY = 'var/stack-certificate';

/**
 * How long before it expires the certificate of the stack is issued again.
 */
const STACK_CERTIFICATE_RENEWAL_DAYS = 30;

/**
 * The sidecars that carry the loopback port 8443 of the suite into the network namespace of another
 * container (compose.yaml), by the container each one follows: the worker reaches the back-channel logout
 * URI the suite gives its clients, and the op container reads the sector identifier documents the modules
 * of the Dynamic plan serve (OIDC Registration §5).
 *
 * @var array<string, string>
 */
const REDIRECTOR_SERVICES = [
    'worker' => 'conformance-worker-redirector',
    'op' => 'conformance-op-redirector',
];

#[AsTask(
    description: 'Start the development stack: the OP on https://op.localhost and PostgreSQL. Add --conformance for the OpenID conformance suite on https://localhost:8443, without the profiler; --access-token-format opaque hands the clients of the suite opaque access tokens; --kms vault adds HashiCorp Vault, --kms aws adds LocalStack (AWS KMS), each sealing the signing keys once "castor provision --kms <backend>" ran',
)]
function start(
    bool $conformance = false,
    bool $build = false,
    #[AsOption(description: 'The access token shape of the clients of the conformance suite: jwt (default) or opaque; the plans must be green with either')]
    ?string $accessTokenFormat = null,
    #[AsOption(
        description: 'The KMS that seals the signing keys: sodium (default) or file (in the process, nothing to start), vault (HashiCorp Vault Transit, dev mode, initialised at every start by docker/vault/init.sh) or aws (LocalStack with the KMS service, initialised at every start by docker/localstack/init.sh)',
    )]
    string $kms = 'sodium',
): void {
    if ($accessTokenFormat !== null && ! in_array($accessTokenFormat, ['jwt', 'opaque'], true)) {
        io()->error(sprintf('Unknown access token format "%s"; the formats are jwt and opaque.', $accessTokenFormat));
        exit(1);
    }
    $backend = kms_backend($kms);
    $command = ['docker', 'compose'];
    $environment = [];
    if ($conformance) {
        $command = [...$command, '--profile', 'conformance'];
        // A plan of a hundred requests has no use for a hundred profiles, and the toolbar has no place in
        // the pages the scripted browser of the suite reads.
        $environment['APP_PROFILER'] = '0';
        // What tells the entrypoints of the op container and of the worker that there is a certificate of
        // the suite to trust (docker/conformance/trust-nginx.sh). It is said here and not found by looking
        // the name up: the op container starts before the suite does, and would find nothing.
        $environment['CONFORMANCE_NGINX_HOST'] = 'conformance-nginx';
    }
    if ($backend['profile'] !== null) {
        $command = [...$command, '--profile', $backend['profile']];
    }
    if ($accessTokenFormat !== null) {
        $environment['CONFORMANCE_ACCESS_TOKEN_FORMAT'] = $accessTokenFormat;
    }
    $certificate = stack_certificate();
    if ($certificate !== null) {
        $environment['BEFFROI_STACK_CERTIFICATE'] = $certificate;
        // Caddy reads the certificate when it starts: one issued again is a configuration compose sees
        // change, so the op container is created again rather than left serving the one it read.
        $environment['BEFFROI_STACK_CERTIFICATE_FINGERPRINT'] = stack_certificate_fingerprint($certificate);
    }
    // The directories compose.yaml mounts into op and worker for the metadata of the SAML judges: made here by whoever
    // runs the task, or Docker makes them as root and "castor saml-sp" or "castor saml-idp" cannot write a file into them.
    foreach (['var/saml-sp/metadata', 'var/saml-idp/metadata'] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    $up = ['up', '-d', '--remove-orphans', '--wait'];
    if ($build) {
        $up[] = '--build';
    }
    $context = context()->withEnvironment($environment);
    $provisioned = stack_names_a_kms();
    if ($provisioned) {
        run([...$command, ...$up], context: $context);
    } else {
        // The worker refuses to boot without the KMS "castor provision" names (issue #773), so on a stack that
        // task has not provisioned yet "up --wait" would wait for a container that cannot become healthy.
        // Everything else is started and waited for; the worker is created with the environment above and
        // left stopped, and "castor provision" starts it once the DSN is written (provision_start_worker()).
        run([...$command, ...$up, ...compose_services_but_the_worker($command, $context)], context: $context);
        run([...$command, 'create', ...($build ? ['--build'] : []), 'worker'], context: $context);
    }
    $started = match ($kms) {
        'vault' => ', Vault: http://localhost:8200 (dev mode, root token in compose.yaml); "castor provision --kms vault" seals the signing keys with it',
        'aws'
            => ', LocalStack (AWS KMS): http://localhost:4566 (credentials test/test, region eu-west-3); "castor provision --kms aws" seals the signing keys with it',
        default => '',
    };
    io()->success(
        'OP: https://op.localhost'
        . ($certificate === null ? ' (internal CA of Caddy)' : ' (certificate of the mkcert CA of the machine)')
        . ($conformance ? ', conformance suite: https://localhost:8443, profiler off' : '')
        . ($accessTokenFormat === null ? '' : sprintf(', %s access tokens for the clients of the suite', $accessTokenFormat))
        . $started
        . ($provisioned ? '' : '; the worker starts with "castor provision", which names the KMS it needs'),
    );
}

/**
 * Whether apps/op/.env.local names the KMS of the stack, which "castor provision" writes there and the worker
 * cannot boot without (issue #773). That one line of the file is read, and nothing else of it.
 */
function stack_names_a_kms(): bool
{
    $path = getcwd() . '/' . DEV_ENV_LOCAL;

    return is_file($path) && preg_match('/^BEFFROI_KMS_DSN="?[^"\s]/m', (string) file_get_contents($path)) === 1;
}

/**
 * The services a "docker compose" command starts under its profiles, but the worker and the sidecar that
 * joins its network namespace.
 *
 * @param list<string> $compose "docker compose" and its profiles
 *
 * @return list<string>
 */
function compose_services_but_the_worker(array $compose, Context $context): array
{
    $services = run([...$compose, 'config', '--services'], context: $context->withQuiet())->getOutput();

    return array_values(array_diff(explode("\n", trim($services)), ['worker', REDIRECTOR_SERVICES['worker']]));
}

/**
 * The names of STACK_HOSTS, each one that has a variable renamed by it when the environment sets it, as
 * compose.yaml does.
 *
 * @return list<string>
 */
function stack_hosts(): array
{
    $hosts = [];
    foreach (STACK_HOSTS as $variable => $default) {
        $value = is_string($variable) ? getenv($variable) : false;
        $hosts[] = is_string($value) && $value !== '' ? $value : $default;
    }

    return $hosts;
}

/**
 * The directory of the mkcert CA of the machine, when it holds a root and its key, and null otherwise (no
 * mkcert, as on a CI runner, or a root without its key). Nothing of it is configured by hand, and nothing
 * here installs anything in a trust store.
 */
function mkcert_caroot(): ?string
{
    $mkcert = new ExecutableFinder()->find('mkcert');
    if ($mkcert === null) {
        return null;
    }
    $caroot = run([$mkcert, '-CAROOT'], context: context()->withQuiet()->withAllowFailure());
    if (! $caroot->isSuccessful()) {
        return null;
    }
    $directory = trim($caroot->getOutput());
    if ($directory === '' || ! is_file($directory . '/rootCA.pem') || ! is_file($directory . '/rootCA-key.pem')) {
        return null;
    }

    return $directory;
}

/**
 * The directory of the certificate the stack serves for every name of stack_hosts(), issued by mkcert on
 * this machine, or null when the machine has no mkcert CA and Caddy keeps its internal one, as on a CI
 * runner. The key of the mkcert root stays where mkcert keeps it: what the op container is given is the
 * certificate of the stack, its key and a copy of the root certificate, which is what the walks and the
 * conformance suite trust (docker/op/entrypoint.sh). The certificate is issued again when it is missing,
 * when it expires within STACK_CERTIFICATE_RENEWAL_DAYS, when the names it covers are not the names of the
 * stack, or when the root beside it is no longer the root of mkcert.
 */
function stack_certificate(): ?string
{
    $caroot = mkcert_caroot();
    if ($caroot === null) {
        return null;
    }
    $directory = context()->workingDirectory . '/' . STACK_CERTIFICATE_DIRECTORY;
    $hosts = stack_hosts();
    if (stack_certificate_is_current($directory, $hosts, $caroot . '/rootCA.pem')) {
        return $directory;
    }
    if (! is_dir($directory) && ! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }
    run(
        [
            'mkcert',
            '-cert-file',
            $directory . '/cert.pem',
            '-key-file',
            $directory . '/key.pem',
            ...$hosts,
        ],
        context: context()->withQuiet(),
    );
    if (! copy($caroot . '/rootCA.pem', $directory . '/root.pem')) {
        io()->error(sprintf('Cannot copy the mkcert root to %s.', $directory));
        exit(1);
    }
    io()->note(sprintf('The certificate of the stack was issued by mkcert for %s.', implode(', ', $hosts)));

    return $directory;
}

/**
 * The SHA-256 fingerprint of the certificate kept in this directory.
 */
function stack_certificate_fingerprint(string $directory): string
{
    $certificate = file_get_contents($directory . '/cert.pem');
    $fingerprint = $certificate === false ? false : openssl_x509_fingerprint($certificate, 'sha256');
    if ($fingerprint === false) {
        io()->error(sprintf('Cannot read the certificate of the stack in %s.', $directory));
        exit(1);
    }

    return $fingerprint;
}

/**
 * Whether the certificate kept in this directory covers exactly these names, is valid for longer than
 * STACK_CERTIFICATE_RENEWAL_DAYS, and sits beside a copy of this root.
 *
 * @param list<string> $hosts
 */
function stack_certificate_is_current(string $directory, array $hosts, string $root): bool
{
    $certificate = @file_get_contents($directory . '/cert.pem');
    $copy = @file_get_contents($directory . '/root.pem');
    if ($certificate === false || $copy === false || ! is_file($directory . '/key.pem') || $copy !== file_get_contents($root)) {
        return false;
    }
    $parsed = openssl_x509_parse($certificate);
    if ($parsed === false || ! is_int($parsed['validTo_time_t'] ?? null)) {
        return false;
    }
    if ($parsed['validTo_time_t'] < (time() + (STACK_CERTIFICATE_RENEWAL_DAYS * 86_400))) {
        return false;
    }
    $alternativeNames = $parsed['extensions']['subjectAltName'] ?? null;
    if (! is_string($alternativeNames)) {
        return false;
    }
    $covered = array_map(static fn (string $name): string => trim(str_replace('DNS:', '', $name)), explode(',', $alternativeNames));
    $expected = $hosts;
    sort($covered);
    sort($expected);

    return $covered === $expected;
}

/**
 * @return array{profile: ?string, scheme: string}
 */
function kms_backend(string $kms): array
{
    if (! isset(KMS_BACKENDS[$kms])) {
        io()->error(sprintf('Unknown KMS "%s"; the backends are %s.', $kms, implode(', ', array_keys(KMS_BACKENDS))));
        exit(1);
    }

    return KMS_BACKENDS[$kms];
}

/**
 * @return array<string>
 */
function compose_profiles(): array
{
    $options = [];
    foreach (COMPOSE_PROFILES as $profile) {
        $options[] = '--profile';
        $options[] = $profile;
    }

    return $options;
}

/**
 * The services of the stack that are running, as compose names them.
 *
 * @return array<string>
 */
function compose_running_services(): array
{
    $running = run(
        ['docker', 'compose', ...compose_profiles(), 'ps', '--status', 'running', '--services'],
        context: context()->withAllowFailure()->withQuiet(),
    );

    return $running->isSuccessful() ? explode("\n", trim($running->getOutput())) : [];
}

/**
 * The root of the certificate the stack serves, copied out of the op container to a file of the host and
 * left there: the mkcert root when "castor start" found one, or an authority that exists only inside the
 * container, so curl and the PHP of the machine trust that file and nothing else (mtls.php, demo.php),
 * whichever of the two the stack was started with. Every walk of the laboratory asks for it here, so that
 * the path is written once and a stack that is not up is said in one wording instead of being an exit code
 * under a quiet process.
 */
function caddy_ca(string $destination): string
{
    $directory = dirname($destination);
    if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }
    if (! in_array('op', compose_running_services(), true)) {
        io()->error('The op container is not running, so there is no CA of Caddy to read: run "castor start" first.');
        exit(1);
    }
    $copy = run([
        'docker',
        'compose',
        'cp',
        '--follow-link',
        'op:' . CADDY_ROOT_CERTIFICATE,
        $destination,
    ], context: context()->withQuiet()->withAllowFailure());
    if (! $copy->isSuccessful() || ! is_file($destination)) {
        io()->error(sprintf(
            'Cannot read %s from the op container, which is running: "docker compose exec op ls %s" says what it holds.',
            CADDY_ROOT_CERTIFICATE,
            dirname(CADDY_ROOT_CERTIFICATE),
        ));
        exit(1);
    }

    return $destination;
}

/**
 * Brings the sidecars of the containers just restarted or started back up, and does nothing when the stack
 * runs without the suite (a run against a suite of its own has no sidecar to bring back). A sidecar that was
 * never started is brought up the same way: "castor start" leaves the one of the worker for "castor
 * provision", which starts the worker it follows.
 *
 * One is created again, never restarted, and always after the container it follows: it holds the
 * identifier of the container whose network namespace it joined, resolved once when Docker created it. A
 * container that restarts leaves that namespace behind, and one that is recreated takes the identifier
 * with it, so restarting the sidecar forwards nothing at best and fails outright at worst ("joining
 * network namespace of container: No such container"). Nothing says so either way, and the only things
 * that notice are the back-channel logout plan, five minutes later, on a logout token that never left,
 * and the two sector modules of the Dynamic plan, on a document that cannot be reached.
 *
 * @param list<string> $restarted the containers just restarted or started, whose network namespace is a new one
 */
function compose_recreate_redirectors(array $restarted): void
{
    $running = compose_running_services();
    if (! in_array('conformance-nginx', $running, true)) {
        return;
    }
    foreach ($restarted as $container) {
        $sidecar = REDIRECTOR_SERVICES[$container] ?? null;
        if ($sidecar === null || ! in_array($container, $running, true)) {
            continue;
        }

        run(['docker', 'compose', ...compose_profiles(), 'up', '-d', '--force-recreate', '--no-deps', $sidecar]);
    }
}

/**
 * Restarts what reads the schema, after a migration that changes the type of a column.
 *
 * A migration that seals a column recreates it as BYTEA, and a process that booted before the mapping
 * changed still holds the type registry it built then: it reads that column with the type it had, which
 * throws on a column typed "string" and, on one typed "text", hands its caller the raw ciphertext as a
 * string with nothing at all to say so ([beffroi#430](https://github.com/beffroi-auth/beffroi/issues/430)). The
 * op container holds the kernel of the application for every request its FrankenPHP workers serve, the
 * worker container runs for an hour, and neither restarts on a write in the database.
 *
 * Whether the migration applied anything is not asked: a restart nothing needed costs a few seconds on a
 * development stack, and one that was needed and not done costs a green walk and an hour in the logs.
 */
function compose_restart_after_migration(): void
{
    $running = compose_running_services();
    $restarted = array_values(array_filter(
        ['op', 'worker'],
        static fn (string $service): bool => in_array($service, $running, true),
    ));
    if ($restarted === []) {
        return;
    }

    io()->note(sprintf(
        'Restarting %s: a process that booted before a migration reads the columns it changed with the type they had.',
        implode(' and ', $restarted),
    ));
    run(['docker', 'compose', ...compose_profiles(), 'restart', ...$restarted]);
    // Last, and after the containers they follow, for the reason compose_recreate_redirectors gives.
    compose_recreate_redirectors($restarted);
}

#[AsTask(description: 'Stop the development stack')]
function stop(): void
{
    run(['docker', 'compose', ...compose_profiles(), 'down', '--remove-orphans']);
}

#[AsTask(description: 'Follow the logs of the development stack', ignoreValidationErrors: true)]
function logs(#[AsRawTokens] array $args = []): void
{
    run(['docker', 'compose', ...compose_profiles(), 'logs', '-f', ...$args]);
}

#[AsTask(
    description: 'Run a Symfony console command of the application inside the op container; a migration restarts what reads the schema',
    ignoreValidationErrors: true,
)]
function console(#[AsRawTokens] array $args = []): void
{
    op_console($args);
    if (console_runs_the_migrations($args)) {
        compose_restart_after_migration();
    }
}

/**
 * Whether these arguments run the migration command, under whatever abbreviation of its name was typed:
 * the console resolves "d:m:m" and "doctrine:mig:migrate" to the same command, so what is recognised here
 * is the command and not one spelling of it. A dry run changes no type and is not one of them.
 *
 * Every token is looked at rather than the first that is not an option, an option whose value is written
 * apart from its name making that value look like the command; no value of one abbreviates this command.
 *
 * @param array<string> $args
 */
function console_runs_the_migrations(array $args): bool
{
    if (in_array('--dry-run', $args, true)) {
        return false;
    }
    return array_any($args, fn ($argument) => console_abbreviates($argument, 'doctrine:migrations:migrate'));
}

/**
 * Whether a token names a command or abbreviates it, the way the console resolves one: as many parts as
 * the name has, each a non-empty prefix of the part at its place (Symfony\Component\Console\Application).
 */
function console_abbreviates(string $token, string $command): bool
{
    $typed = explode(':', $token);
    $parts = explode(':', $command);
    if (count($typed) !== count($parts)) {
        return false;
    }
    return array_all($parts, fn ($part, $index) => ! ($typed[$index] === '' || ! str_starts_with($part, $typed[$index])));
}

/**
 * Runs a console command of the application inside the op container, without a TTY when the input is
 * fed by the task (the password of the development user) or when the output is captured.
 *
 * @param array<string> $args
 */
function op_console(array $args, ?Context $context = null): Process
{
    $tty = $context === null && stream_isatty(\STDOUT);

    return run(
        ['docker', 'compose', 'exec', ...($tty ? [] : ['-T']), 'op', 'php', 'bin/console', ...$args],
        context: $context,
    );
}

#[AsTask(description: 'Build the stylesheet of the pages (Tailwind and DaisyUI) inside the op container; --watch rebuilds on change')]
function tailwind(bool $watch = false): void
{
    op_console(['tailwind:build', ...($watch ? ['--watch'] : [])]);
}
