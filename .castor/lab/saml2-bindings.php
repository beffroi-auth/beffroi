<?php

declare(strict_types=1);

/*
 * beffroi/saml2-bindings against what is not this package (spec/bindings.md sections 9.1 and 9.5): the OpenSSL command
 * line and Python's zlib on the URLs the sender signed, the oracle the CI runs, and the judge of section 9.5,
 * SimpleSAMLphp both ways with Keycloak reinforcing it, run by hand and never by the CI (section 12).
 * tests/saml2-bindings/Interop/simplesamlphp/README.md and tests/saml2-bindings/Interop/keycloak/README.md hold what
 * each step does, its results and its findings. The two installations have compose projects and ports of their own
 * (8091, 8092 and 8190), so that they run beside saml2-model's.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\exit_code;
use function Castor\io;
use function Castor\run;

/**
 * Where the OpenSSL oracle writes its URLs, under the ignored var/.
 */
const SAML2_BINDINGS_ORACLE = 'var/oracle/saml2-bindings';

/**
 * The directory of the SimpleSAMLphp judge, relative to the root of the repository.
 */
const SAML2_BINDINGS_SIMPLESAMLPHP = 'tests/saml2-bindings/Interop/simplesamlphp';

/**
 * The directory of the Keycloak harness, relative to the root of the repository.
 */
const SAML2_BINDINGS_KEYCLOAK = 'tests/saml2-bindings/Interop/keycloak';

#[AsTask(
    description: 'Write signed HTTP-Redirect URLs with RedirectSender under every algorithm this build has, then have the OpenSSL command line verify each signature over the octets of the binding built from the URL, and Python\'s zlib inflate each message to the document the writer wrote, each under its signer\'s certificate in Alpine 3.22 (spec/bindings.md section 9.1), what the job Oracle of the CI runs: PHP_VERSION=8.5 castor saml2-bindings-oracle',
)]
function saml2_bindings_oracle(): void
{
    foreach (glob(SAML2_BINDINGS_ORACLE . '/*') ?: [] as $file) {
        unlink($file);
    }
    phpqa(
        [
            'composer',
            'exec',
            '--',
            'phpunit',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--no-coverage',
            '--testsuite',
            'saml2-bindings',
            '--filter',
            'RedirectSenderOracleTest',
        ],
        ['REDIRECT_ORACLE' => SAML2_BINDINGS_ORACLE],
    );
    // What the oracle reads, mounted read-only: the script, the two certificates and what the sender wrote.
    in_alpine(
        'apk add -q openssl python3 >/dev/null 2>&1 && openssl version && python3 --version'
        . ' && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh tests/saml2-bindings/Fixture/keys/sp-signing-certificate.pem '
        . SAML2_BINDINGS_ORACLE
        . '/sp-*.url'
        . ' && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh tests/saml2-bindings/Fixture/keys/idp-signing-certificate.pem '
        . SAML2_BINDINGS_ORACLE
        . '/idp-*.url',
        [
            'tests/saml2-bindings/Fixture/oracle',
            'tests/saml2-bindings/Fixture/keys/sp-signing-certificate.pem',
            'tests/saml2-bindings/Fixture/keys/idp-signing-certificate.pem',
            SAML2_BINDINGS_ORACLE,
        ],
    );
}

#[AsTask(
    description: 'The judge of spec/bindings.md section 9.5, SimpleSAMLphp both ways: without an option, the whole run (up, the capture, the exchange, down); each option runs its step alone, in the order listed',
)]
function saml2_bindings_simplesamlphp(
    #[AsOption(description: 'Start the installation, its image built locally if needed')]
    bool $up = false,
    #[AsOption(
        description: 'Play login and logout between the installation\'s two parties, every query string and form read by this package (capture.php)',
    )]
    bool $capture = false,
    #[AsOption(
        description: 'Play the exchange with this package, the installation up: both ways, login and logout, the probes and the measures (exchange.php)',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'With the capture and the exchange: keep what SimpleSAMLphp sent in tests/saml2-bindings/Fixture/real/, dated, instead of received/',
    )]
    bool $keep = false,
    #[AsOption(description: 'The figure of section 9.6 on the real query strings and forms (timing.php)')]
    bool $timing = false,
    #[AsOption(description: 'Stop the installation')]
    bool $down = false,
): void {
    if (! $up && ! $capture && ! $exchange && ! $timing && ! $down) {
        saml2_bindings_installed();
        try {
            saml2_bindings_simplesamlphp_up();
            saml2_bindings_simplesamlphp_script('capture.php', $keep);
            saml2_bindings_simplesamlphp_script('exchange.php', $keep);
        } finally {
            saml2_bindings_simplesamlphp_down();
        }

        return;
    }
    if ($up) {
        saml2_bindings_installed();
        saml2_bindings_simplesamlphp_up();
    }
    if ($capture) {
        saml2_bindings_simplesamlphp_script('capture.php', $keep);
    }
    if ($exchange) {
        saml2_bindings_simplesamlphp_script('exchange.php', $keep);
    }
    if ($timing) {
        saml2_bindings_installed();
        phpqa(['php', SAML2_BINDINGS_SIMPLESAMLPHP . '/timing.php']);
    }
    if ($down) {
        saml2_bindings_simplesamlphp_down();
    }
}

/**
 * What a clean checkout lacks: the dependencies of the repository, which the scripts load.
 */
function saml2_bindings_installed(): void
{
    if (! is_file('vendor/autoload.php')) {
        io()->error('The repository is not installed: run "composer install" first.');
        exit(1);
    }
}

/**
 * The installation up, its image built from installation/Dockerfile; written/, which both parties mount, created here
 * so that Docker does not create it as root.
 */
function saml2_bindings_simplesamlphp_up(): void
{
    if (! is_dir(SAML2_BINDINGS_SIMPLESAMLPHP . '/written')) {
        mkdir(SAML2_BINDINGS_SIMPLESAMLPHP . '/written');
    }
    run([
        'docker',
        'compose',
        '-f',
        SAML2_BINDINGS_SIMPLESAMLPHP . '/installation/compose.yaml',
        'up',
        '-d',
        '--build',
        '--force-recreate',
    ]);
    for ($attempt = 0; $attempt < 60; ++$attempt) {
        $idp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8091/simplesaml/module.php/saml/idp/metadata',
        ], context: context()->withQuiet());
        $sp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8092/simplesaml/module.php/saml/sp/metadata/for-bindings',
        ], context: context()->withQuiet());
        if ($idp === 0 && $sp === 0) {
            return;
        }
        sleep(1);
    }
    io()->error('SimpleSAMLphp did not come up.');
    exit(1);
}

/**
 * A script of the judge in the phpqa image, on the network of the installation, localhost:8091 and localhost:8092
 * pinned to its two containers so that every URL stays the one the installation knows.
 */
function saml2_bindings_simplesamlphp_script(string $script, bool $keep): void
{
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'saml2-bindings-simplesamlphp_default',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'EXCHANGE_CONNECT_TO=localhost:8091:idp:80,localhost:8092:sp:80',
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', saml2_interop_php_version()),
        'php',
        SAML2_BINDINGS_SIMPLESAMLPHP . '/' . $script,
        ...($keep ? ['--keep'] : []),
    ]);
}

function saml2_bindings_simplesamlphp_down(): void
{
    run(['docker', 'compose', '-f', SAML2_BINDINGS_SIMPLESAMLPHP . '/installation/compose.yaml', 'down']);
}

#[AsTask(
    description: 'Keycloak against this package, both ways (spec/bindings.md section 9.5): without an option, the whole run (up, the capture, the exchange, down); each option runs its step alone, in the order listed',
)]
function saml2_bindings_keycloak(
    #[AsOption(description: 'Start Keycloak, the realms of tests/saml2-bindings/Interop/keycloak/realms/ imported with new keys')]
    bool $up = false,
    #[AsOption(
        description: 'Play login and logout between realm sp\'s broker and realm idp, every query string and form read by this package (capture.php)',
    )]
    bool $capture = false,
    #[AsOption(
        description: 'Configure Keycloak from this package\'s metadata and play the exchange, Keycloak up: both ways, login and logout, the probes and the measures (exchange.php)',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'With the capture and the exchange: keep what Keycloak sent in tests/saml2-bindings/Fixture/real/, dated, instead of received/; the realm keys being new at every up, run both in one up',
    )]
    bool $keep = false,
    #[AsOption(description: 'Stop Keycloak and remove its container, its realms and keys with it')]
    bool $down = false,
): void {
    if (! $up && ! $capture && ! $exchange && ! $down) {
        saml2_bindings_installed();
        try {
            saml2_bindings_keycloak_up();
            saml2_bindings_keycloak_script('capture.php', $keep);
            saml2_bindings_keycloak_script('exchange.php', $keep);
        } finally {
            saml2_bindings_keycloak_down();
        }

        return;
    }
    if ($up) {
        saml2_bindings_installed();
        saml2_bindings_keycloak_up();
    }
    if ($capture) {
        saml2_bindings_keycloak_script('capture.php', $keep);
    }
    if ($exchange) {
        saml2_bindings_keycloak_script('exchange.php', $keep);
    }
    if ($down) {
        saml2_bindings_keycloak_down();
    }
}

/**
 * Keycloak up, the realms imported at its first start with new keys; the scripts wait for it to answer.
 */
function saml2_bindings_keycloak_up(): void
{
    run(['docker', 'compose', '-f', SAML2_BINDINGS_KEYCLOAK . '/compose.yaml', 'up', '-d']);
}

/**
 * A script of the harness in the phpqa image, inside the network namespace of the Keycloak container: localhost:8190 is
 * Keycloak there, the host and the port of every URL it builds and checks.
 */
function saml2_bindings_keycloak_script(string $script, bool $keep): void
{
    $container = trim(capture(
        ['docker', 'compose', '-f', SAML2_BINDINGS_KEYCLOAK . '/compose.yaml', 'ps', '-q', 'keycloak'],
        context()->withQuiet()->withAllowFailure(),
        onFailure: '',
    ));
    if ($container === '') {
        io()->error('Keycloak is not running: castor saml2-bindings-keycloak --up.');
        exit(1);
    }
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'container:' . $container,
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'XDEBUG_MODE=off',
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', saml2_interop_php_version()),
        'php',
        SAML2_BINDINGS_KEYCLOAK . '/' . $script,
        ...($keep ? ['--keep'] : []),
    ]);
}

function saml2_bindings_keycloak_down(): void
{
    run(['docker', 'compose', '-f', SAML2_BINDINGS_KEYCLOAK . '/compose.yaml', 'down']);
}
