<?php

declare(strict_types=1);

/*
 * beffroi/saml2-model against the implementations that are not this one (spec/model.md sections 9.1 and 9.5):
 * xmlsec1 on what the writers signed, the oracle the CI runs, and the judge of section 9.5, SimpleSAMLphp and
 * Keycloak both ways, run by hand and never by the CI (section 12). tests/saml2-model/Interop/simplesamlphp/README.md
 * and tests/saml2-model/Interop/keycloak/README.md hold what each step does, its results and its findings.
 */

use Castor\Attribute\AsArgument;
use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\exit_code;
use function Castor\io;
use function Castor\run;

/**
 * Where the oracle writes the responses it signed, under the ignored var/.
 */
const SAML2_MODEL_ORACLE = 'var/oracle/saml2-model';

/**
 * The signed documents the writers wrote and the repository commits, by the certificate of their signer (section
 * 9.1): the identity provider's responses, logout request and metadata, the service provider's AuthnRequest and
 * logout response. The job Oracle of the CI verifies the same files.
 */
const SAML2_MODEL_XMLSEC_COMMITTED = [
    'tests/saml2-model/Fixture/keys/idp-signing-certificate.pem' => [
        'tests/saml2-model/Fixture/behaviour/response-written-signed-assertion.xml',
        'tests/saml2-model/Fixture/behaviour/response-written-signed-assertion-and-response.xml',
        'tests/saml2-model/Fixture/behaviour/response-written-failure-signed-refused.xml',
        'tests/saml2-model/Fixture/behaviour/logout-request-written-and-signed-by-the-writer.xml',
        'tests/saml2-model/Fixture/behaviour/metadata-written-and-signed-by-the-writer.xml',
    ],
    'tests/saml2-model/Fixture/keys/sp-signing-certificate.pem' => [
        'tests/saml2-model/Fixture/behaviour/authn-request-written-and-signed-by-the-writer.xml',
        'tests/saml2-model/Fixture/behaviour/logout-response-written-and-signed-by-the-writer.xml',
    ],
];

/**
 * The directory of the SimpleSAMLphp judge, relative to the root of the repository.
 */
const SAML2_MODEL_SIMPLESAMLPHP = 'tests/saml2-model/Interop/simplesamlphp';

/**
 * The library half of the SimpleSAMLphp judge runs on the PHP its README pins, whatever PHP_VERSION says.
 */
const SAML2_MODEL_SIMPLESAMLPHP_LIBRARY_IMAGE = 'ghcr.io/spomky-labs/phpqa:8.4';

const SAML2_MODEL_KEYCLOAK_COMPOSE = 'tests/saml2-model/Interop/keycloak/compose.yaml';

/**
 * Where the documents of a Keycloak run go unless --output says otherwise, under the ignored var/: the model's in its
 * model/ directory, for xmlsec1.
 */
const SAML2_MODEL_KEYCLOAK_RUN = 'var/keycloak';

#[AsTask(
    description: 'Verify every signature of a written file with xmlsec1 (spec/model.md section 9.1), in Alpine 3.22: castor saml2-model-xmlsec tests/saml2-model/Fixture/behaviour/response-written-signed-assertion-and-response.xml',
)]
function saml2_model_xmlsec(
    #[AsArgument(description: 'The signed file, relative to the working directory')]
    string $file,
    #[AsOption(
        description: 'The certificate whose key verifies, relative to the working directory: the identity provider\'s test certificate, or the service provider\'s for what it signs',
    )]
    string $certificate = 'tests/saml2-model/Fixture/keys/idp-signing-certificate.pem',
): void {
    saml2_model_xmlsec1([$file], $certificate);
}

#[AsTask(
    description: 'Write and sign responses with every scheme this build offers, then have xmlsec1 verify every signature of each, and of every signed document the writers committed, each under its signer\'s certificate (spec/model.md section 9.1), what the job Oracle of the CI runs: PHP_VERSION=8.5 castor saml2-model-oracle',
)]
function saml2_model_oracle(): void
{
    foreach (glob(SAML2_MODEL_ORACLE . '/*.xml') ?: [] as $file) {
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
            'saml2-model',
            '--filter',
            'ResponseWriterOracleTest',
        ],
        ['XMLSEC_ORACLE' => SAML2_MODEL_ORACLE],
    );
    saml2_model_xmlsec1(glob(SAML2_MODEL_ORACLE . '/*.xml') ?: [], 'tests/saml2-model/Fixture/keys/idp-signing-certificate.pem');
    foreach (SAML2_MODEL_XMLSEC_COMMITTED as $certificate => $files) {
        saml2_model_xmlsec1($files, $certificate);
    }
}

/**
 * Runs tests/saml2-model/Fixture/oracle/verify-signatures.sh over $files with the key of $certificate, in Alpine.
 *
 * @param list<string> $files
 */
function saml2_model_xmlsec1(array $files, string $certificate): void
{
    in_alpine(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Fixture/oracle/verify-signatures.sh '
            . implode(' ', array_map(escapeshellarg(...), [$certificate, ...$files])),
        ['tests/saml2-model/Fixture/oracle/verify-signatures.sh', $certificate, ...$files],
    );
}

#[AsTask(
    description: 'The judge of spec/model.md section 9.5, SimpleSAMLphp both ways: without an option, the whole exchange (install, up, the exchange, verify.php and xmlsec1 on what the model wrote, down); each option runs its step alone, in the order listed',
)]
function saml2_model_simplesamlphp(
    #[AsOption(
        description: 'The library half: simplesamlphp/saml2 writes its fixtures into tests/saml2-model/Fixture/real/ with the test keys',
    )]
    bool $produce = false,
    #[AsOption(
        description: 'Start the installation in the configuration of the exchange (SSP_EXCHANGE=true), the image built if needed',
    )]
    bool $up = false,
    #[AsOption(
        description: 'Play login and logout between the installation\'s two parties with curl and keep their documents in tests/saml2-model/Fixture/real/ (capture.sh, phase 1)',
    )]
    bool $capture = false,
    #[AsOption(
        description: 'Play the exchange with the model, the installation up: both ways, login and logout, and the probes',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'With the exchange: keep what SimpleSAMLphp sent in tests/saml2-model/Fixture/real/, dated, instead of received/',
    )]
    bool $keep = false,
    #[AsOption(
        description: 'The library half and xmlsec1 verify every signature of a batch: --in and --glob, the model\'s documents of the last exchange by default',
    )]
    bool $verify = false,
    #[AsOption(
        description: 'The batch of --verify: a directory, relative to the root, holding the signers\' metadata next to their documents',
    )]
    string $in = SAML2_MODEL_SIMPLESAMLPHP . '/written',
    #[AsOption(description: 'The files of --verify in that directory')]
    string $glob = '*.xml',
    #[AsOption(description: 'Stop the installation')]
    bool $down = false,
): void {
    if (! $produce && ! $up && ! $capture && ! $exchange && ! $verify && ! $down) {
        saml2_model_simplesamlphp_install();
        try {
            saml2_model_simplesamlphp_up();
            saml2_model_simplesamlphp_exchange($keep);
            saml2_model_simplesamlphp_verify($in, $glob);
        } finally {
            saml2_model_simplesamlphp_down();
        }

        return;
    }
    if ($produce) {
        saml2_model_simplesamlphp_install();
        saml2_model_simplesamlphp_library(['php', 'produce.php'], ['tests/saml2-model/Fixture/real' => '/out']);
    }
    if ($up) {
        saml2_model_simplesamlphp_install();
        saml2_model_simplesamlphp_up();
    }
    if ($capture) {
        run(['bash', SAML2_MODEL_SIMPLESAMLPHP . '/installation/capture.sh']);
    }
    if ($exchange) {
        saml2_model_simplesamlphp_exchange($keep);
    }
    if ($verify) {
        saml2_model_simplesamlphp_install();
        saml2_model_simplesamlphp_verify($in, $glob);
    }
    if ($down) {
        saml2_model_simplesamlphp_down();
    }
}

/**
 * What a clean checkout lacks: the dependencies of the repository, which the exchange loads, and the throwaway
 * Composer project of the library half.
 */
function saml2_model_simplesamlphp_install(): void
{
    if (! is_file('vendor/autoload.php')) {
        io()->error('The repository is not installed: run "composer install" first.');
        exit(1);
    }
    if (! is_file(SAML2_MODEL_SIMPLESAMLPHP . '/library/vendor/autoload.php')) {
        saml2_model_simplesamlphp_library(['composer', 'install', '-n', '--no-progress']);
    }
}

/**
 * The installation in the configuration of the exchange: the identity provider publishes HTTP-POST next to
 * HTTP-Redirect; both parties read the model's metadata from written/, created here so that Docker does not.
 */
function saml2_model_simplesamlphp_up(): void
{
    if (! is_dir(SAML2_MODEL_SIMPLESAMLPHP . '/written')) {
        mkdir(SAML2_MODEL_SIMPLESAMLPHP . '/written');
    }
    run(
        [
            'docker',
            'compose',
            '-f',
            SAML2_MODEL_SIMPLESAMLPHP . '/installation/compose.yaml',
            'up',
            '-d',
            '--build',
            '--force-recreate',
        ],
        context: context()->withEnvironment(['SSP_EXCHANGE' => 'true']),
    );
    for ($attempt = 0; $attempt < 60; ++$attempt) {
        $idp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8081/simplesaml/module.php/saml/idp/metadata',
        ], context: context()->withQuiet());
        $sp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8082/simplesaml/module.php/saml/sp/metadata/for-model',
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
 * The exchange script in the phpqa image, on the network of the installation, localhost:8081 and localhost:8082
 * pinned to its two containers so that every URL stays the one the installation knows.
 */
function saml2_model_simplesamlphp_exchange(bool $keep): void
{
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'saml2-model-simplesamlphp_default',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'EXCHANGE_CONNECT_TO=localhost:8081:idp:80,localhost:8082:sp:80',
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', saml2_interop_php_version()),
        'php',
        SAML2_MODEL_SIMPLESAMLPHP . '/exchange.php',
        ...($keep ? ['--keep'] : []),
    ]);
}

/**
 * verify.php of the library half, then xmlsec1, on every document of a batch that matches the glob.
 */
function saml2_model_simplesamlphp_verify(string $in, string $glob): void
{
    saml2_model_simplesamlphp_library(['php', 'verify.php', '/in', $glob], [$in => '/in:ro']);
    in_alpine(
        'apk add -q xmlsec libxml2-utils && sh ' . SAML2_MODEL_SIMPLESAMLPHP . '/xmlsec1-verify.sh ' . escapeshellarg($in) . ' ' . escapeshellarg($glob),
        [SAML2_MODEL_SIMPLESAMLPHP . '/xmlsec1-verify.sh', $in],
    );
}

function saml2_model_simplesamlphp_down(): void
{
    run(['docker', 'compose', '-f', SAML2_MODEL_SIMPLESAMLPHP . '/installation/compose.yaml', 'down']);
}

/**
 * A command of the library half in its container, library/ at /app and the test keys at /keys, as its README runs it.
 *
 * @param list<string> $command
 * @param array<string, string> $mounts directories relative to the root, and where the container sees them
 */
function saml2_model_simplesamlphp_library(array $command, array $mounts = []): void
{
    $volumes = [];
    foreach ($mounts as $directory => $path) {
        $volumes[] = '-v';
        $volumes[] = getcwd() . '/' . $directory . ':' . $path;
    }
    run([
        'docker',
        'run',
        '--rm',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'COMPOSER_HOME=/tmp/composer',
        '-v',
        getcwd() . '/' . SAML2_MODEL_SIMPLESAMLPHP . '/library:/app',
        '-v',
        getcwd() . '/tests/saml2-model/Fixture/keys:/keys:ro',
        ...$volumes,
        '-w',
        '/app',
        SAML2_MODEL_SIMPLESAMLPHP_LIBRARY_IMAGE,
        ...$command,
    ]);
}

#[AsTask(
    description: 'Keycloak against the model, both ways (spec/model.md section 9.5, tests/saml2-model/Interop/keycloak/README.md): without an option, up, capture, exchange, verify and down, in that order',
)]
function saml2_model_keycloak(
    #[AsOption(description: 'Start Keycloak, the realms of tests/saml2-model/Interop/keycloak/realms/ imported with new keys')]
    bool $up = false,
    #[AsOption(description: 'Capture a login and a logout of the broker of realm sp against realm idp (capture.sh)')]
    bool $capture = false,
    #[AsOption(
        description: 'Configure Keycloak from the model\'s metadata and play the model as identity provider and as service provider (exchange.php)',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'Verify with xmlsec1 every document the model wrote in the exchange, and every signature of Keycloak\'s documents in --output',
    )]
    bool $verify = false,
    #[AsOption(description: 'Stop Keycloak and remove its container, its realms and keys with it')]
    bool $down = false,
    #[AsOption(
        description: 'Where Keycloak\'s documents are written, dated: tests/saml2-model/Fixture/real to renew the fixtures, whose files of the same day it rewrites',
    )]
    string $output = SAML2_MODEL_KEYCLOAK_RUN,
): void {
    if (! $up && ! $capture && ! $exchange && ! $verify && ! $down) {
        [$up, $capture, $exchange, $verify, $down] = [true, true, true, true, true];
    }
    $model = SAML2_MODEL_KEYCLOAK_RUN . '/model';
    if ($up) {
        run(['docker', 'compose', '-f', SAML2_MODEL_KEYCLOAK_COMPOSE, 'up', '-d']);
    }

    try {
        if ($capture || $exchange) {
            // A run leaves only its own documents behind in the ignored directories, never touching the fixtures.
            $stale = glob($model . '/*') ?: [];
            if ($output === SAML2_MODEL_KEYCLOAK_RUN || str_starts_with($output, SAML2_MODEL_KEYCLOAK_RUN . '/')) {
                $stale = [...$stale, ...(glob($output . '/keycloak-*.xml') ?: [])];
            }
            foreach ($stale as $file) {
                unlink($file);
            }
        }
        if ($capture) {
            io()->section('Capture: the broker of realm sp against realm idp');
            run(['bash', 'tests/saml2-model/Interop/keycloak/capture.sh', $output]);
        }
        if ($exchange) {
            io()->section('Exchange: the model against Keycloak, both ways');
            saml2_model_keycloak_exchange($output, $model);
        }
        if ($verify) {
            io()->section('xmlsec1: the documents the model wrote');
            $identityProvider = glob($model . '/model-idp-*.xml') ?: [];
            $serviceProvider = glob($model . '/model-sp-*.xml') ?: [];
            if ($identityProvider === [] || $serviceProvider === []) {
                io()->error('No document of the model in ' . $model . ': run the exchange first.');
                exit(1);
            }
            saml2_model_xmlsec1($identityProvider, 'tests/saml2-model/Fixture/keys/idp-signing-certificate.pem');
            saml2_model_xmlsec1($serviceProvider, 'tests/saml2-model/Fixture/keys/sp-signing-certificate.pem');
            io()->section('xmlsec1: the signatures of Keycloak\'s documents in ' . $output);
            in_alpine(
                'apk add -q xmlsec libxml2-utils openssl >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/keycloak/verify.sh '
                    . escapeshellarg($output),
                ['tests/saml2-model/Interop/keycloak/verify.sh', $output],
            );
        }
    } finally {
        if ($down) {
            run(['docker', 'compose', '-f', SAML2_MODEL_KEYCLOAK_COMPOSE, 'down']);
        }
    }
}

/**
 * Runs exchange.php in the phpqa image, inside the network namespace of the Keycloak container: localhost:8180 is
 * Keycloak there, the host and the port of every URL Keycloak builds and checks.
 */
function saml2_model_keycloak_exchange(string $output, string $model): void
{
    $container = trim(capture(
        ['docker', 'compose', '-f', SAML2_MODEL_KEYCLOAK_COMPOSE, 'ps', '-q', 'keycloak'],
        context()->withQuiet()->withAllowFailure(),
        onFailure: '',
    ));
    if ($container === '') {
        io()->error('Keycloak is not running: castor saml2-model-keycloak --up.');
        exit(1);
    }

    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '-i',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '--network',
        'container:' . $container,
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        '-e',
        'XDEBUG_MODE=off',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', saml2_interop_php_version()),
        'php',
        'tests/saml2-model/Interop/keycloak/exchange.php',
        $output,
        $model,
    ]);
}

/**
 * The PHP of the image the exchanges of the SAML judges run in, saml2-model's and saml2-bindings': the one PHP_VERSION
 * names, as for every task of the repository, 8.5 when it names none, the PHP the README of each judge measured with.
 */
function saml2_interop_php_version(): string
{
    return getenv('PHP_VERSION') ?: '8.5';
}
