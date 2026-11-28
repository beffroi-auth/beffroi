<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses.')]
function check_licenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0'],
): void {
    io()->title('Checking licenses');
    $allowedExceptions = [];
    $command = ['composer', 'licenses', '-f', 'json'];
    $context = context();
    $context->withEnvironment([
        'XDEBUG_MODE' => 'off',
    ]);
    $context->withQuiet();
    $result = run($command, context: $context);
    if (! $result->isSuccessful()) {
        io()->error('Cannot determine licenses');
        exit(1);
    }
    $licenses = json_decode((string) $result->getOutput(), true);
    $disallowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => ! in_array($name, $allowedExceptions, true) && count(array_diff($info['license'], $allowedLicenses)) === 1,
        \ARRAY_FILTER_USE_BOTH,
    );
    $allowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => in_array($name, $allowedExceptions, true) || count(array_diff($info['license'], $allowedLicenses)) === 0,
        \ARRAY_FILTER_USE_BOTH,
    );
    if (count($disallowed) > 0) {
        io()->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                array_keys($disallowed),
                $disallowed,
            ),
        );
        io()->error('Disallowed licenses found');
        exit(1);
    }
    io()->table(
        ['Package', 'License'],
        array_map(
            static fn ($name, $info) => [$name, implode(', ', $info['license'])],
            array_keys($allowed),
            $allowed,
        ),
    );
    io()->success('All licenses are allowed');
}

/**
 * In a worktree, ".git" points into the common directory by an absolute path of the host, which the mount of the
 * working directory does not cover: phpqa() mounts it at that very path.
 */
function git_common_directory(): ?string
{
    $output = shell_exec('git rev-parse --git-common-dir 2>/dev/null');
    if (! is_string($output) || trim($output) === '') {
        return null;
    }

    $common = realpath(trim($output));
    $workingDirectory = realpath(getcwd());
    if ($common === false || $workingDirectory === false) {
        return null;
    }

    if (str_starts_with($common . \DIRECTORY_SEPARATOR, $workingDirectory . \DIRECTORY_SEPARATOR)) {
        return null;
    }

    return $common;
}

/**
 * Runs a command in the phpqa image, or directly when already inside a container (CI) or without Docker.
 *
 * @param array<string> $command
 * @param array<string, string> $environment
 * @param string|null $phpIniDirectory relative to the repository, read after the image's own conf.d
 * @param string|null $workingDirectory relative to the repository
 */
function phpqa(
    array $command,
    array $environment = [],
    ?string $phpIniDirectory = null,
    ?string $workingDirectory = null,
    bool $hostNetwork = false,
): void {
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim(shell_exec('command -v docker') ?? '') !== '';
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;
    $environment += [
        'XDEBUG_MODE' => 'off',
        // The tests take longer than the 300 s composer allows a script by default; the runner decides when to stop.
        'COMPOSER_PROCESS_TIMEOUT' => '0',
    ];

    if (! $hasDocker || $inContainer) {
        // A leading colon keeps the directory PHP was compiled to scan: this adds to the image's configuration.
        if ($phpIniDirectory !== null) {
            $environment['PHP_INI_SCAN_DIR'] = ':' . getcwd() . '/' . $phpIniDirectory;
        }
        $context = context()->withEnvironment($environment);
        if ($workingDirectory !== null) {
            $context = $context->withWorkingDirectory(getcwd() . '/' . $workingDirectory);
        }
        run($command, context: $context);
        return;
    }

    $gitCommonDirectory = git_common_directory();

    // No TMPDIR: the test kernel dumps its container in /tmp and boots with APP_DEBUG=0, where Symfony reuses a
    // dumped container without checking its configuration, so it must not outlive the run.
    $dockerOptions = [
        '--rm',
        '--init',
        stream_isatty(\STDOUT) ? '-it' : '-i',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-v',
        getcwd() . ':/project',
        '-w',
        $workingDirectory === null ? '/project' : '/project/' . $workingDirectory,
        // The development stack publishes its PostgreSQL on the loopback address of the machine.
        ...($hostNetwork ? ['--network', 'host'] : []),
        ...($gitCommonDirectory === null ? [] : ['-v', sprintf('%s:%s:ro', $gitCommonDirectory, $gitCommonDirectory)]),
        '-e',
        $phpIniDirectory === null
            ? 'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d'
            : 'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d:/project/' . $phpIniDirectory,
    ];
    foreach ($environment as $name => $value) {
        $dockerOptions[] = '-e';
        $dockerOptions[] = $name . '=' . $value;
    }

    run([
        'docker',
        'run',
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', $phpVersion),
        ...$command,
    ]);
}

#[AsTask(description: 'Update the PHPQA Docker image')]
function phpqa_update(): void
{
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;

    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . $phpVersion]);
}

#[AsTask(
    description: 'Print the PHP, libxml and OpenSSL versions and whether LIBXML_NO_XXE and OPENSSL_PKCS1_PSS_PADDING are defined: what the corpus of the SAML packages can and cannot exercise on this build (spec/core.md section 12, spec/dsig.md section 10)',
)]
function libxml(): void
{
    phpqa([
        'php',
        '-r',
        'printf("PHP %s, libxml %s, LIBXML_NO_XXE %s, %s, OPENSSL_PKCS1_PSS_PADDING %s\n", PHP_VERSION, LIBXML_DOTTED_VERSION, defined("LIBXML_NO_XXE") ? "defined" : "undefined", OPENSSL_VERSION_TEXT, defined("OPENSSL_PKCS1_PSS_PADDING") ? "defined" : "undefined");',
    ]);
}

#[AsTask(description: 'Run PHPUnit tests with coverage', ignoreValidationErrors: true)]
function phpunit(
    #[AsOption(
        description: 'Run the test files in parallel processes, through paratest, which merges the coverage of its workers itself; "auto" is what it makes of the cores it finds. One process is PHPUnit itself, which is what debugging a single test wants',
    )]
    string $processes = '1',
    #[AsOption(
        description: 'Measure nothing, pcov left off and no report written: what a run nobody reads the coverage of wants, and what an image without pcov needs, paratest choosing a driver as soon as a report is asked of it',
    )]
    bool $noCoverage = false,
    #[AsRawTokens]
    array $args = [],
): void {
    // Paratest and not shards: PHPUnit refuses to merge the XML coverage reports the mutation job reads.
    $parallel = $processes !== '1';

    phpqa(
        [
            'composer',
            'exec',
            '--',
            $parallel ? 'paratest' : 'phpunit',
            ...($parallel ? ['--processes=' . $processes] : []),
            ...($noCoverage ? [] : ['--coverage-xml', '.ci-tools/coverage', '--log-junit=.ci-tools/coverage/junit.xml']),
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        // XDEBUG_MODE stays "off": php-code-coverage measures with pcov whenever it is enabled.
        [],
        $noCoverage ? null : '.ci-tools/php/coverage',
    );
}

#[AsTask(
    description: 'Run the suite of the standalone application: its own kernel, on the PostgreSQL that DATABASE_URL names and the KMS of apps/beffroi/.env.test, the schema written by the migrations of the provider before the first test. It needs a PostgreSQL reachable from the machine, which "castor start" publishes on the loopback address',
    ignoreValidationErrors: true,
)]
function app_phpunit(#[AsRawTokens] array $args = []): void
{
    io()->title('Running the suite of the application');

    application_console(['doctrine:database:create', '--if-not-exists']);
    application_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);

    // The PHPUnit of the image, not "composer exec": the "vendor/bin" of the application carries none.
    application_phpqa(['phpunit', '--configuration', 'phpunit.dist.xml', ...$args]);
}

/**
 * @param array<string> $args
 */
function application_console(array $args): void
{
    application_phpqa(['php', 'bin/console', ...$args], [
        'APP_ENV' => 'test',
        'APP_DEBUG' => '0',
    ]);
}

/**
 * @param array<string> $command
 * @param array<string, string> $environment
 */
function application_phpqa(array $command, array $environment = []): void
{
    assert_application_installed();

    phpqa($command, $environment, workingDirectory: 'apps/beffroi', hostNetwork: true);
}

function application_context(): Context
{
    assert_application_installed();

    return context()->withWorkingDirectory(getcwd() . '/apps/beffroi');
}

function assert_application_installed(): void
{
    if (is_file(getcwd() . '/apps/beffroi/vendor/autoload.php')) {
        return;
    }

    io()->error('The application is not installed: run "(cd apps/beffroi && composer install)" first.');
    exit(1);
}

/**
 * The static binary of Castor reports no PHP_BINARY: the PHP of the PATH stands in.
 */
function application_php(): string
{
    return \PHP_BINARY === '' ? 'php' : \PHP_BINARY;
}

#[AsTask(description: 'Check the formatting with Mago')]
function mago_format(): void
{
    phpqa(['mago', 'format', '--check']);
}

#[AsTask(description: 'Format the code with Mago')]
function mago_format_fix(): void
{
    phpqa(['mago', 'format']);
}

#[AsTask(description: 'Run the Mago linter')]
function mago_lint(): void
{
    phpqa(['mago', 'lint']);
}

#[AsTask(description: 'Apply the fixes the Mago linter offers')]
function mago_lint_fix(): void
{
    phpqa(['mago', 'lint', '--fix']);
}

#[AsTask(description: 'Run the Mago analyzer. Informative only: PHPStan at level max is what the CI gates on, and the two do not find the same things')]
function mago_analyze(#[AsRawTokens] array $args = []): void
{
    phpqa(['mago', 'analyze', ...$args]);
}

#[AsTask(description: 'Run Rector dry-run')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

const PHPSTAN_CONFIGURATIONS = [
    '.ci-tools/phpstan.neon',
    '.ci-tools/phpstan-xml-security.neon',
    '.ci-tools/phpstan-saml2-model.neon',
    '.ci-tools/phpstan-saml2-bindings.neon',
    '.ci-tools/phpstan-saml.neon',
];

#[AsTask(description: 'Run PHPStan, the identity provider\'s packages and then each SAML package')]
function phpstan(): void
{
    foreach (PHPSTAN_CONFIGURATIONS as $configuration) {
        phpqa([
            'composer',
            'exec',
            '--',
            'phpstan',
            'analyse',
            '--error-format=github',
            '--configuration=' . $configuration,
        ]);
    }
    phpstan_saml_rules();
}

const PHPSTAN_SAML_RULES_FIXTURE = 'tests/saml/PhpStan/Fixture';

const PHPSTAN_SAML_RULES_CONFIGURATION = '.ci-tools/phpstan-saml-rules.neon';

const PHPSTAN_SAML_RULES_REPORT = '.ci-tools/cache/phpstan-saml-rules/report.json';

const PHPSTAN_SAML_RULES_IDENTIFIERS = [
    'beffroi.bannedCall',
    'beffroi.bannedName',
    'ekinoBannedCode.function',
    'ekinoBannedCode.expression',
];

#[AsTask(
    description: 'Prove the bans of beffroi/saml (section 8): PHPStan with its rules on tests/saml/PhpStan/Fixture, whose lines say what each must report; fails on a refusal missing and on one nobody expected',
)]
function phpstan_saml_rules(): void
{
    io()->section('Proving the bans of beffroi/saml on their fixture');
    $report = PHPSTAN_SAML_RULES_REPORT;
    if (! is_dir(dirname($report))) {
        mkdir(dirname($report), 0o777, true);
    }
    // A report left by an earlier run is never read as this one's.
    if (is_file($report)) {
        unlink($report);
    }

    // PHPStan exits with 1 when it reports errors, the point here, and above 1 when it fails; the shell writes the
    // report, since phpqa() captures no output.
    phpqa([
        'sh',
        '-c',
        sprintf(
            'phpstan analyse --no-progress --error-format=json --configuration=%s > %s; status=$?; [ "$status" -le 1 ]',
            PHPSTAN_SAML_RULES_CONFIGURATION,
            $report,
        ),
    ]);

    $analysis = is_file($report) ? json_decode((string) file_get_contents($report), true) : null;
    if (! is_array($analysis) || ! is_array($analysis['files'] ?? null) || ! is_array($analysis['errors'] ?? null)) {
        io()->error('PHPStan left no readable report in ' . $report);
        exit(1);
    }

    $expected = phpstan_saml_rules_expected();
    $reported = [];
    $broken = array_map(static fn (mixed $error): string => (string) json_encode($error), $analysis['errors']);
    foreach ($analysis['files'] as $file => $result) {
        foreach ($result['messages'] ?? [] as $message) {
            $identifier = (string) ($message['identifier'] ?? '');
            $line = sprintf('%s:%d %s', phpstan_saml_rules_relative((string) $file), $message['line'] ?? 0, $message['message']);
            if (in_array($identifier, PHPSTAN_SAML_RULES_IDENTIFIERS, true)) {
                // A set and not a count: PHPStan visits a nullsafe call twice.
                $reported[$line] = true;
            } elseif ($identifier === '' || str_starts_with($identifier, 'phpstan.')) {
                // A parse error or a message without an identifier: the fixture was not read.
                $broken[] = $line;
            }
        }
    }

    $missing = array_keys(array_diff_key($expected, $reported));
    $unexpected = array_keys(array_diff_key($reported, $expected));
    sort($missing);
    sort($unexpected);
    if ($expected === []) {
        $broken[] = 'the fixture expects nothing: no line of ' . PHPSTAN_SAML_RULES_FIXTURE . ' carries "// error: "';
    }
    if ($missing === [] && $unexpected === [] && $broken === []) {
        io()->success(sprintf('%d refusals expected, %d reported, the same ones.', count($expected), count($reported)));

        return;
    }

    foreach ([
        'Expected by the fixture and not reported (a rule stopped firing, or a line moved)' => $missing,
        'Reported and not expected (a rule fires on what it let through, or a line moved)' => $unexpected,
        'PHPStan could not read the fixture' => $broken,
    ] as $title => $lines) {
        if ($lines !== []) {
            io()->error($title);
            io()->listing($lines);
        }
    }

    exit(1);
}

/**
 * What the lines of the fixture say they must be refused with: "file:line message", from each "// error: message".
 *
 * @return array<string, true>
 */
function phpstan_saml_rules_expected(): array
{
    $expected = [];
    $files = glob(getcwd() . '/' . PHPSTAN_SAML_RULES_FIXTURE . '/*.php');
    foreach ($files === false ? [] : $files as $file) {
        foreach (file($file, \FILE_IGNORE_NEW_LINES) ?: [] as $number => $line) {
            // A marker ends a line of code; the comments that explain the fixture may quote one.
            if (preg_match('~^\s*(\*|/\*|//)~', $line) === 1) {
                continue;
            }
            preg_match_all('~// error: (.+?)(?=\s// error: |$)~', $line, $matches);
            foreach ($matches[1] as $message) {
                $expected[sprintf('%s:%d %s', phpstan_saml_rules_relative($file), $number + 1, $message)] = true;
            }
        }
    }

    return $expected;
}

function phpstan_saml_rules_relative(string $path): string
{
    $position = strpos($path, PHPSTAN_SAML_RULES_FIXTURE . '/');

    return $position === false ? $path : substr($path, $position);
}

#[AsTask(description: 'Generate PHPStan baseline')]
function phpstan_baseline(): void
{
    phpqa([
        'composer',
        'exec',
        '--',
        'phpstan',
        'analyse',
        '--configuration=.ci-tools/phpstan.neon',
        '--generate-baseline=.ci-tools/phpstan-baseline.neon',
        '--allow-empty-baseline',
    ]);
}

#[AsTask(description: 'Run Deptrac')]
function deptrac(): void
{
    phpqa([
        'composer',
        'exec',
        '--',
        'deptrac',
        '--config-file',
        '.ci-tools/deptrac.yaml',
        '--report-uncovered',
        '--report-skipped',
        '--fail-on-uncovered',
    ]);
}

const GENERATED_CONFIGURATION = [
    'apps/beffroi/config/reference.php',
    'apps/beffroi/config/schema.json',
];

#[AsTask(
    description: 'Check that the generated configuration reference and schema of the application, as git holds them, still say what the configuration trees of its bundles declare',
)]
function config_reference(): void
{
    io()->title('Checking the generated configuration reference and schema');

    $committed = committed_configuration();
    $onDisk = generated_configuration();
    regenerate_generated_configuration();
    $regenerated = generated_configuration();

    $behind = [];
    foreach (GENERATED_CONFIGURATION as $file) {
        if ($regenerated[$file] !== $committed[$file]) {
            $behind[] = $file;
            run(['git', '--no-pager', 'diff', '--', $file], context: context()->withAllowFailure());
        }

        if ($regenerated[$file] !== $onDisk[$file]) {
            file_put_contents(getcwd() . '/' . $file, $onDisk[$file]);
        }
    }

    if ($behind === []) {
        io()->success('The reference and the schema are what the bundles of the application declare.');

        return;
    }

    io()->error(sprintf(
        'Behind the configuration trees they are generated from: %s. Run "castor config-reference-fix" and commit the result.',
        implode(', ', $behind),
    ));
    exit(1);
}

#[AsTask(
    description: 'Regenerate the configuration reference and schema of the application from the configuration trees of its bundles',
)]
function config_reference_fix(): void
{
    regenerate_generated_configuration();
    io()->success('The reference and the schema are written again; commit them with the change that moved the trees.');
}

/**
 * The index of git rather than the disk, which any debug boot of the kernel rewrites: the boot step of the Application
 * workflow, a stack or a console on a desk.
 *
 * @return array<string, string> content by path
 */
function committed_configuration(): array
{
    $contents = [];
    foreach (GENERATED_CONFIGURATION as $file) {
        $contents[$file] = run(['git', '--no-pager', 'show', ':' . $file], context: context()->withQuiet())->getOutput();
    }

    return $contents;
}

/**
 * @return array<string, string> content by path
 */
function generated_configuration(): array
{
    $contents = [];
    foreach (GENERATED_CONFIGURATION as $file) {
        $path = getcwd() . '/' . $file;
        $content = is_file($path) ? file_get_contents($path) : false;
        $contents[$file] = $content === false ? '' : $content;
    }

    return $contents;
}

/**
 * On the host, with the PHP that made its Composer install: "cache:clear" compiles the container whatever the
 * state of the cache, and only a debug compilation writes the two files.
 */
function regenerate_generated_configuration(): void
{
    run([application_php(), 'bin/console', 'cache:clear'], context: application_context()->withEnvironment([
        'APP_ENV' => 'dev',
        'APP_DEBUG' => '1',
    ]));
}

/**
 * Section 9 of spec/core.md, spec/dsig.md, spec/enc.md, spec/model.md, spec/bindings.md and spec/saml.md
 */
const INFECTION_STRICT_FILES = [
    'src/xml-security/src/Core/Loader.php',
    'src/xml-security/src/Core/Internal/Inspector.php',
    'src/xml-security/src/Core/Canonicalizer.php',
    'src/xml-security/src/Core/Text.php',
    'src/xml-security/src/Core/Children.php',
    'src/xml-security/src/Core/CanonicalXml.php',
    'src/xml-security/src/Core/Serializer.php',
    'src/xml-security/src/Dsig/Signature.php',
    'src/xml-security/src/Dsig/SignedInfo.php',
    'src/xml-security/src/Dsig/Reference.php',
    'src/xml-security/src/Dsig/SignatureAlgorithm.php',
    'src/xml-security/src/Dsig/DigestAlgorithm.php',
    'src/xml-security/src/Dsig/Internal/Base64.php',
    'src/xml-security/src/Dsig/Internal/Structure.php',
    'src/xml-security/src/Dsig/Internal/Pem.php',
    'src/xml-security/src/Dsig/Verifier.php',
    'src/xml-security/src/Dsig/Verified.php',
    'src/xml-security/src/Dsig/VerificationKey.php',
    'src/xml-security/src/Dsig/VerificationKeys.php',
    'src/xml-security/src/Dsig/Signer.php',
    'src/xml-security/src/Dsig/PrivateKey.php',
    'src/xml-security/src/Enc/ContentAlgorithm.php',
    'src/xml-security/src/Enc/CbcContentAlgorithm.php',
    'src/xml-security/src/Enc/OaepHash.php',
    'src/xml-security/src/Enc/KeyTransport.php',
    'src/xml-security/src/Enc/EncryptedData.php',
    'src/xml-security/src/Enc/EncryptedKey.php',
    'src/xml-security/src/Enc/Internal/Base64.php',
    'src/xml-security/src/Enc/Internal/Structure.php',
    'src/xml-security/src/Enc/Internal/CipherData.php',
    'src/xml-security/src/Enc/Internal/Pem.php',
    'src/xml-security/src/Enc/Internal/BlockPadding.php',
    'src/xml-security/src/Enc/Decryptor.php',
    'src/xml-security/src/Enc/PrivateDecryptionKey.php',
    'src/xml-security/src/Enc/Encryptor.php',
    'src/xml-security/src/Enc/PeerKey.php',
    'src/saml2-model/src/Exception/MessageRefused.php',
    'src/saml2-model/src/Exception/MalformedMessage.php',
    'src/saml2-model/src/Exception/Unsupported.php',
    'src/saml2-model/src/Exception/SignatureRequired.php',
    'src/saml2-model/src/Exception/IssuerMismatch.php',
    'src/saml2-model/src/Exception/AudienceMismatch.php',
    'src/saml2-model/src/Exception/RecipientMismatch.php',
    'src/saml2-model/src/Exception/DestinationMismatch.php',
    'src/saml2-model/src/Exception/UnknownEndpoint.php',
    'src/saml2-model/src/Exception/InResponseToMismatch.php',
    'src/saml2-model/src/Exception/Replayed.php',
    'src/saml2-model/src/Exception/InvalidNameId.php',
    'src/saml2-model/src/Exception/IndeterminateCondition.php',
    'src/saml2-model/src/Exception/UnsuccessfulResponse.php',
    'src/saml2-model/src/Exception/OutsideValidityWindow.php',
    'src/saml2-model/src/Exception/LimitExceeded.php',
    'src/saml2-model/src/Protocol/StatusCode.php',
    'src/saml2-model/src/Protocol/SecondLevelStatusCode.php',
    'src/saml2-model/src/Protocol/Status.php',
    'src/saml2-model/src/Value/Time.php',
    'src/saml2-model/src/Value/Boolean.php',
    'src/saml2-model/src/Value/SamlId.php',
    'src/saml2-model/src/Value/Uri.php',
    'src/saml2-model/src/Value/Version.php',
    'src/saml2-model/src/Value/UnsignedShort.php',
    'src/saml2-model/src/Value/Counts.php',
    'src/saml2-model/src/Value/Characters.php',
    'src/saml2-model/src/Assertion/NameId.php',
    'src/saml2-model/src/Validation/TimeBounds.php',
    'src/saml2-model/src/Validation/Authentication.php',
    'src/saml2-model/src/Metadata/IndexedEndpoints.php',
    'src/saml2-model/src/Metadata/MetadataReader.php',
    'src/saml2-model/src/Internal/Schema.php',
    'src/saml2-model/src/Internal/Particle.php',
    'src/saml2-model/src/Internal/Window.php',
    'src/saml2-model/src/Internal/Metadata/EndpointReader.php',
    'src/saml2-model/src/Internal/Metadata/EntityDescriptorReader.php',
    'src/saml2-model/src/Internal/Metadata/KeyDescriptorReader.php',
    'src/saml2-model/src/Internal/Metadata/RoleReader.php',
    'src/saml2-model/src/Internal/Metadata/RoleRules.php',
    'src/saml2-model/src/Internal/Protocol/MessageAuthentication.php',
    'src/saml2-model/src/Internal/Protocol/StatusReader.php',
    'src/saml2-model/src/Internal/Assertion/AssertionContext.php',
    'src/saml2-model/src/Internal/Assertion/IssuerReader.php',
    'src/saml2-model/src/Internal/Assertion/NameIdReader.php',
    'src/saml2-model/src/Internal/Assertion/HeaderReader.php',
    'src/saml2-model/src/Internal/Assertion/SubjectReader.php',
    'src/saml2-model/src/Internal/Assertion/ConditionsReader.php',
    'src/saml2-model/src/Internal/Assertion/AuthnStatementReader.php',
    'src/saml2-model/src/Internal/Assertion/AttributeStatementReader.php',
    'src/saml2-model/src/Internal/Assertion/AssertionReader.php',
    'src/saml2-model/src/Internal/Response/Envelope.php',
    'src/saml2-model/src/Internal/Response/SignedResponse.php',
    'src/saml2-model/src/Internal/Response/DecryptedAssertion.php',
    'src/saml2-model/src/Internal/Response/CoveringResponseSignature.php',
    'src/saml2-model/src/Internal/Response/PlaintextReader.php',
    'src/saml2-model/src/Internal/Response/ReadAssertion.php',
    'src/saml2-model/src/Internal/Response/SignedAssertion.php',
    'src/saml2-model/src/Internal/Response/EnvelopeReader.php',
    'src/saml2-model/src/Protocol/UnverifiedResponse.php',
    'src/saml2-model/src/Protocol/Response.php',
    'src/saml2-model/src/Validation/ExpectedResponse.php',
    'src/saml2-model/src/Validation/SignatureCoverage.php',
    'src/saml2-model/src/Validation/AcceptedAssertion.php',
    'src/saml2-model/src/Validation/ResponseValidator.php',
    'src/saml2-model/src/Internal/AuthnRequest/AssertionConsumerService.php',
    'src/saml2-model/src/Internal/AuthnRequest/AuthnRequestContext.php',
    'src/saml2-model/src/Internal/AuthnRequest/AuthnRequestReader.php',
    'src/saml2-model/src/Internal/AuthnRequest/NameIdPolicyReader.php',
    'src/saml2-model/src/Internal/AuthnRequest/RequestedAuthnContextReader.php',
    'src/saml2-model/src/Validation/AuthnRequestValidator.php',
    'src/saml2-model/src/Validation/AcceptedAuthnRequest.php',
    'src/saml2-model/src/Internal/Writing/Tree.php',
    'src/saml2-model/src/Internal/Writing/NameIdBuilder.php',
    'src/saml2-model/src/Internal/Writing/StatusBuilder.php',
    'src/saml2-model/src/Internal/Writing/AssertionBuilder.php',
    'src/saml2-model/src/Internal/Writing/ResponseBuilder.php',
    'src/saml2-model/src/Writing/SignedParts.php',
    'src/saml2-model/src/Writing/ResponseWriter.php',
    'src/saml2-model/src/Writing/AuthnRequestWriter.php',
    'src/saml2-model/src/Writing/MetadataWriter.php',
    'src/saml/src/Domain/Metadata/Certificate.php',
    'src/saml/src/Domain/Metadata/IdentityProviderDescription.php',
    'src/saml/src/Domain/Metadata/PublishedMetadata.php',
    'src/saml/src/Application/Metadata/SigningCertificates.php',
    'src/saml/src/Application/Metadata/IdentityProviderMetadataHandler.php',
    'src/saml/src/Bridge/Model/ModelMetadataWriter.php',
    'src/saml/src/Domain/Metadata/ServiceProviderEndpoints.php',
    'src/saml/src/Domain/Metadata/ServiceProviderDescription.php',
    'src/saml/src/Application/Metadata/ServiceProviderMetadataHandler.php',
    'src/saml/src/Bridge/Model/ModelServiceProviderMetadataWriter.php',
    'src/saml/src/Bridge/Model/ModelEntityId.php',
    'src/saml/src/Domain/Key/UpstreamEncryptionKeys.php',
    'src/saml/src/Application/Metadata/BuiltCertificates.php',
    'src/saml/src/Application/Metadata/EncryptionCertificates.php',
    'src/saml/src/Bridge/Model/UpstreamDecryptionKeys.php',
    'src/saml/src/Bridge/Model/ProviderDecryptionKey.php',
    'src/saml/src/Domain/Metadata/AcceptedMetadata.php',
    'src/saml/src/Domain/Metadata/Lexical.php',
    'src/saml/src/Domain/Metadata/MetadataLocation.php',
    'src/saml/src/Domain/ServiceProvider/AcceptedServiceProviderMetadata.php',
    'src/saml/src/Domain/ServiceProvider/AttributeMapping.php',
    'src/saml/src/Domain/ServiceProvider/AttributeNameFormat.php',
    'src/saml/src/Domain/ServiceProvider/ServiceProvider.php',
    'src/saml/src/Domain/ServiceProvider/ServiceProviderMetadata.php',
    'src/saml/src/Application/Metadata/MetadataRefreshment.php',
    'src/saml/src/Application/Metadata/MetadataRefresh.php',
    'src/saml/src/Application/Metadata/AcceptedMetadataForgetting.php',
    'src/saml/src/Application/ServiceProvider/ServiceProviderRole.php',
    'src/saml/src/Bridge/Model/MetadataDocumentReader.php',
    'src/saml/src/Bridge/Model/ModelServiceProviderMetadataReader.php',
    'src/saml/src/Bridge/Configuration/ConfigurationServiceProviders.php',
    'src/saml/src/Bridge/Configuration/DeclarationMembers.php',
    'src/saml/src/Domain/Upstream/AcceptedUpstreamMetadata.php',
    // The domain of S-44, which belongs to the core (S-60): strict_coverage() runs the suite of the core for it.
    'src/core/src/Domain/Identity/EmailDomain.php',
    'src/saml/src/Domain/Upstream/GroupMapping.php',
    'src/saml/src/Domain/Upstream/ProfileAttribute.php',
    'src/saml/src/Domain/Upstream/UpstreamIdentityProvider.php',
    'src/saml/src/Domain/Upstream/UpstreamMetadata.php',
    'src/saml/src/Application/Upstream/UpstreamIdentityProviderRole.php',
    'src/saml/src/Bridge/Model/ModelUpstreamMetadataReader.php',
    'src/saml/src/Bridge/Configuration/ConfigurationUpstreamIdentityProviders.php',
    'src/saml/src/Domain/Upstream/UpstreamAuthnRequest.php',
    'src/saml/src/Domain/Upstream/SentAuthnRequest.php',
    'src/saml/src/Domain/Upstream/AddressHint.php',
    'src/saml/src/Application/Upstream/UpstreamSignOn.php',
    'src/saml/src/Bridge/Model/ModelAuthnRequestSender.php',
    'src/saml/src/Domain/Upstream/VerifiedAssertion.php',
    'src/saml/src/Domain/Upstream/UpstreamAssertion.php',
    'src/saml/src/Domain/Upstream/AuthnContextMethods.php',
    'src/saml/src/Application/Upstream/AssertionConsumerService.php',
    'src/saml/src/Bridge/Model/ModelResponseReceiver.php',
    'src/saml/src/Domain/ServiceProvider/AuthnRequestSigning.php',
    'src/saml/src/Bridge/Model/ModelAuthnRequestParties.php',
    'src/saml/src/Domain/SingleSignOn/AttributeValue.php',
    'src/saml/src/Domain/SingleSignOn/PersistentNameId.php',
    'src/saml/src/Domain/SingleSignOn/PostedForm.php',
    'src/saml/src/Domain/SingleSignOn/ReleasedAttribute.php',
    'src/saml/src/Domain/SingleSignOn/SignOnFailure.php',
    'src/saml/src/Domain/SingleSignOn/SignOnRequest.php',
    'src/saml/src/Domain/SingleSignOn/SignOnResponse.php',
    'src/saml/src/Domain/SingleSignOn/SignOnStatus.php',
    'src/saml/src/Application/SingleSignOn/AttributeRelease.php',
    'src/saml/src/Application/SingleSignOn/SingleSignOn.php',
    'src/saml/src/Bridge/Model/ModelAuthnRequestReceiver.php',
    'src/saml/src/Bridge/Model/ModelIdentityProvider.php',
    'src/saml/src/Bridge/Model/ModelSignOnResponder.php',
    'src/saml/src/Domain/SingleLogout/SignOutRequest.php',
    'src/saml/src/Domain/SingleLogout/SignOutStatus.php',
    'src/saml/src/Domain/SingleLogout/SignOutResponse.php',
    'src/saml/src/Domain/SingleLogout/RedirectedMessage.php',
    'src/saml/src/Domain/SingleLogout/SessionParticipation.php',
    'src/saml/src/Domain/Replay/RememberedMessage.php',
    'src/saml/src/Domain/Event/ServiceProviderSignedIn.php',
    'src/saml/src/Application/SingleLogout/SingleLogout.php',
    'src/saml/src/Application/SingleLogout/SessionParticipants.php',
    'src/saml/src/Bridge/Model/DeclaredServiceProviderReader.php',
    'src/saml/src/Bridge/Model/ModelLogoutMessageReceiver.php',
    'src/saml/src/Bridge/Model/ModelSignOutResponder.php',
    'src/saml/src/Bridge/Model/TenantReplayGuard.php',
    'src/saml/src/Bridge/Model/TenantSigning.php',
    'src/saml/src/Domain/SingleLogout/LogoutRequester.php',
    'src/saml/src/Domain/SingleLogout/LogoutHop.php',
    'src/saml/src/Domain/SingleLogout/LogoutProgress.php',
    'src/saml/src/Domain/SingleLogout/LogoutChain.php',
    'src/saml/src/Domain/SingleLogout/LogoutChainStarted.php',
    'src/saml/src/Domain/SingleLogout/LogoutChainEnded.php',
    'src/saml/src/Domain/SingleLogout/SignOutNotice.php',
    'src/saml/src/Domain/SingleLogout/SentSignOutNotice.php',
    'src/saml/src/Domain/SingleLogout/SignOutAnswer.php',
    'src/saml/src/Application/SingleLogout/ProviderLogout.php',
    'src/saml/src/Bridge/Model/ModelSignOutNotifier.php',
    'src/saml2-model/src/Writing/LogoutRequestWriter.php',
    'src/saml2-model/src/Writing/LogoutResponseWriter.php',
    'src/saml2-model/src/Internal/Logout/Envelope.php',
    'src/saml2-model/src/Internal/Logout/LogoutContext.php',
    'src/saml2-model/src/Internal/Logout/LogoutRequestReader.php',
    'src/saml2-model/src/Internal/Logout/LogoutResponseReader.php',
    'src/saml2-model/src/Internal/Logout/ReplayWindow.php',
    'src/saml2-model/src/Validation/LogoutRequestValidator.php',
    'src/saml2-model/src/Validation/LogoutResponseValidator.php',
    'src/saml2-model/src/Validation/AcceptedLogoutRequest.php',
    'src/saml2-model/src/Validation/AcceptedLogoutResponse.php',
    'src/saml2-bindings/src/BindingLimits.php',
    'src/saml2-bindings/src/Exception/BindingRefused.php',
    'src/saml2-bindings/src/Exception/MalformedParameters.php',
    'src/saml2-bindings/src/Exception/MalformedEncoding.php',
    'src/saml2-bindings/src/Exception/InvalidRelayState.php',
    'src/saml2-bindings/src/Exception/XmlSignatureRefused.php',
    'src/saml2-bindings/src/Exception/NoVerificationKey.php',
    'src/saml2-bindings/src/Exception/Unsupported.php',
    'src/saml2-bindings/src/Exception/LimitExceeded.php',
    'src/saml2-bindings/src/Internal/Percent.php',
    'src/saml2-bindings/src/Internal/Base64.php',
    'src/saml2-bindings/src/Internal/DestinationScheme.php',
    'src/saml2-bindings/src/Internal/Inflater.php',
    'src/saml2-bindings/src/Internal/Deflater.php',
    'src/saml2-bindings/src/Internal/SignedOctets.php',
    'src/saml2-bindings/src/Internal/DetachedSignature.php',
    'src/saml2-bindings/src/Internal/QueryParameters.php',
    'src/saml2-bindings/src/Internal/FormFields.php',
    'src/saml2-bindings/src/Internal/Reception.php',
    'src/saml2-bindings/src/Internal/Service.php',
    'src/saml2-bindings/src/RedirectReceiver.php',
    'src/saml2-bindings/src/PostReceiver.php',
    'src/saml2-bindings/src/RedirectSender.php',
    'src/saml2-bindings/src/PostSender.php',
    'src/saml2-bindings/src/PostForm.php',
    'src/saml2-bindings/src/ReceivedAuthnRequest.php',
    'src/saml2-bindings/src/ReceivedLogoutRequest.php',
    'src/saml2-bindings/src/ReceivedLogoutResponse.php',
    'src/saml2-bindings/src/ReceivedResponse.php',
];

#[AsTask(
    description: 'Run Infection for mutation testing, on the coverage produced by a fresh PHPUnit run. --diff keeps only the mutants of the lines added or modified since the base branch, the shape of every CI run; --strict mutates the files the specifications of the SAML packages hold to a hundred percent; without either the whole source is mutated, which takes hours',
)]
function infect(
    int $minMsi = 0,
    int $minCoveredMsi = 0,
    #[AsOption(description: 'Mutate only the lines added or modified since --base, committed or not')]
    bool $diff = false,
    #[AsOption(
        description: 'Mutate the files of INFECTION_STRICT_FILES whole, uncovered lines included, and fail under a hundred percent, whatever --min-msi and --min-covered-msi say, on a coverage of its own: the suites of the SAML packages and of the core measured by Xdebug in .ci-tools/coverage-strict',
    )]
    bool $strict = false,
    #[AsOption(
        description: 'The branch or commit the diff of --diff is taken from; Infection narrows it to the merge base with HEAD. The default is the maintenance branch the clone points at, which a clone sets and "git remote set-head origin -a" restores',
    )]
    string $base = 'origin/HEAD',
    #[AsOption(description: 'Mutant processes run in parallel; "max" is the number of cores minus one')]
    string $threads = 'max',
    #[AsOption(
        description: 'Reuse the coverage of the last "castor phpunit" in .ci-tools/coverage, or with --strict of the last strict run in .ci-tools/coverage-strict, instead of running the tests again; it must come from the same source and the same paths',
    )]
    bool $reuseCoverage = false,
): void {
    if ($diff && $strict) {
        io()->error('--diff and --strict mutate two different sets: pick one.');
        exit(1);
    }
    $strictFiles = array_values(array_filter(INFECTION_STRICT_FILES, is_file(...)));
    if ($strict && $strictFiles !== INFECTION_STRICT_FILES) {
        io()->error(sprintf('Missing from the tree: %s.', implode(', ', array_diff(INFECTION_STRICT_FILES, $strictFiles))));
        exit(1);
    }

    $coverage = $strict ? '.ci-tools/coverage-strict' : '.ci-tools/coverage';
    if ($reuseCoverage) {
        if (! is_file($coverage . '/index.xml') || ! is_file($coverage . '/junit.xml')) {
            io()->error(sprintf('No coverage to reuse in %s: run the tests first, or drop --reuse-coverage.', $coverage));
            exit(1);
        }
    } elseif ($strict) {
        strict_coverage();
    } else {
        phpunit();
    }

    $options = [
        '--coverage=' . $coverage,
        '--skip-initial-tests',
        sprintf('--min-msi=%d', $strict ? 100 : $minMsi),
        sprintf('--min-covered-msi=%d', $strict ? 100 : $minCoveredMsi),
        '--threads=' . $threads,
        '--logger-github',
        '-s',
        // Infection decides whether to skip a mutant from the summed duration of the test files covering it, in
        // junit.xml, which is why the timeout of infection.json.dist is far above any single run.
        '--only-covering-test-cases',
    ];

    if ($strict) {
        $options[] = '--filter=' . implode(',', $strictFiles);
        $options[] = '--with-uncovered';
    }

    if ($diff) {
        // Infection runs "git diff" on the directories of infection.json.dist as written, hence that file at the root.
        $options[] = '--git-diff-lines';
        $options[] = '--git-diff-base=' . $base;
    }

    phpqa(['composer', 'exec', '--', 'infection', ...$options], [
        'XDEBUG_MODE' => 'coverage',
    ]);
}

/**
 * Measured by Xdebug: pcov reports no line for a "continue" statement, whose mutants it would leave uncovered.
 */
function strict_coverage(): void
{
    phpqa(
        [
            'composer',
            'exec',
            '--',
            'phpunit',
            '--coverage-xml',
            '.ci-tools/coverage-strict',
            '--log-junit=.ci-tools/coverage-strict/junit.xml',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--testsuite',
            'xml-security,saml2-model,saml2-bindings,saml,core',
        ],
        ['XDEBUG_MODE' => 'coverage'],
    );
}

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis.')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    // The formatter runs last: Rector and the linter rewrite statements, the formatter lays them out.
    mago_lint_fix();
    rector_fix();
    mago_format_fix();

    io()->section('Running static analysis…');
    phpstan_baseline();
    deptrac();

    io()->success('Code is ready. You may now commit and push your changes.');
}
