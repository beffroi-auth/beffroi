<?php

declare(strict_types=1);

/*
 * The quality tools, what the CI runs on every push (.github/workflows/ci.yml): each one in the phpqa image
 * when Docker is available, save the check of the generated configuration of the application, which boots
 * the application itself and runs where its own Composer install was made.
 */

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
 * The Git directory to mount beside the working directory, and null when the working directory already
 * carries it.
 *
 * In a worktree, ".git" is a file holding "gitdir: <main checkout>/.git/worktrees/<name>", an absolute path
 * of the host that the mount of the working directory does not cover, so every tool that reads the
 * repository from the container stops on "not a git repository: ...". What carries the objects, the refs and
 * the worktree's own directory is the common directory, so mounting it at the very path that pointer names
 * is what makes the repository readable. Every issue is worked on in a worktree (AGENTS.md), and the one
 * mutation run a change of a rule asks for by hand, "castor infect --diff", is a tool that reads it.
 *
 * A main checkout keeps its common directory under the working directory, where /project already carries
 * it, and gets no second mount: its command is the one it has always been.
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
 * The environment, the working directory and the PHP configuration apply in both cases.
 *
 * @param array<string> $command
 * @param array<string, string> $environment
 * @param string|null $phpIniDirectory a directory of the repository, read after the image's own conf.d, for
 *                                     the one task that needs what it turns on (.ci-tools/php/)
 * @param string|null $workingDirectory a directory of the repository the command runs from, for the task
 *                                      whose configuration lives beside what it reads (apps/op)
 * @param bool $hostNetwork the network of the machine instead of one of the container's own, for the task
 *                          that reaches a port the development stack publishes on the loopback address
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
        // A leading colon keeps the directory PHP was compiled to scan and adds ours after it, so the
        // configuration of the image still applies and this only adds to it.
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

    // The temporary directory of a run is the container's own /tmp, and it is left there. TMPDIR would move
    // it under the working directory, where it would outlive the run, and that is what must not happen: the
    // compiled container of the test kernel lives in it (AppKernel::getCacheDir()) and that kernel boots
    // with APP_DEBUG=0, where Symfony reuses a dumped container without asking whether the configuration it
    // was dumped from has moved. What the compilation costs is measured: a run of one test class is 3 532 ms
    // on an empty cache against 2 180 ms with it already there, so 1 350 ms once per run, which is less than
    // one afternoon spent on a container nothing invalidated.
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
        // What the container reaches is then what the machine reaches, the loopback address included, which
        // is where the development stack publishes its PostgreSQL (compose.yaml).
        ...($hostNetwork ? ['--network', 'host'] : []),
        // Read only: what the container does with it is read the repository, and nothing it runs has
        // business writing in the Git directory of the checkout a worktree hangs from.
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
    #[AsRawTokens]
    array $args = [],
): void {
    // paratest takes the options this task already passes, the same coverage and the same JUnit report,
    // and it merges what its workers produced itself: sharding across runs cannot, PHPUnit refusing to
    // merge XML coverage reports, and that report is what the mutation job reads. Each worker is given a
    // TEST_TOKEN, which AppKernel turns into a cache directory of its own, and with it a compiled
    // container, a database and a key storage of its own (issue #529).
    $parallel = $processes !== '1';

    phpqa(
        [
            'composer',
            'exec',
            '--',
            $parallel ? 'paratest' : 'phpunit',
            ...($parallel ? ['--processes=' . $processes] : []),
            '--coverage-xml',
            '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        // XDEBUG_MODE stays at the "off" phpqa() defaults it to: the coverage comes from pcov, which
        // php-code-coverage picks over Xdebug whenever it is enabled, and which the whole suite costs
        // 275 s with against 404 s with Xdebug, 229 s being what it costs with no coverage at all. What
        // reads this coverage is the mutation job, and line coverage is all it asks for.
        [],
        '.ci-tools/php/coverage',
    );
}

/*
 * The suite of the standalone application (issue #521), which is not the suite of the packages and does not
 * run against what it runs against. The three suites of ".ci-tools/phpunit.xml.dist" judge the rules of the
 * provider on a test kernel of their own, on SQLite; this one boots the kernel of "apps/op", the one a
 * deployment boots, so it needs what that kernel needs: a PostgreSQL, and a KMS to seal the personal columns
 * the page of a person writes (decisions 0011 and 0018). Which is why it is a task and not a line of the
 * suites above, and why the job that runs it carries a database service.
 *
 * It runs in the phpqa image, as every tool of this repository does, and the runner is the PHPUnit that
 * image carries: this application declares none of its own, no more than it declares PHPStan or Rector. The
 * container is given the network of the machine, because what answers on the loopback address is the
 * PostgreSQL the development stack publishes there, and the application's own "vendor" is read from the
 * mount of the repository.
 */
#[AsTask(
    description: 'Run the suite of the standalone application: its own kernel, on the PostgreSQL that DATABASE_URL names and the KMS of apps/op/.env.test, the schema written by the migrations of the bundle before the first test. It needs a PostgreSQL reachable from the machine, which "castor start" publishes on the loopback address',
    ignoreValidationErrors: true,
)]
function app_phpunit(#[AsRawTokens] array $args = []): void
{
    io()->title('Running the suite of the application');

    // The database the suite writes is never the one the stack serves: the test environment of the
    // application appends "_test" to the name DATABASE_URL carries (apps/op/config/packages/doctrine.yaml),
    // and a run empties every table of it before every test.
    application_console(['doctrine:database:create', '--if-not-exists']);
    // The schema comes from the migrations of the bundle, the way a deployment gets it, which is also the
    // one place of this repository where they are played against PostgreSQL by a run nobody started by
    // hand. The suite creates nothing and drops nothing: it empties the rows.
    application_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);

    // "phpunit" and not "composer exec -- phpunit": what is played here is the runner of the image, and the
    // "vendor/bin" of this application carries none for Composer to find first.
    application_phpqa(['phpunit', '--configuration', 'phpunit.dist.xml', ...$args]);
}

/**
 * A console command of the application, in the environment its suite runs in. Not op_console() of
 * .castor/stack/stack.php, which runs in the container of a stack that is up.
 *
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
 * A command of the application in the phpqa image: from "apps/op", where its configuration and its own
 * "vendor" are, and on the network of the machine, where the PostgreSQL its kernel reads answers.
 *
 * @param array<string> $command
 * @param array<string, string> $environment
 */
function application_phpqa(array $command, array $environment = []): void
{
    assert_application_installed();

    phpqa($command, $environment, workingDirectory: 'apps/op', hostNetwork: true);
}

/**
 * Where the application is installed, which is where the tasks that boot it on the host run:
 * "apps/op/composer.json" resolves the packages through path repositories and its "vendor" is its own.
 */
function application_context(): Context
{
    assert_application_installed();

    return context()->withWorkingDirectory(getcwd() . '/apps/op');
}

/**
 * Nothing of the application runs before its own Composer install was made, in the image as on the host:
 * what every task of it reads is "apps/op/vendor".
 */
function assert_application_installed(): void
{
    if (is_file(getcwd() . '/apps/op/vendor/autoload.php')) {
        return;
    }

    io()->error('The application is not installed: run "(cd apps/op && composer install)" first.');
    exit(1);
}

/**
 * The PHP the application runs with. The static binary of Castor carries its own runtime and reports no
 * PHP_BINARY, so the PHP of the PATH is what boots the application there; a Castor running on a PHP names it.
 */
function application_php(): string
{
    return \PHP_BINARY === '' ? 'php' : \PHP_BINARY;
}

/*
 * Mago (https://mago.carthage.software/), the toolchain of Carthage Software: one Rust binary, no PHP
 * runtime, already installed in the phpqa image (/tools/mago), configured by mago.toml at the root of
 * the repository, which is where its editor integrations look for it. It holds the formatter and the
 * linter, in place of Easy Coding Standard. Its analyzer is not PHPStan's equal and replaces nothing:
 * see mago_analyze() below and the [analyzer] section of mago.toml.
 */

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

/**
 * The configurations PHPStan runs, one analysis each: the identity provider's packages under the baseline, and
 * each SAML package, beffroi/saml among them, under its own, with no baseline and the bans of its section 8, which
 * are rules of that package and not of the others.
 */
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

/**
 * The fixture of the rules of beffroi/saml and the configuration that analyses it alone: every form section 8 of
 * src/saml/spec/saml.md bans, one line each, and the lines that must pass.
 */
const PHPSTAN_SAML_RULES_FIXTURE = 'tests/saml/PhpStan/Fixture';

const PHPSTAN_SAML_RULES_CONFIGURATION = '.ci-tools/phpstan-saml-rules.neon';

const PHPSTAN_SAML_RULES_REPORT = '.ci-tools/cache/phpstan-saml-rules/report.json';

/**
 * The identifiers of the errors the rules of section 8 report, the only ones this task reads: BannedCallsRule and
 * BannedCallablesRule, BannedNamesRule, and the function list and the statements of ekino/phpstan-banned-code.
 */
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

    // PHPStan answers 1 when it reports errors, which is its job here; the report is the result, and anything above 1
    // is PHPStan failing. The redirection is the shell's of the container: phpqa() does not capture an output.
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
                // A set and not a count: PHPStan visits a nullsafe call twice, and what is asked is whether the line is refused.
                $reported[$line] = true;
            } elseif ($identifier === '' || str_starts_with($identifier, 'phpstan.')) {
                // A parse error or a message without an identifier: the fixture was not read, and what it says is not proven.
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

/**
 * The path PHPStan reports (/project/... in the image, the working directory outside it) from the fixture directory on.
 */
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
        // A clean analysis is the expected outcome, not a failure of the task.
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

/*
 * The generated configuration of the application, both files committed: "apps/op/config/reference.php", the
 * array shapes an editor completes a "beffroi.*" key with, and "apps/op/config/schema.json", the JSON schema a
 * language server validates the YAML against. The kernel writes them when it compiles its container in debug
 * (FrameworkBundle, PhpConfigReferenceDumpPass and JsonSchemaConfigDumpPass), from the configuration trees of
 * the bundles the application has installed, and nothing else writes them: a node added, renamed or re-worded
 * in "BeffroiBundle::configure()" leaves them behind until someone boots the application. A member that exists
 * and is not in the reference is a member nobody discovers; a member the reference still carries and the
 * container refuses is worse, since the file says otherwise.
 */
const GENERATED_CONFIGURATION = [
    'apps/op/config/reference.php',
    'apps/op/config/schema.json',
];

#[AsTask(
    description: 'Check that the generated configuration reference and schema of the application still say what the configuration trees of its bundles declare',
)]
function config_reference(): void
{
    io()->title('Checking the generated configuration reference and schema');

    $onDisk = generated_configuration();
    regenerate_generated_configuration();
    $regenerated = generated_configuration();

    $behind = [];
    foreach (GENERATED_CONFIGURATION as $file) {
        if ($regenerated[$file] === $onDisk[$file]) {
            continue;
        }

        $behind[] = $file;
        // The check reports, it does not fix, the rule the formatter already follows here: the file goes back
        // to what it held, and what the kernel would have written is shown instead.
        $written = sprintf('%s/%s', sys_get_temp_dir(), basename($file));
        file_put_contents($written, $regenerated[$file]);
        file_put_contents(getcwd() . '/' . $file, $onDisk[$file]);
        run(['git', '--no-pager', 'diff', '--no-index', '--', $file, $written], context: context()->withAllowFailure());
        unlink($written);
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
 * The content of the two generated files, by path.
 *
 * @return array<string, string>
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
 * Boots the application the way a developer does, on the host and outside the stack: "cache:clear" compiles
 * the container whatever the state of the cache, and compiling it in debug is what writes the two files.
 * Not in the QA image like the other tasks of this file: the application is installed by its own Composer
 * install, and it runs with the PHP that made it.
 */
function regenerate_generated_configuration(): void
{
    run([application_php(), 'bin/console', 'cache:clear'], context: application_context()->withEnvironment([
        'APP_ENV' => 'dev',
        'APP_DEBUG' => '1',
    ]));
}

/**
 * The files the specifications of the SAML packages accept only with no escaped mutant (section 9 of spec/core.md,
 * spec/dsig.md, spec/enc.md, spec/model.md, spec/bindings.md and spec/saml.md): "castor infect --strict" mutates them whole,
 * uncovered lines included, and fails under a hundred percent. A file joins the list in the commit that creates it, never before: a
 * listed file missing from the tree is an error.
 */
const INFECTION_STRICT_FILES = [
    // beffroi/xml-security. Loader delegates the rules of 6.1 steps 5 and 6 to Internal\Inspector, which is why that
    // file is held to the same bar.
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
    // beffroi/saml2-model.
    // Section 5.8: the refusals, and the status a refused response carries (M-13, M-16).
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
    // Section 9: the lexical forms of M-6 and SamlId, every file of src/Value/.
    'src/saml2-model/src/Value/Time.php',
    'src/saml2-model/src/Value/Boolean.php',
    'src/saml2-model/src/Value/SamlId.php',
    'src/saml2-model/src/Value/Uri.php',
    'src/saml2-model/src/Value/Version.php',
    'src/saml2-model/src/Value/UnsignedShort.php',
    'src/saml2-model/src/Value/Counts.php',
    'src/saml2-model/src/Value/Characters.php',
    // Section 9: NameId, the rule of each format (M-12).
    'src/saml2-model/src/Assertion/NameId.php',
    // Section 9: the bounds of time the validators and the metadata reader share (M-7).
    'src/saml2-model/src/Validation/TimeBounds.php',
    // Section 5.6: how a protocol message was authenticated (M-2).
    'src/saml2-model/src/Validation/Authentication.php',
    // Section 9: IndexedEndpoints, the default endpoint and the searches of M-9.
    'src/saml2-model/src/Metadata/IndexedEndpoints.php',
    // Section 9: the metadata reader (section 6.5).
    'src/saml2-model/src/Metadata/MetadataReader.php',
    // Section 9: the one reading model of the SAML schemas, every strict reader's (M-5).
    'src/saml2-model/src/Internal/Schema.php',
    'src/saml2-model/src/Internal/Particle.php',
    // Section 9: the edges of the windows of M-7, which every reader takes.
    'src/saml2-model/src/Internal/Window.php',
    // Section 9: the strict readers of metadata and the rules its roles share.
    'src/saml2-model/src/Internal/Metadata/EndpointReader.php',
    'src/saml2-model/src/Internal/Metadata/EntityDescriptorReader.php',
    'src/saml2-model/src/Internal/Metadata/KeyDescriptorReader.php',
    'src/saml2-model/src/Internal/Metadata/RoleReader.php',
    'src/saml2-model/src/Internal/Metadata/RoleRules.php',
    // Section 9: the rule of M-2 for a received protocol message, and the one reader of a samlp:Status (M-5, M-13).
    'src/saml2-model/src/Internal/Protocol/MessageAuthentication.php',
    'src/saml2-model/src/Internal/Protocol/StatusReader.php',
    // Section 9: the strict readers of the assertion and their rules, sections 6.1 steps 7 to 11.
    'src/saml2-model/src/Internal/Assertion/AssertionContext.php',
    'src/saml2-model/src/Internal/Assertion/IssuerReader.php',
    'src/saml2-model/src/Internal/Assertion/NameIdReader.php',
    'src/saml2-model/src/Internal/Assertion/HeaderReader.php',
    'src/saml2-model/src/Internal/Assertion/SubjectReader.php',
    'src/saml2-model/src/Internal/Assertion/ConditionsReader.php',
    'src/saml2-model/src/Internal/Assertion/AuthnStatementReader.php',
    'src/saml2-model/src/Internal/Assertion/AttributeStatementReader.php',
    'src/saml2-model/src/Internal/Assertion/AssertionReader.php',
    // Section 9: the envelope of a response, its status, the selection of the signed element and the decryption of an
    // encrypted assertion, section 6.1 steps 2 to 6 and section 6.7.
    'src/saml2-model/src/Internal/Response/Envelope.php',
    'src/saml2-model/src/Internal/Response/SignedResponse.php',
    'src/saml2-model/src/Internal/Response/DecryptedAssertion.php',
    'src/saml2-model/src/Internal/Response/CoveringResponseSignature.php',
    'src/saml2-model/src/Internal/Response/PlaintextReader.php',
    'src/saml2-model/src/Internal/Response/ReadAssertion.php',
    'src/saml2-model/src/Internal/Response/SignedAssertion.php',
    'src/saml2-model/src/Internal/Response/EnvelopeReader.php',
    // Section 9: the validator of a response and what it takes and returns (sections 5.4, 5.5).
    'src/saml2-model/src/Protocol/UnverifiedResponse.php',
    'src/saml2-model/src/Protocol/Response.php',
    'src/saml2-model/src/Validation/ExpectedResponse.php',
    'src/saml2-model/src/Validation/SignatureCoverage.php',
    'src/saml2-model/src/Validation/AcceptedAssertion.php',
    'src/saml2-model/src/Validation/ResponseValidator.php',
    // Section 9: the strict reader of an AuthnRequest and the resolution of its assertion consumer service (M-9).
    'src/saml2-model/src/Internal/AuthnRequest/AssertionConsumerService.php',
    'src/saml2-model/src/Internal/AuthnRequest/AuthnRequestContext.php',
    'src/saml2-model/src/Internal/AuthnRequest/AuthnRequestReader.php',
    'src/saml2-model/src/Internal/AuthnRequest/NameIdPolicyReader.php',
    'src/saml2-model/src/Internal/AuthnRequest/RequestedAuthnContextReader.php',
    // Section 9: the validator of an AuthnRequest and what it returns (section 6.2).
    'src/saml2-model/src/Validation/AuthnRequestValidator.php',
    'src/saml2-model/src/Validation/AcceptedAuthnRequest.php',
    // Section 6.6: the builders of a response and its assertion, whose output the validator of section 6.1 reads
    // back (M-15).
    'src/saml2-model/src/Internal/Writing/Tree.php',
    'src/saml2-model/src/Internal/Writing/NameIdBuilder.php',
    'src/saml2-model/src/Internal/Writing/StatusBuilder.php',
    'src/saml2-model/src/Internal/Writing/AssertionBuilder.php',
    'src/saml2-model/src/Internal/Writing/ResponseBuilder.php',
    // Section 6.6: the writer of a response, which checks what the validator would refuse and signs (M-15).
    'src/saml2-model/src/Writing/SignedParts.php',
    'src/saml2-model/src/Writing/ResponseWriter.php',
    // Section 6.6: the writers of the other messages and of metadata, each on the tree builder of the response's.
    'src/saml2-model/src/Writing/AuthnRequestWriter.php',
    'src/saml2-model/src/Writing/MetadataWriter.php',
    // beffroi/saml, section 9: what the metadata of the identity provider of a tenant says, the certificates it keeps
    // and forgets, and the handler and the writer that build it (section 6.1).
    'src/saml/src/Domain/Metadata/Certificate.php',
    'src/saml/src/Domain/Metadata/IdentityProviderDescription.php',
    'src/saml/src/Domain/Metadata/PublishedMetadata.php',
    'src/saml/src/Application/Metadata/SigningCertificates.php',
    'src/saml/src/Application/Metadata/IdentityProviderMetadataHandler.php',
    'src/saml/src/Bridge/Model/ModelMetadataWriter.php',
    // beffroi/saml, section 9: the service provider of a tenant, its entity ID of its own, what its metadata say, and
    // the handler and the writer that build them (section 6.9).
    'src/saml/src/Domain/Metadata/ServiceProviderEndpoints.php',
    'src/saml/src/Domain/Metadata/ServiceProviderDescription.php',
    'src/saml/src/Application/Metadata/ServiceProviderMetadataHandler.php',
    'src/saml/src/Bridge/Model/ModelServiceProviderMetadataWriter.php',
    'src/saml/src/Bridge/Model/ModelEntityId.php',
    // beffroi/saml, section 9: the key each upstream identity provider encrypts for, its certificates given to that
    // provider alone, and the key that opens what it encrypted and nothing another provider encrypted (S-64 to S-66,
    // sections 6.12 and 6.13).
    'src/saml/src/Domain/Key/UpstreamEncryptionKeys.php',
    'src/saml/src/Application/Metadata/BuiltCertificates.php',
    'src/saml/src/Application/Metadata/EncryptionCertificates.php',
    'src/saml/src/Bridge/Model/UpstreamDecryptionKeys.php',
    'src/saml/src/Bridge/Model/ProviderDecryptionKey.php',
    // beffroi/saml, section 9: the service providers of a tenant, their declaration, the reading of their metadata and
    // the document kept against a rollback (section 6.2).
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
    // beffroi/saml, section 9: the upstream identity providers of a tenant, their declaration, their domains, the
    // reading of their metadata and the role the refresh reads them by (S-42 to S-45)
    'src/saml/src/Domain/Upstream/AcceptedUpstreamMetadata.php',
    // the domain of S-44, the core's since S-60, so that the discovery of the login page, the first sign-in and the
    // refusal of a local credential read it by one rule: held as it was, by the suite of the core
    'src/core/src/Domain/Identity/EmailDomain.php',
    'src/saml/src/Domain/Upstream/GroupMapping.php',
    'src/saml/src/Domain/Upstream/ProfileAttribute.php',
    'src/saml/src/Domain/Upstream/UpstreamIdentityProvider.php',
    'src/saml/src/Domain/Upstream/UpstreamMetadata.php',
    'src/saml/src/Application/Upstream/UpstreamIdentityProviderRole.php',
    'src/saml/src/Bridge/Model/ModelUpstreamMetadataReader.php',
    'src/saml/src/Bridge/Configuration/ConfigurationUpstreamIdentityProviders.php',
    // beffroi/saml, section 9: the request the service provider sends an upstream identity provider, what it is written
    // from, the use case that starts it and the sender that writes and signs it (S-48 to S-50, section 6.11)
    'src/saml/src/Domain/Upstream/UpstreamAuthnRequest.php',
    'src/saml/src/Domain/Upstream/SentAuthnRequest.php',
    // the address a person gave the login page, carried to the provider that reads one (S-68, issue #816)
    'src/saml/src/Domain/Upstream/AddressHint.php',
    'src/saml/src/Application/Upstream/UpstreamSignOn.php',
    'src/saml/src/Bridge/Model/ModelAuthnRequestSender.php',
    // the assertion consumer service (spec/saml.md S-52 to S-59, issue #784)
    'src/saml/src/Domain/Upstream/VerifiedAssertion.php',
    'src/saml/src/Domain/Upstream/UpstreamAssertion.php',
    'src/saml/src/Domain/Upstream/AuthnContextMethods.php',
    'src/saml/src/Application/Upstream/AssertionConsumerService.php',
    'src/saml/src/Bridge/Model/ModelResponseReceiver.php',
    // beffroi/saml, section 9: the signature an authentication request needs and its translation to the model's terms
    // (section 6.3).
    'src/saml/src/Domain/ServiceProvider/AuthnRequestSigning.php',
    'src/saml/src/Bridge/Model/ModelAuthnRequestParties.php',
    // beffroi/saml, section 9: single sign-on, the values it keeps and writes, the use case, the attributes released,
    // the request received and validated, and the answer written and signed (section 6.4).
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
    // beffroi/saml, section 9: Single Logout started by a service provider, the request accepted once, the sessions
    // ended and the answer signed (section 6.5), and each service provider's part in a session (S-26).
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
    // beffroi/saml, section 9: Single Logout started by the identity provider, every service provider of the ended
    // sessions told through the browser, the chain kept and played once, and where it ends (section 6.6).
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
    // Section 9: the strict readers of the two logout messages (sections 6.3, 6.4).
    'src/saml2-model/src/Internal/Logout/Envelope.php',
    'src/saml2-model/src/Internal/Logout/LogoutContext.php',
    'src/saml2-model/src/Internal/Logout/LogoutRequestReader.php',
    'src/saml2-model/src/Internal/Logout/LogoutResponseReader.php',
    'src/saml2-model/src/Internal/Logout/ReplayWindow.php',
    // Section 9: the logout validators and what they return (section 5.6).
    'src/saml2-model/src/Validation/LogoutRequestValidator.php',
    'src/saml2-model/src/Validation/LogoutResponseValidator.php',
    'src/saml2-model/src/Validation/AcceptedLogoutRequest.php',
    'src/saml2-model/src/Validation/AcceptedLogoutResponse.php',
    // beffroi/saml2-bindings.
    // Section 5.1: the bounds and their ceilings of section 7 (B-7).
    'src/saml2-bindings/src/BindingLimits.php',
    // Section 5.4: the refusals, each naming its rule (B-11).
    'src/saml2-bindings/src/Exception/BindingRefused.php',
    'src/saml2-bindings/src/Exception/MalformedParameters.php',
    'src/saml2-bindings/src/Exception/MalformedEncoding.php',
    'src/saml2-bindings/src/Exception/InvalidRelayState.php',
    'src/saml2-bindings/src/Exception/XmlSignatureRefused.php',
    'src/saml2-bindings/src/Exception/NoVerificationKey.php',
    'src/saml2-bindings/src/Exception/Unsupported.php',
    'src/saml2-bindings/src/Exception/LimitExceeded.php',
    // B-8: the percent codec, the one place a percent-escape is read or written.
    'src/saml2-bindings/src/Internal/Percent.php',
    // B-8: base64 in its one form, the one place it is decoded.
    'src/saml2-bindings/src/Internal/Base64.php',
    // Sections 6.3 and 6.4 step 1: the scheme of a Destination, http or https.
    'src/saml2-bindings/src/Internal/DestinationScheme.php',
    // B-7, B-8: the bounded inflater, raw DEFLATE refused as soon as its output exceeds the bound.
    'src/saml2-bindings/src/Internal/Inflater.php',
    // B-8: the deflater, raw DEFLATE.
    'src/saml2-bindings/src/Internal/Deflater.php',
    // B-2: the signed octets, the raw values in the binding's order.
    'src/saml2-bindings/src/Internal/SignedOctets.php',
    // B-4: the detached signature, verified under the keys of the peer's metadata.
    'src/saml2-bindings/src/Internal/DetachedSignature.php',
    // B-1, B-3, B-9, section 6.1 steps 2 to 7: the reading of a query string's parameters.
    'src/saml2-bindings/src/Internal/QueryParameters.php',
    // B-1, B-7, B-9, section 6.2 steps 1 to 3: the reading of a form's fields.
    'src/saml2-bindings/src/Internal/FormFields.php',
    // B-5, section 5.2: one input read whole, the message and the detached signature of that very input.
    'src/saml2-bindings/src/Internal/Reception.php',
    // Sections 6.1 steps 3 and 11, 6.2 steps 2 and 6: the message each service of ours expects.
    'src/saml2-bindings/src/Internal/Service.php',
    // Section 6.1: HTTP-Redirect received, in order (B-6, B-7).
    'src/saml2-bindings/src/RedirectReceiver.php',
    // Section 6.2: HTTP-POST received, in order (B-7, B-8, B-10).
    'src/saml2-bindings/src/PostReceiver.php',
    // Section 6.3: HTTP-Redirect sent, in order (B-2, B-6, B-9, B-10, B-12).
    'src/saml2-bindings/src/RedirectSender.php',
    // Section 6.4: HTTP-POST sent, in order (B-7, B-9, B-10, B-12), and the form it returns (section 6.7).
    'src/saml2-bindings/src/PostSender.php',
    'src/saml2-bindings/src/PostForm.php',
    // Section 6.1 step 12: authenticated as the binding says, then validated (B-5).
    'src/saml2-bindings/src/ReceivedAuthnRequest.php',
    'src/saml2-bindings/src/ReceivedLogoutRequest.php',
    'src/saml2-bindings/src/ReceivedLogoutResponse.php',
    // Section 6.2 step 7: a response, over HTTP-POST only, validated by the model (B-5, B-12).
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

    // The XML coverage and the JUnit report of a "castor phpunit" run are what Infection reads from .ci-tools/coverage.
    // The strict run reads a coverage of its own, the suites of the SAML packages and of the core measured by Xdebug:
    // pcov reports no line for a "continue" statement, so the mutant that turns one into "break" is not covered under
    // it, and the hundred percent the specifications ask for is out of reach on a line every test of the corpus runs.
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
        // Each mutant runs only the test cases that cover its line (PHPUnit --filter), not the whole test files:
        // the functional tests cover most of the source, and the files they live in take minutes to run.
        // Infection still decides whether to skip a mutant from the summed duration of the covering test files
        // as reported by junit.xml, which is why the timeout of infection.json.dist is far above any single run.
        '--only-covering-test-cases',
    ];

    if ($strict) {
        $options[] = '--filter=' . implode(',', $strictFiles);
        $options[] = '--with-uncovered';
    }

    if ($diff) {
        // Infection runs "git diff <merge base> -- <source directories>" from the working directory and passes the
        // directories of infection.json.dist as they are written: this is why that file sits at the root of the
        // repository, not in .ci-tools with the other configurations. A diff that touches no source file is a success.
        $options[] = '--git-diff-lines';
        $options[] = '--git-diff-base=' . $base;
    }

    // The PHPUnit configuration Infection 0.32 generates still carries cacheResult="false", which PHPUnit 13
    // reports as a deprecation ("recordTestRunHistory" replaces it) and PHPUnit 14 will refuse.
    phpqa(['composer', 'exec', '--', 'infection', ...$options], [
        'XDEBUG_MODE' => 'coverage',
    ]);
}

/**
 * The coverage the strict mutation run reads: the suites of the SAML packages, and the one of the core, which tests the
 * domain of an address all of them read (spec/saml.md S-60), measured by Xdebug, which counts a "continue" statement as
 * a line, where pcov does not.
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
