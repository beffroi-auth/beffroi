<?php

declare(strict_types=1);

/*
 * The website of beffroi.tech (apps/website), what the Website workflow runs (.github/workflows/website.yml): a
 * Symfony application of its own, installed by its own Composer install, which nothing of the identity provider
 * requires and which requires nothing of it. Its tasks run where that install was made, with the PHP of the host,
 * as the check of the generated configuration of apps/op does; its formatting, its linting and Rector are the ones
 * of the root (mago.toml, .ci-tools/rector.php), which the quality job of ci.yml runs.
 */

use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\capture;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * The credentials of the database of apps/website/compose.yaml, the defaults its .env names too.
 */
const WEBSITE_DATABASE = 'postgresql://app:!ChangeMe!@127.0.0.1:%d/app?serverVersion=16&charset=utf8';

/**
 * @param array<string> $args
 */
#[AsTask(description: 'Run the suite of the website, on the PostgreSQL of its compose.yaml unless DATABASE_URL names one')]
function website_phpunit(#[AsRawTokens] array $args = []): void
{
    io()->title('Running the suite of the website');

    $context = website_database_context()->withEnvironment(['APP_ENV' => 'test', 'APP_DEBUG' => '0']);
    // The test environment appends "_test" to the name of the database (config/packages/doctrine.yaml), and the
    // suite empties its tables before each test: the schema comes from the migrations, as on a deployment.
    run([application_php(), 'bin/console', 'doctrine:database:create', '--if-not-exists'], context: $context);
    run([application_php(), 'bin/console', 'doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing'], context: $context);
    run([application_php(), 'bin/phpunit', ...$args], context: $context);
}

#[AsTask(description: 'Run PHPStan on the website, at level max, with its Symfony and Doctrine extensions')]
function website_phpstan(): void
{
    io()->title('Running PHPStan on the website');

    $context = website_context();
    // The Symfony extension reads the container the dev kernel compiles (apps/website/phpstan.dist.neon).
    run([application_php(), 'bin/console', 'cache:warmup'], context: $context->withEnvironment(['APP_ENV' => 'dev', 'APP_DEBUG' => '1']));
    run([
        application_php(),
        'vendor/bin/phpstan',
        'analyse',
        '--no-progress',
        '--error-format=' . (getenv('GITHUB_ACTIONS') === 'true' ? 'github' : 'table'),
    ], context: $context);
}

/**
 * Where the website is installed: "apps/website", whose "vendor" is its own.
 */
function website_context(): Context
{
    if (! is_file(getcwd() . '/apps/website/vendor/autoload.php')) {
        io()->error('The website is not installed: run "(cd apps/website && composer install)" first.');
        exit(1);
    }

    return context()->withWorkingDirectory(getcwd() . '/apps/website');
}

/**
 * The website, and the PostgreSQL its suite writes: the one DATABASE_URL names when the environment carries it (the
 * service of the Website workflow), or else the one of its compose.yaml, started for the run and left up.
 */
function website_database_context(): Context
{
    $context = website_context();
    if (getenv('DATABASE_URL') !== false) {
        return $context;
    }

    run(['docker', 'compose', 'up', '--detach', '--wait', 'database'], context: $context);
    // "0.0.0.0:55012": the port Docker published for 5432, which compose.override.yaml leaves to it.
    $published = trim(capture(['docker', 'compose', 'port', 'database', '5432'], context: $context));
    $port = (int) substr($published, (int) strrpos($published, ':') + 1);

    return $context->withEnvironment(['DATABASE_URL' => sprintf(WEBSITE_DATABASE, $port)]);
}
