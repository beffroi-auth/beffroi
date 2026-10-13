<?php

declare(strict_types=1);

/*
 * The relying party of apps/rp started against the running stack: a Symfony application that signs a user
 * in with "oidc_login" as the client "rp" of apps/op/config/packages/beffroi.yaml, and nothing else, so
 * that what is tried against the provider is tried from an application that can be edited on the spot.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use Symfony\Component\Dotenv\Dotenv;
use function Castor\io;
use function Castor\run;

const RP_DIRECTORY = 'apps/rp';

/**
 * Served by the Caddy of op, which passes it to the "rp" service of compose.yaml (docker/rp/rp.Caddyfile).
 */
const RP_URL = 'https://rp.localhost';

#[AsTask(
    description: 'Start the relying party of apps/rp on https://rp.localhost against the development OP: its .env.local takes the secret of the client "rp" from apps/op/.env.local, then the "rp" service of compose.yaml is started, which installs the application the first time; --stop stops it',
)]
function rp(
    #[AsOption(description: 'Stop the relying party')]
    bool $stop = false,
): void {
    if ($stop) {
        run(['docker', 'compose', '--profile', 'rp', 'rm', '--stop', '--force', 'rp']);

        return;
    }

    io()->title('The relying party of apps/rp');
    // Parsed and not loaded: what castor loads it hands to every process it starts as a real environment
    // variable, and the provider has no secret to give the relying party but this one.
    $provider = getcwd() . '/apps/op/.env.local';
    $secret = is_file($provider) ? new Dotenv()->parse((string) file_get_contents($provider), $provider)['OIDC_RP_SECRET'] ?? '' : '';
    if ($secret === '') {
        io()->error('apps/op/.env.local holds no OIDC_RP_SECRET: run "castor provision" first.');
        exit(1);
    }
    // The application runs without worker mode and reads .env.local at each request: a secret written
    // after it started is served by the next one.
    demo_write_env_local(getcwd() . '/' . RP_DIRECTORY . '/.env.local', ['OIDC_CLIENT_SECRET' => $secret]);
    run(['docker', 'compose', '--profile', 'rp', 'up', '-d', '--wait', 'rp']);

    io()->success(sprintf('%s/profile signs in on the development OP as "%s"; "castor rp --stop" stops it.', RP_URL, DEV_USERNAME));
}
