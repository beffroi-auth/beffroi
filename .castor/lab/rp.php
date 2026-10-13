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
use function Castor\context;
use function Castor\io;
use function Castor\run;

const RP_DIRECTORY = 'apps/rp';

const RP_URL = 'https://localhost:8003';

#[AsTask(
    description: 'Start the relying party of apps/rp on https://localhost:8003 against the development OP: its .env.local takes the secret of the client "rp" from apps/op/.env.local, the CA of Caddy is copied where its HTTP client reads it, and its server is started again so that it serves what was just written; --stop stops it',
)]
function rp(
    #[AsOption(description: 'Stop the server of the relying party')]
    bool $stop = false,
): void {
    $directory = getcwd() . '/' . RP_DIRECTORY;
    $server = context()->withWorkingDirectory($directory);
    if ($stop) {
        run(['symfony', 'server:stop'], context: $server->withAllowFailure());

        return;
    }

    io()->title('The relying party of apps/rp');
    // Parsed and not loaded: loading the dotenv of the provider would hand every value of it to the server
    // started below as a real environment variable, which wins over the files of the relying party
    // (APP_SECRET and DEFAULT_URI are names of both).
    $provider = getcwd() . '/apps/op/.env.local';
    $secret = is_file($provider) ? new Dotenv()->parse((string) file_get_contents($provider), $provider)['OIDC_RP_SECRET'] ?? '' : '';
    if ($secret === '') {
        io()->error('apps/op/.env.local holds no OIDC_RP_SECRET: run "castor provision" first.');
        exit(1);
    }
    demo_write_env_local($directory . '/.env.local', ['OIDC_CLIENT_SECRET' => $secret]);
    caddy_ca($directory . '/var/caddy-root.crt');

    if (! is_dir($directory . '/vendor')) {
        run(['composer', 'install', '--no-interaction'], context: $server);
    }
    // The Symfony CLI hands the names of .env.local to the PHP it runs once, when it starts: a server
    // already up keeps the secret of the provisioning it was started after.
    run(['symfony', 'server:stop'], context: $server->withQuiet()->withAllowFailure());
    run(['php', 'bin/console', 'cache:clear'], context: $server->withQuiet());
    run(['symfony', 'server:start', '--port=' . parse_url(RP_URL, \PHP_URL_PORT), '--daemon'], context: $server);

    io()->success(sprintf('%s/profile signs in on the development OP as "%s"; "castor rp --stop" stops the server.', RP_URL, DEV_USERNAME));
}
