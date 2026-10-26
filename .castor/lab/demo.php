<?php

declare(strict_types=1);

/*
 * oidc-demo (Symfony oidc_login) against the stack: the experiments of the spikes, one request at a time from
 * the command line, so that every step is looked at (--check, --rotate, --passkey, --form-post,
 * --logout-others, --resource-server, --api, --dpop, --forge, --device, --service, --ciba, --assertion,
 * --rar, --native, --push). The last five need no oidc-demo: their clients are the CLIs of tests/demo/ and the walk
 * itself, because what they play has no browser of the demonstration in it, or asks for something oidc_login
 * does not send.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Process\InputStream;
use Symfony\Component\Process\Process;

/**
 * oidc-demo, the reference client of the core (Symfony's oidc_login): where it is checked out, next to this
 * repository or next to the repository this one is nested in, where its server listens, and the client the
 * application registers for it (apps/op/config/packages/beffroi.yaml).
 */
const DEMO_DIRS = ['../oidc-demo', '../../oidc-demo'];

const DEMO_URL = 'https://localhost:8002';

const DEMO_CLIENT_ID = 'oidc-demo';

/**
 * The second instance of oidc-demo, the one --logout-others logs out by back-channel from the first: the
 * same checkout, another client, another port, and a host of its own, because a cookie is not told apart
 * by port and the two instances would otherwise share a session. Plain HTTP on a loopback name: the worker
 * that carries it a logout token trusts no certificate of the Symfony CLI, and a client registers a
 * loopback URI or an HTTPS one (decision 0006).
 */
const DEMO_SECOND_URL = 'http://demo.localhost:8003';

const DEMO_SECOND_CLIENT_ID = 'oidc-demo-second';

/**
 * The secrets of the clients this tenant declares in its configuration that the demonstration holds
 * besides its own: the one with opaque access tokens, and the one of the rich authorization request. Its
 * API describes a token any of them handed out (RFC 7662 §2.2), which is what it needs their secrets
 * for, and "castor provision" generated them.
 *
 * A client the forge builds is none of these: it registers itself, and the keys it signs with or receives
 * an encrypted document with are drawn when it is built and published to the provider in its
 * registration, so nothing of it is provisioned and nothing of it is written here.
 */
const DEMO_FORGE_SECRETS = [
    'OIDC_DEMO_OPAQUE_SECRET' => 'DEMO_OPAQUE_SECRET',
    'DEMO_RAR_SECRET' => 'DEMO_RAR_SECRET',
];

#[AsTask(
    description: 'Point oidc-demo (Symfony oidc_login) at the development OP and start it on https://localhost:8002: its .env.local takes the issuer, the client and the secret of apps/op/.env.local, its php.ini trusts the CA of Caddy; --check then signs in as "alice", opens /profile and logs out from the command line; --rotate runs a whole key rotation against it, with short windows for the run, and measures what oidc_login does on an unknown "kid"; --passkey signs in with a password, is sent back for a passkey by /vault (acr_values=phr) and signs the assertion with a software authenticator; --form-post has the OP answer the authorization request with a self-submitting page and posts it back cross-site; --logout-others runs a second instance of the demo on another client and logs it out by back-channel from the first; --api plays the API Platform API of the demonstration, whose firewall asks the OP about the token at every request and keeps the answer a few seconds; --flows opens the pages where every flow this provider serves is drawn and plays two of them hop by hop; --ciba, --assertion, --rar and --native play the four things of spike 6 that have no browser of the demonstration in them; --push stands a push service up and has the notification of a backchannel request decrypted by the browser it was sent to; --by-hand, with --ciba or --push, answers nothing for you and stands in for nobody: your own browser gets the notification and you allow the request yourself',
)]
function demo(
    #[AsOption(description: 'Where oidc-demo is checked out; ../oidc-demo or ../../oidc-demo by default')]
    ?string $dir = null,
    #[AsOption(description: 'Sign in as the development user, open /profile and log out, from the command line, and print what was verified')]
    bool $check = false,
    #[AsOption(
        description: 'The second success criterion of spike 2 (issue #59): sign in, rotate the signing key of the OP, let the scheduled step activate it, sign in again, refresh, log out, retire the old key, then measure the refetch cooldown of oidc_login; the JWK Set max-age and the token lifetimes are shortened in apps/op/.env.local for the time of the run (about six minutes)',
    )]
    bool $rotate = false,
    #[AsOption(
        description: 'The third success criterion of spike 3 (issue #93): sign in with a password, open /profile, be sent back to the OP by /vault with acr_values=phr and prompt=login, enrol a passkey and sign the assertion with a software authenticator (tests/demo/passkey-browser.php), open /vault with an ID token carrying acr=phr, log out; the passkey is revoked afterwards',
    )]
    bool $passkey = false,
    #[AsOption(
        description: 'The third success criterion of spike 4 (issue #137): the demo configured with response_mode=form_post, the authorization response posted back to its callback by the page of the OP, and what a SameSite cookie makes of that cross-site POST',
    )]
    bool $formPost = false,
    #[AsOption(
        description: 'The second success criterion of spike 4 (issue #137): a second instance of the demo on another client of the same OP, signed in on the same session, logged out by back-channel when the first instance logs out; the delay is measured and printed',
    )]
    bool $logoutOthers = false,
    #[AsOption(
        description: 'The last acceptance step of issue #61 (issue #64): the demo as a resource server behind the introspection endpoint, with an opaque access token and with an "at+jwt", the introspection response read as JSON and required signed (RFC 9701), and what revoking the token does to each',
    )]
    bool $resourceServer = false,
    #[AsOption(
        description: 'Issues #556 and #559: the API Platform API of oidc-demo under /api/v1, behind a firewall of its own; the access token the client holds is described by the OP at every request (RFC 7662), the document naming the scheme its page offers and the scope each operation needs, a write refused for the scope it was never granted, a token of another client of the demonstration served because the API asks the OP as each client whose secret it holds, the page where a session calls the API with its own token, and the few seconds the answer of the OP is kept played on both sides',
    )]
    bool $api = false,
    #[AsOption(
        description: 'The two criteria of spike 5 judged at the client (issue #167): oidc-demo signs in as before on a provider serving PAR, request objects, JARM, DPoP and mTLS, then its resource server is handed a token bound by DPoP, on both shapes of access token, and refuses the same token to whoever holds it without the key',
    )]
    bool $dpop = false,
    #[AsOption(
        description: 'The forge of clients (issue #582): every preset of the page composed, registered at the provider with an initial access token the console issued (RFC 7591), signed in with, read hop by hop and deleted again (RFC 7592), from a client that puts the whole authorization request in the URL of the browser to one that pushes it signed, reads a signed response, holds a bound token and opens an encrypted ID token; and one composition the walk writes itself, which no preset holds',
    )]
    bool $forge = false,
    #[AsOption(
        description: 'The first interoperability criterion of spike 6 (issue #228): a PHP CLI with no browser and no secret obtains a token by the device grant (tests/demo/device-cli.php), the code it shows is confirmed in a browser meanwhile, and every step is asserted',
    )]
    bool $device = false,
    #[AsOption(
        description: 'Issue #462: the pages of the demonstration where every flow this provider serves is drawn, the set of pictures read against the discovery document, then a device grant run and a backchannel run played hop by hop from a page, each hop showing the request that was sent and the answer that came back',
    )]
    bool $flows = false,
    #[AsOption(
        description: 'The second and third interoperability criteria of spike 6 (issue #228): a service obtains a token for itself for a resource it named, a gateway exchanges it to act on its behalf, and the resource server of the demonstration accepts the exchanged token, names the subject and the actor, and refuses a token addressed to another resource',
    )]
    bool $service = false,
    #[AsOption(
        description: 'Spike 6 (issue #299): a client asks for a user it names by login_hint, with a binding message, and that user finds the request on /account/approvals and allows it; both delivery modes, the client polling in one and called back on a listener of its own in the other (tests/demo/ciba-client.php)',
    )]
    bool $ciba = false,
    #[AsOption(
        description: 'Spike 6 (issue #299): an assertion signed by an issuer the tenant trusts, exchanged for an access token for the user it names (RFC 7523 §2.1), then the same assertion again, one about somebody no linked identity resolves, and one asking for "openid", all three refused the same way',
    )]
    bool $assertion = false,
    #[AsOption(
        description: 'Spike 6 (issue #299): a request carrying authorization_details, the detail read on the consent page before it is agreed to, then followed into the access token and into the introspection (RFC 9396), and a type nobody wired refused',
    )]
    bool $rar = false,
    #[AsOption(
        description: 'Spike 6 (issue #299): a program on the machine of its user, twice, on two ports of the loopback interface against one registration (RFC 8252 §7.3), and a redirection on a name rather than on the IP literal refused',
    )]
    bool $native = false,
    #[AsOption(
        description: 'Spike 6 (issue #311): a push service of the lab takes the notification of a backchannel request, a browser of the lab opens it (RFC 8291) and verifies who signed it (RFC 8292), nothing in it names the request (BCP 10027 §5.2), then a 503 brings the message back and a 410 takes the browser out',
    )]
    bool $push = false,
    #[AsOption(
        description: 'Spike 7 (issue #345): a client this provider never saw registers itself with an initial access token the console issued (RFC 7591), signs the development user in with the credentials it was answered, reads and replaces itself at the URI it was handed and is refused a member the provider does not offer (RFC 7592), then a second client registers on another host and the two pairwise "sub" of the same user are printed side by side; the token spent buys nothing more, and the client deletes itself',
    )]
    bool $register = false,
    #[AsOption(
        description: 'Spike 7 (issue #347): a client nothing of this provider authorises registers on a statement an authority the tenant pinned signed (RFC 7591 §2.3), what that authority says of it outranking what it said of itself, then signs the development user in like any other client; the same statement again, one signed by an authority pinned for something else, one addressed elsewhere and a request carrying none are refused',
    )]
    bool $attested = false,
    #[AsOption(
        description: 'Nobody answers for you, and nothing of the laboratory stands in for anybody. With --ciba the request is made for the development user, in poll mode, and the run waits while you read the notification your own browser received and answer on /account/approvals yourself. With --push there is no push service and no browser of the laboratory at all: the notification goes to the browsers you subscribed, through their own push services, and the run says which of them this provider reached and when',
    )]
    bool $byHand = false,
    #[AsOption(description: 'Stop the server of oidc-demo instead')]
    bool $stop = false,
): void {
    $isDemo = static fn (string $dir): bool => (
        file_exists($dir . '/config/packages/security.yaml') && str_contains((string) file_get_contents($dir . '/config/packages/security.yaml'), 'oidc_login')
    );
    $candidates = $dir === null ? DEMO_DIRS : [$dir];
    $dir = null;
    foreach ($candidates as $candidate) {
        $candidate = str_starts_with($candidate, '/') ? $candidate : getcwd() . '/' . $candidate;
        if ($isDemo($candidate)) {
            $dir = realpath($candidate) ?: $candidate;
            break;
        }
    }
    if ($dir === null) {
        io()->error(sprintf('oidc-demo is not in %s (no oidc_login firewall in config/packages/security.yaml). Pass --dir.', implode(' nor ', $candidates)));
        exit(1);
    }
    if ($stop) {
        run(['symfony', 'server:stop'], context: demo_context($dir)->withAllowFailure());

        return;
    }

    io()->title('oidc-demo against the development OP');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['BEFFROI_ISSUER', 'OIDC_DEMO_SECRET', 'BEFFROI_DEV_USER_PASSWORD'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
            exit(1);
        }
    }

    io()->section('Configuration');
    $fixture = [
        'OIDC_PROVIDER_URI' => $env['BEFFROI_ISSUER'],
        'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
        'OIDC_CLIENT_SECRET' => $env['OIDC_DEMO_SECRET'],
        // the declared clients beside this one keep secrets of their own, which the walks above never
        // swap (demo_forge_values)
        ...demo_forge_values($env),
    ];
    // RFC 7591 §1.2: the credential the registration endpoint asks for in the mode the forge plays, issued
    // here and not in the walk below, because the server has to be started with it: the Symfony CLI hands
    // the names of this file to the PHP it runs, and a name written after it started is a name that server
    // does not have (demo_context).
    if ($forge) {
        $fixture['FORGE_INITIAL_ACCESS_TOKEN'] = demo_initial_access_token(DEMO_FORGE_TOKEN_NAME, count(DEMO_FORGE_PRESETS) + 1);
    }
    // .env.local only: the .env of the demo, which its repository holds, is not touched
    demo_write_env_local($dir . '/.env.local', $fixture);
    // The OP serves a certificate of Caddy's internal CA, which the PHP of the host does not know unless
    // the CA was installed on the machine: the demo runs with a php.ini of its own that trusts it, which
    // the Symfony CLI reads from the root of the project.
    $ca = caddy_ca($dir . '/var/caddy-root.crt');
    file_put_contents($dir . '/php.ini', sprintf(
        "; written by \"castor demo\" of the OP: trust the CA of Caddy for https://op.localhost\nopenssl.cafile=%s\ncurl.cainfo=%s\n",
        $ca,
        $ca,
    ));
    io()->text(sprintf('Issuer %s, client "%s", secret from apps/op/.env.local, CA of Caddy in %s.', $env['BEFFROI_ISSUER'], DEMO_CLIENT_ID, $ca));

    io()->section('Server');
    $server = demo_context($dir);
    demo_server($server, $fixture);
    io()->success(sprintf(
        '%s/profile signs in on %s as "%s", password %s.',
        DEMO_URL,
        $env['BEFFROI_ISSUER'],
        DEV_USERNAME,
        $env['BEFFROI_DEV_USER_PASSWORD'],
    ));

    if ($check) {
        demo_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($rotate) {
        demo_rotation_check($server, $env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($passkey) {
        demo_passkey_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($formPost) {
        demo_form_post_check($dir, $env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($resourceServer) {
        if (($env['OIDC_DEMO_OPAQUE_SECRET'] ?? '') === '') {
            io()->error('OIDC_DEMO_OPAQUE_SECRET is empty: run "castor provision" first.');
            exit(1);
        }
        demo_resource_server_check(
            $dir,
            $env['BEFFROI_ISSUER'],
            $env['BEFFROI_DEV_USER_PASSWORD'],
            $env['OIDC_DEMO_OPAQUE_SECRET'],
            $env['OIDC_DEMO_SECRET'],
            $ca,
        );
    }
    if ($api) {
        if (($env['OIDC_DEMO_OPAQUE_SECRET'] ?? '') === '') {
            io()->error('OIDC_DEMO_OPAQUE_SECRET is empty: run "castor provision" first.');
            exit(1);
        }
        demo_api_check(
            $dir,
            $env['BEFFROI_ISSUER'],
            $env['BEFFROI_DEV_USER_PASSWORD'],
            $env['OIDC_DEMO_SECRET'],
            $env['OIDC_DEMO_OPAQUE_SECRET'],
            $ca,
        );
    }
    if ($dpop) {
        if (($env['OIDC_DEMO_OPAQUE_SECRET'] ?? '') === '') {
            io()->error('OIDC_DEMO_OPAQUE_SECRET is empty: run "castor provision" first.');
            exit(1);
        }
        demo_dpop_check($dir, $env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $env['OIDC_DEMO_SECRET'], $env['OIDC_DEMO_OPAQUE_SECRET'], $ca);
    }
    if ($forge) {
        demo_forge_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($device) {
        demo_device_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($flows) {
        if (($env[DEMO_CIBA_CLIENTS['poll']['secret']] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', DEMO_CIBA_CLIENTS['poll']['secret']));
            exit(1);
        }
        if (($env['BEFFROI_DEV_USER_SUBJECT'] ?? '') === '') {
            io()->error('BEFFROI_DEV_USER_SUBJECT is empty: run "castor provision" first, which writes the subject this provider issued the development user and which the backchannel flow of the demonstration names its user by.');
            exit(1);
        }
        demo_flows_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($service) {
        foreach (['DEMO_SERVICE_SECRET', 'DEMO_GATEWAY_SECRET'] as $name) {
            if (($env[$name] ?? '') === '') {
                io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
                exit(1);
            }
        }
        demo_service_check($dir, $env['BEFFROI_ISSUER'], $env['DEMO_SERVICE_SECRET'], $env['DEMO_GATEWAY_SECRET'], $ca);
    }
    if ($ciba) {
        $secrets = [];
        foreach (DEMO_CIBA_CLIENTS as $registration) {
            if (($env[$registration['secret']] ?? '') === '') {
                io()->error(sprintf('%s is empty: run "castor provision" first.', $registration['secret']));
                exit(1);
            }
            $secrets[$registration['secret']] = $env[$registration['secret']];
        }
        if (($env['BEFFROI_DEV_USER_SUBJECT'] ?? '') === '') {
            io()->error('BEFFROI_DEV_USER_SUBJECT is empty: run "castor provision" first, which writes the subject this provider issued the development user.');
            exit(1);
        }
        demo_ciba_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca, $env['BEFFROI_DEV_USER_SUBJECT'], $secrets, $byHand);
    }
    if ($assertion) {
        if (($env['DEMO_ASSERTION_SECRET'] ?? '') === '') {
            io()->error('DEMO_ASSERTION_SECRET is empty: run "castor provision" first.');
            exit(1);
        }
        if (! is_file(getcwd() . '/' . DEMO_ASSERTION_JWKS)) {
            io()->error(sprintf('%s does not exist: run "castor provision" first, which generates the key of the trusted issuer.', DEMO_ASSERTION_JWKS));
            exit(1);
        }
        demo_assertion_check($env['BEFFROI_ISSUER'], $ca, $env['DEMO_ASSERTION_SECRET']);
    }
    if ($rar) {
        if (($env['DEMO_RAR_SECRET'] ?? '') === '') {
            io()->error('DEMO_RAR_SECRET is empty: run "castor provision" first.');
            exit(1);
        }
        demo_rar_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca, $env['DEMO_RAR_SECRET']);
    }
    if ($native) {
        demo_native_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($register) {
        demo_register_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($attested) {
        demo_attested_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if ($push) {
        $registration = DEMO_CIBA_CLIENTS['poll'];
        if (($env[$registration['secret']] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $registration['secret']));
            exit(1);
        }
        if ($byHand) {
            if (($env['BEFFROI_DEV_USER_SUBJECT'] ?? '') === '') {
                io()->error('BEFFROI_DEV_USER_SUBJECT is empty: run "castor provision" first, which writes the subject this provider issued the development user.');
                exit(1);
            }
            demo_push_by_hand(
                $env['BEFFROI_ISSUER'],
                $env['BEFFROI_DEV_USER_PASSWORD'],
                $ca,
                $registration['client'],
                $env[$registration['secret']],
                $env['BEFFROI_DEV_USER_SUBJECT'],
            );
        } else {
            demo_push_check($env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $ca, [
                $registration['secret'] => $env[$registration['secret']],
            ]);
        }
    }
    if ($logoutOthers) {
        if (($env['OIDC_DEMO_SECOND_SECRET'] ?? '') === '') {
            io()->error('OIDC_DEMO_SECOND_SECRET is empty: run "castor provision" first.');
            exit(1);
        }
        demo_logout_others_check($dir, $env['BEFFROI_ISSUER'], $env['BEFFROI_DEV_USER_PASSWORD'], $env['OIDC_DEMO_SECOND_SECRET'], $ca);
    }
}

/**
 * The context the commands of the demonstration run in: its directory, and not one of the names its
 * .env.local carries, the file this walk writes its secrets into.
 *
 * This walk reads the dotenv of the provider to hand the demonstration its secrets, and reading it puts
 * every value in the environment of this process, from where every child inherits it as a real
 * environment variable. A real environment variable wins over a dotenv file, and a server started as a
 * daemon keeps the environment it was started with for as long as it lives. Two names are the same on
 * both sides, DEMO_RAR_SECRET being one, so a server older than the "castor provision" that regenerated
 * it authenticated that client with the secret of the provisioning before it, and the provider answered
 * "401 invalid_client" to a client that had asked for nothing wrong (issue #491). What that file says is what the server serves, and it is read again at every request:
 * the walks already count on that, demo_form_post_check writing a response mode and playing it without
 * starting anything again.
 */
function demo_context(string $dir): Context
{
    $written = [];
    $path = $dir . '/.env.local';
    if (is_file($path)) {
        preg_match_all('/^([A-Z][A-Z0-9_]*)=/m', (string) file_get_contents($path), $names);
        foreach ($names[1] as $name) {
            // "false" takes the name out of the environment of the child, where "null" would hand it the
            // empty string, which is a value and wins over the file just the same
            $written[$name] = false;
        }
    }

    return context()->withWorkingDirectory($dir)->withEnvironment($written);
}

/**
 * The server of the demonstration, listening and serving the fixture this walk has just written.
 *
 * A server that is up already is compared with that fixture before anything is played against it, and
 * the run stops on a name it holds another value for: the walk that hands the demonstration its secrets
 * is the walk that must know the server has them, and a red read at the token endpoint of the provider
 * would be a red that is not the provider's (issue #491).
 *
 * @param array<string, string> $fixture what demo_write_env_local has just written
 */
function demo_server(Context $server, array $fixture): void
{
    // the discovery document of the previous issuer may still be cached
    run(['php', 'bin/console', 'cache:clear'], context: $server->withQuiet());
    $status = run(['symfony', 'server:status', '--no-ansi'], context: $server->withAllowFailure()->withQuiet())->getOutput();
    if (! str_contains($status, 'Listening on')) {
        demo_server_start($server);

        return;
    }

    $stale = demo_server_stale_values($status, $fixture);
    if ($stale === null) {
        // nothing here says what a running process was started with, so there is nothing to compare: the
        // server is started again rather than played against on trust, which is the other way to answer
        // the same question
        io()->note('What the server of oidc-demo was started with cannot be read here, so it is started again.');
        run(['symfony', 'server:stop'], context: $server->withQuiet()->withAllowFailure());
        demo_server_start($server);

        return;
    }
    if ($stale !== []) {
        io()->error([
            sprintf(
                'The server of oidc-demo holds another value than the one just written for %s.',
                implode(' and ', $stale),
            ),
            'It keeps the environment it was started with for as long as it lives, and a real environment variable wins over the .env.local this walk writes: it authenticates with the secret of the provisioning it was started after, and the provider answers "401 invalid_client" to a client that asked for nothing wrong. Run "castor demo --stop", then run this again.',
        ]);
        exit(1);
    }

    io()->note('The server of oidc-demo runs already; "castor demo --stop" stops it.');
}

/**
 * Starts the server of the demonstration as a daemon, on the port of DEMO_URL.
 */
function demo_server_start(Context $server): void
{
    run(['symfony', 'server:start', '--port=' . parse_url(DEMO_URL, \PHP_URL_PORT), '--daemon'], context: $server);
}

/**
 * The names of the fixture the running server of the demonstration holds another value for, read from the
 * environment of the processes "symfony server:status" names, or null where the environment of a running
 * process cannot be read, nothing of the fixture being then comparable with anything.
 *
 * @param array<string, string> $fixture
 *
 * @return list<string>|null
 */
function demo_server_stale_values(string $status, array $fixture): ?array
{
    preg_match_all('/^\s*PID (\d+):/m', $status, $matches);
    if ($matches[1] === []) {
        return null;
    }

    $stale = [];
    foreach ($matches[1] as $pid) {
        $environment = sprintf('/proc/%s/environ', $pid);
        if (! is_readable($environment)) {
            return null;
        }
        foreach (explode("\0", (string) file_get_contents($environment)) as $variable) {
            [$name, $value] = array_pad(explode('=', $variable, 2), 2, '');
            if (isset($fixture[$name]) && ! hash_equals($fixture[$name], $value)) {
                $stale[$name] = $name;
            }
        }
    }

    return array_values($stale);
}

/**
 * What the declared clients of this tenant need of the OP beside the one the demonstration signs in as,
 * read where "castor provision" left it: the secret of each. A secret that is not there yet is left out
 * rather than written empty, so that a demonstration configured before the provisioning says which client
 * is missing instead of failing to boot.
 *
 * @param array<string, string> $env apps/op/.env of the monorepo, .env.local merged over it
 *
 * @return array<string, string>
 */
function demo_forge_values(array $env): array
{
    $values = [];
    foreach (DEMO_FORGE_SECRETS as $name => $variable) {
        if (($env[$name] ?? '') !== '') {
            $values[$variable] = $env[$name];
        }
    }

    return $values;
}

/**
 * Sets or replaces the given variables in a dotenv file and keeps every other line.
 *
 * @param array<string, string> $values
 */
function demo_write_env_local(string $path, array $values): void
{
    $lines = file_exists($path) ? explode("\n", rtrim((string) file_get_contents($path), "\n")) : [];
    foreach ($values as $name => $value) {
        $line = sprintf('%s=%s', $name, $value);
        $written = false;
        foreach ($lines as $index => $existing) {
            if (str_starts_with($existing, $name . '=')) {
                $lines[$index] = $line;
                $written = true;
            }
        }
        if (! $written) {
            $lines[] = $line;
        }
    }
    file_put_contents($path, implode("\n", array_filter($lines, static fn (string $line): bool => $line !== '')) . "\n");
}

/**
 * The success criterion of spike 1, second half, from the command line: what a browser does from
 * /profile of the demo to the login page of the OP, the callback, /profile again and the logout, one
 * request at a time (no redirect followed), so that every step is looked at: PKCE S256 in the
 * authorization request, "iss" on the callback (RFC 9207), an "at+jwt" access token and an ID token with
 * the nonce on the page, the RP-Initiated Logout round trip, and no session left at the OP afterwards.
 */
function demo_check(string $issuer, string $password, string $ca): void
{
    io()->section('Sign in, /profile, logout');
    $cookies = [];
    $verified = [];

    $session = demo_sign_in($cookies, $issuer, $password, $ca);
    $verified[] = ['Authorization request', 'response_type=code, client_id=' . DEMO_CLIENT_ID . ', PKCE S256, nonce, state'];
    $verified[] = ['Authorization response', 'code, state, iss=' . $issuer];
    $idToken = $session['tokens']['id_token']['claims'];
    $accessToken = $session['tokens']['access_token']['claims'];
    $verified[] = ['/profile', sprintf('sub %s, %d claims from UserInfo', $idToken['sub'] ?? '?', preg_match_all('/<tr><th>[a-z_]+<\/th>/', $session['page']))];
    $verified[] = ['ID token', sprintf('nonce, auth_time, acr=%s, amr=%s, at_hash, sid', $idToken['acr'] ?? '?', json_encode($idToken['amr'] ?? null))];
    $verified[] = ['Access token', sprintf('typ=at+jwt, scope="%s", jti %s', $accessToken['scope'] ?? '?', $accessToken['jti'] ?? '?')];

    // RP-Initiated Logout: the demo ends its session and the one of the OP, which sends the browser back
    demo_logout($cookies, $issuer, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), '/profile asks for a new login');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?'), 'the OP asks for a login again: its session ended');
    $verified[] = ['RP-Initiated Logout', 'id_token_hint verified, back to ' . DEMO_URL . '/, the OP asks for a login again'];

    io()->table(['Step', 'Verified'], $verified);
    io()->note(sprintf(
        'The refresh of the access token (refresh_access_token) happens on the first request after it expired, ten minutes after the login (access_token_ttl of the application): sign in from a browser, open %s/profile again then and compare the "jti"; "castor demo --rotate" sees it happen with a shorter lifetime.',
        DEMO_URL,
    ));
    io()->success('oidc-demo signed in, opened /profile and logged out against the OP, without a patch.');
}

/**
 * The browser with a software authenticator of the passkey check: the enrolment and the assertion, driven
 * over HTTP against the OP by the SoftwareAuthenticator of the functional tests, under the autoloader of
 * the monorepo, which castor does not load.
 */
const DEMO_PASSKEY_BROWSER = 'tests/demo/passkey-browser.php';

/**
 * The class /vault of the demo requires (OpenID Connect EAP ACR Values 1.0), the one of the default policy
 * of the tenant a passkey proves (decision 0010 of the design repository).
 */
const DEMO_PASSKEY_CLASS = 'phr';

/**
 * What the walk calls the key it enrols, before the instant it appends to tell two runs apart. A person
 * typed that name, so the column holding it is sealed, and "castor dump-search" looks for this prefix in a
 * dump of the database: read there rather than typed again, so that renaming it here renames what is
 * searched for.
 */
const DEMO_PASSKEY_NAME_PREFIX = 'castor demo --passkey ';

/**
 * The third success criterion of spike 3 (issue #93): oidc-demo, on Symfony's oidc_login without a patch,
 * requires a phishing-resistant login on /vault and gets one. From the command line, one request at a
 * time as demo_check: a password sign-in through the demo and /profile open, whose ID token says acr "1";
 * /vault, which access_control protects with REQUIRES_PHR, an attribute of the demonstration, sends the browser back to
 * the authorization endpoint with acr_values=phr, prompt=login and the previous ID token as id_token_hint
 * (the re-authentication entry point of oidc_login); the OP asks for a login, where the browser of
 * DEMO_PASSKEY_BROWSER enrols a passkey on the account of its session and signs the assertion; the OP
 * records the proof on the same session, resumes the interaction and sends the browser to the callback
 * with a code; the demo verifies the new ID token (acr=phr, "hwk" in amr, the same sid, a later auth_time)
 * and opens /vault, which prints what oidc_login recorded on the security token. Then the RP-Initiated
 * Logout round trip, across the step-up: one session, one sid. The passkey is revoked at the end, so that
 * the user is left as found.
 */
function demo_passkey_check(string $issuer, string $password, string $ca): void
{
    io()->section('Sign in with a password, /vault asks for a passkey, logout');
    $cookies = [];
    $verified = [];
    $host = (string) parse_url($issuer, \PHP_URL_HOST);

    $session = demo_sign_in($cookies, $issuer, $password, $ca);
    $before = $session['tokens']['id_token']['claims'];
    demo_expect(($before['acr'] ?? null) !== DEMO_PASSKEY_CLASS, sprintf(
        'the ID token of a password login says acr=%s, not %s',
        json_encode($before['acr'] ?? null),
        DEMO_PASSKEY_CLASS,
    ));
    $verified[] = [
        'Password login',
        sprintf(
            '/profile open, acr=%s, amr=%s, auth_time %s, sid %s',
            $before['acr'] ?? '?',
            json_encode($before['amr'] ?? null),
            $before['auth_time'] ?? '?',
            $before['sid'] ?? '?',
        ),
    ];

    // /vault: the demo denies REQUIRES_PHR and starts the re-authentication from its access denied handler
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/vault');
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/authorize?'),
        sprintf('/vault sends the browser back to the authorization endpoint (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
    demo_expect(($authorization['acr_values'] ?? null) === DEMO_PASSKEY_CLASS && ($authorization['prompt'] ?? null) === 'login', sprintf(
        'the authorization request carries acr_values=%s and prompt=login',
        DEMO_PASSKEY_CLASS,
    ));
    demo_expect(
        ($authorization['id_token_hint'] ?? null) === $session['tokens']['id_token']['raw'],
        'the authorization request carries the previous ID token as id_token_hint',
    );
    demo_expect(
        ($authorization['code_challenge_method'] ?? null) === 'S256' && isset($authorization['state'], $authorization['nonce']),
        'it stays an ordinary authorization request: PKCE S256, state, nonce',
    );
    $verified[] = ['/vault', sprintf('302 to the OP with acr_values=%s, prompt=login, id_token_hint', DEMO_PASSKEY_CLASS)];

    // the OP holds the session of the password login and asks for a login anyway (prompt=login)
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login?interaction='),
        sprintf('the OP asks for a login on its existing session (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $login);

    // the browser with the software authenticator: a passkey enrolled, the assertion signed and posted
    io()->text(' <comment>tests/demo/passkey-browser.php</comment>');
    $browser = run(
        ['php', DEMO_PASSKEY_BROWSER],
        context: context()
            ->withQuiet()
            ->withAllowFailure()
            ->withEnvironment([
                'XDEBUG_MODE' => 'off',
            ])
            ->withInput(json_encode(
                [
                    'issuer' => $issuer,
                    'cafile' => $ca,
                    'cookies' => $cookies[$host] ?? [],
                    'interaction' => (string) ($login['interaction'] ?? ''),
                    'name' => DEMO_PASSKEY_NAME_PREFIX . date('Y-m-d H:i:s'),
                    'username' => DEV_USERNAME,
                ],
                \JSON_THROW_ON_ERROR,
            )),
    );
    // the steps of the browser, then the reason of a failure without the trace of the exception that ends it
    foreach (explode("\n", rtrim($browser->getErrorOutput(), "\n")) as $line) {
        if (str_starts_with($line, 'Stack trace:')) {
            break;
        }
        if ($line !== '') {
            io()->text(' ' . preg_replace('/^PHP Fatal error:\s+Uncaught \w+: (.*) in \S+:\d+$/', '$1', $line));
        }
    }
    demo_expect($browser->isSuccessful(), 'the passkey is enrolled and the assertion accepted');
    $passkey = (array) json_decode($browser->getOutput(), true, 4, \JSON_THROW_ON_ERROR);
    $cookies[$host] = (array) ($passkey['cookies'] ?? []);
    $verified[] = [
        'Passkey',
        sprintf(
            'enrolled on the account page (credential %s), assertion signed (sign count %d) and accepted on the login page',
            $passkey['credential_id'] ?? '?',
            $passkey['sign_count'] ?? 0,
        ),
    ];

    // the login page resumes the interaction: the browser goes to the callback with a code
    [$status, $location] = demo_resume($cookies, $ca, $issuer, (string) ($passkey['location'] ?? ''));
    demo_expect(
        $status === 302 && str_starts_with($location, DEMO_URL . '/oidc/callback?'),
        sprintf('the OP sends the browser to the callback of the demo (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(
        isset($callback['code']) && ($callback['state'] ?? null) === $authorization['state'] && ($callback['iss'] ?? null) === $issuer,
        'the callback carries a code, the state of the re-authentication and iss',
    );
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/vault', sprintf(
        'the demo verifies the ID token and sends the browser back to /vault (got %d %s)',
        $status,
        $location,
    ));
    $verified[] = ['Callback', 'code exchanged, ID token verified, back to /vault'];

    // /vault opens: what oidc_login recorded from the new ID token
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/vault');
    demo_expect($status === 200, sprintf('/vault opens (got %d)', $status));
    $received = [];
    foreach (['acr', 'amr', 'auth-time', 'sid'] as $name) {
        $received[$name] = preg_match(sprintf('/<code data-%s>([^<]*)<\/code>/', $name), $page, $found) === 1 ? html_entity_decode($found[1]) : '';
    }
    $amr = (array) json_decode($received['amr'], true);
    demo_expect($received['acr'] === DEMO_PASSKEY_CLASS, sprintf('the ID token says acr=%s (got %s)', DEMO_PASSKEY_CLASS, json_encode($received['acr'])));
    demo_expect(
        in_array('hwk', $amr, true) && in_array('pwd', $amr, true),
        sprintf('amr lists the passkey and the password of the same session (got %s)', $received['amr']),
    );
    demo_expect($received['sid'] === ($before['sid'] ?? null), sprintf(
        'the sid is the one of the password login: one session on the OP (got %s)',
        $received['sid'],
    ));
    demo_expect((int) $received['auth-time'] >= (int) ($before['auth_time'] ?? 0), sprintf(
        'auth_time is the passkey\'s (%s, was %s)',
        $received['auth-time'],
        $before['auth_time'] ?? '?',
    ));
    $verified[] = [
        '/vault',
        sprintf('open; oidc_login received acr=%s, amr=%s, auth_time %s, sid %s', $received['acr'], $received['amr'], $received['auth-time'], $received['sid']),
    ];

    // RP-Initiated Logout across the step-up: the hint is the new ID token, the one session ends
    $kid = demo_logout($cookies, $issuer, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), '/profile asks for a new login');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?'), 'the OP asks for a login again: its session ended');
    $verified[] = [
        'RP-Initiated Logout',
        sprintf('id_token_hint of the step-up verified (kid %s), back to %s/, the OP asks for a login again', $kid, DEMO_URL),
    ];

    // the passkey of the run is revoked: beffroi:user:show lists it by its name, beffroi:user:revoke-credential takes its identifier
    $shown = op_console(['beffroi:user:show', DEV_USERNAME], context()->withQuiet())->getOutput();
    $name = 'castor demo --passkey';
    demo_expect(
        preg_match('/^\s*passkey\s+([0-9a-f-]{36})\s+' . preg_quote($name, '/') . '/m', $shown, $found) === 1,
        'beffroi:user:show lists the passkey of the run',
    );
    op_console(['beffroi:user:revoke-credential', DEV_USERNAME, $found[1]], context()->withQuiet());
    $verified[] = ['Cleanup', sprintf('passkey %s revoked (beffroi:user:revoke-credential)', $found[1])];

    io()->table(['Step', 'Verified'], $verified);
    io()->success(sprintf(
        'oidc-demo required acr_values=%s on /vault and got a passkey login against the OP, without a patch of oidc_login.',
        DEMO_PASSKEY_CLASS,
    ));
}

/**
 * The variable of the demo that says which response mode the provider is asked for
 * (config/packages/security.yaml of oidc-demo, "authorization_params"), written into its .env.local
 * for the time of a run and left on "query", which is the default of the code flow.
 */
const DEMO_RESPONSE_MODE_ENV = 'OIDC_RESPONSE_MODE';

/**
 * The cookie the session of the demo is carried by: the name PHP gives it, the demo configuring none.
 */
const DEMO_SESSION_COOKIE = 'PHPSESSID';

/**
 * The third success criterion of spike 4 (issue #137): oidc-demo receives a "form_post" response and
 * finds its session again, "state" and PKCE verifier included. The demo is configured with
 * response_mode=form_post for the run, and the round trip is played one request at a time as
 * demo_check does, up to the page the OP answers the authorization request with: a form that posts the
 * response to the callback of the demo, which is the one thing about this mode that is not a redirect
 * like any other, a cross-site POST.
 *
 * The unknown of the spike is in the session cookie of the demo. A browser sends a "SameSite=Lax"
 * cookie, the default, on a top-level navigation and never on a cross-site POST, so the very same POST
 * is played twice, with the cookies the demo set and without them: that is what the callback looks like
 * under each value of the attribute. The value the demo actually sets is read from its Set-Cookie and
 * printed; the rule itself is applied here, because it is a browser that enforces it and this is not
 * one.
 */
function demo_form_post_check(string $dir, string $issuer, string $password, string $ca): void
{
    io()->section('response_mode=form_post');
    demo_write_env_local($dir . '/.env.local', [
        DEMO_RESPONSE_MODE_ENV => 'form_post',
    ]);

    try {
        $cookies = [];
        $verified = [];

        // /profile: the demo starts the flow, asking for the mode it is configured with
        $setCookies = [];
        [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile', setCookies: $setCookies);
        demo_expect(
            $status === 302 && str_starts_with($location, $issuer . '/authorize?'),
            sprintf('/profile sends the browser to the authorization endpoint (got %d %s)', $status, $location),
        );
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
        demo_expect(($authorization['response_mode'] ?? null) === 'form_post', 'the authorization request asks for response_mode=form_post');
        $sameSite = demo_same_site_of($setCookies, DEMO_SESSION_COOKIE);
        demo_expect($sameSite !== null, 'the demo opened a session to hold the "state" and the PKCE verifier of the attempt');
        $verified[] = ['Authorization request', 'response_type=code, PKCE S256, response_mode=form_post'];

        // the login of the OP, unchanged: the mode says how the response comes back, not how it is obtained
        [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
        demo_expect(
            $status === 302 && str_starts_with($location, $issuer . '/login?interaction='),
            sprintf('the OP asks for a login (got %d %s)', $status, $location),
        );
        [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
        demo_expect($status === 200, sprintf('the login page opens (got %d)', $status));
        $page = demo_past_the_address($cookies, $ca, $issuer, $page);
        $form = demo_form_with($page, '_username', 'the login page carries the form of the password');
        demo_expect(
            preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
            'which says where it posts and carries its token',
        );
        [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
            '_username' => DEV_USERNAME,
            '_password' => $password,
            '_csrf_token' => $csrf[1],
        ]);
        demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));

        // and here the mode shows: a page, not a redirection
        [$status, $location, $page, $headers] = demo_resume($cookies, $ca, $issuer, $location);
        demo_expect($status === 200 && $location === '', sprintf(
            'the OP answers the authorization request with a page of its own, not with a redirection (got %d %s)',
            $status,
            $location,
        ));
        demo_expect(str_contains($headers['cache-control'][0] ?? '', 'no-store'), 'the page is never cached (Form Post Response Mode §2)');
        demo_expect(preg_match('/form[^>]+method="post"[^>]+action="([^"]+)"/i', $page, $form) === 1, 'the page carries a form that posts');
        $formAction = html_entity_decode($form[1]);
        demo_expect($formAction === DEMO_URL . '/oidc/callback', sprintf('the form posts to the callback of the demo (got %s)', $formAction));
        $response = demo_form_fields($page);
        demo_expect(
            isset($response['code'], $response['state']) && ($response['iss'] ?? null) === $issuer,
            'the form carries code, state and iss (RFC 9207), as a query string would',
        );
        $verified[] = ['Authorization response', sprintf('a form of %d fields posted to %s, no-store', count($response), $formAction)];

        // the cross-site POST, first as a browser makes it of a cookie it does not send
        $withoutCookies = [];
        [$status, $location] = demo_request($withoutCookies, $ca, 'POST', $formAction, $response);
        demo_expect($status === 302 && $location === DEMO_URL . '/login', sprintf(
            'without the session cookie, the demo refuses the callback and sends the browser to its failure path (got %d %s)',
            $status,
            $location,
        ));
        [$status, , $page] = demo_request($withoutCookies, $ca, 'GET', DEMO_URL . '/login');
        demo_expect(preg_match('/<code>([^<]+)<\/code>/', $page, $detail) === 1, 'the login page of the demo says why');
        $refusal = html_entity_decode($detail[1]);
        demo_expect(
            str_contains($refusal, 'state'),
            sprintf('the login fails on the "state", which the session it did not receive was holding: "%s"', $refusal),
        );
        $verified[] = ['Cookie withheld', sprintf('"%s", which is what SameSite=Lax makes of the POST', $refusal)];

        // then as a browser makes it of a cookie it does send
        [$status, $location] = demo_request($cookies, $ca, 'POST', $formAction, $response);
        demo_expect($status === 302 && $location === DEMO_URL . '/profile', sprintf(
            'with the session cookie, the demo signs the user in (got %d %s)',
            $status,
            $location,
        ));
        [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
        demo_expect($status === 200, sprintf('/profile opens (got %d)', $status));
        $tokens = demo_tokens_of($page);
        demo_expect(isset($tokens['id_token'], $tokens['access_token']), '/profile shows an ID token and an access token');
        $verified[] = [
            'Cookie sent',
            sprintf('the code was exchanged, sub %s, acr=%s', $tokens['id_token']['claims']['sub'] ?? '?', $tokens['id_token']['claims']['acr'] ?? '?'),
        ];

        demo_logout($cookies, $issuer, $ca);
        $verified[] = ['Session cookie of the demo', sprintf('SameSite=%s (framework.session.cookie_samesite)', $sameSite)];

        io()->table(['Step', 'Verified'], $verified);
        io()->success(sprintf(
            'oidc-demo received a form_post response and found its session again, "state" and PKCE verifier included, on a "SameSite=%s" cookie; the same POST without the cookie fails on the "state".',
            $sameSite,
        ));
    } finally {
        demo_write_env_local($dir . '/.env.local', [
            DEMO_RESPONSE_MODE_ENV => 'query',
        ]);
    }
}

/**
 * The value of the "SameSite" attribute of the given cookie among the Set-Cookie headers of a response,
 * lowercased, or null when that cookie is not among them. PHP sends no attribute for "lax", which is
 * what a browser assumes anyway (RFC 6265bis §5.4.7).
 *
 * @param list<string> $setCookies
 */
function demo_same_site_of(array $setCookies, string $name): ?string
{
    foreach ($setCookies as $cookie) {
        if (! str_starts_with($cookie, $name . '=')) {
            continue;
        }

        return preg_match('/;\s*samesite=([a-z]+)/i', $cookie, $matches) === 1 ? strtolower($matches[1]) : 'lax';
    }

    return null;
}

/**
 * The fields of the self-submitting form of a "form_post" response, by name (Form Post Response Mode §2:
 * one hidden input per parameter of the authorization response).
 *
 * @return array<string, string>
 */
function demo_form_fields(string $page): array
{
    preg_match_all('/<input[^>]+type="hidden"[^>]*>/i', $page, $inputs);
    $fields = [];
    foreach ($inputs[0] as $input) {
        if (preg_match('/name="([^"]+)"/', $input, $name) === 1 && preg_match('/value="([^"]*)"/', $input, $value) === 1) {
            $fields[html_entity_decode($name[1])] = html_entity_decode($value[1]);
        }
    }

    return $fields;
}

/**
 * The second success criterion of spike 4 (issue #137): two instances of oidc-demo signed in on one
 * session of the OP, and the second logged out by back-channel when the first logs out, without its user
 * going through it. The first instance is the one already running; the second is the same checkout,
 * started on another port as another client (demo_second_instance), which is what gives it a session and
 * a back-channel logout endpoint of its own.
 *
 * What is measured is the whole delay the issue asks for: from the logout request of the first instance
 * to the moment the second one refuses to serve its page again. It covers the end of the session, the
 * event, the queue, the worker and the POST to the client (issue #136).
 */
function demo_logout_others_check(string $dir, string $issuer, string $password, string $secret, string $ca): void
{
    io()->section('Two instances on one OP, the second logged out by back-channel');
    $second = demo_second_instance($dir, $issuer, $secret, $ca);

    try {
        $cookies = [];
        $verified = [];

        $first = demo_sign_in($cookies, $issuer, $password, $ca);
        $sid = $first['tokens']['id_token']['claims']['sid'] ?? null;
        demo_expect(is_string($sid) && $sid !== '', 'the first instance is signed in, and its ID token names the session of the OP');
        $verified[] = [DEMO_CLIENT_ID, sprintf('signed in, sid %s', $sid)];

        $secondTokens = demo_second_sign_in($cookies, $issuer, $ca);
        demo_expect(
            ($secondTokens['id_token']['claims']['sid'] ?? null) === $sid,
            'the second instance signed in on the same session of the OP: the same "sid"',
        );
        demo_expect(
            in_array(DEMO_SECOND_CLIENT_ID, (array) ($secondTokens['id_token']['claims']['aud'] ?? []), true),
            'its ID token is the one of the second client',
        );
        $verified[] = [DEMO_SECOND_CLIENT_ID, 'signed in on the same session, without a login page'];

        // the first instance logs out: its own session, then the one of the OP, and nothing of the second
        $startedAt = hrtime(true);
        demo_logout($cookies, $issuer, $ca);
        $verified[] = ['RP-Initiated Logout', sprintf('from %s, which the second instance is told nothing of', DEMO_URL)];

        $elapsed = demo_wait_for_logout($cookies, $ca, $startedAt);
        $verified[] = ['Back-channel logout', sprintf('%s asks for a login again %.1f s later', DEMO_SECOND_URL, $elapsed)];

        io()->table(['Step', 'Verified'], $verified);
        io()->success(sprintf(
            'The second instance was logged out %.1f s after the first one logged out, by a logout token the OP posted to it: the whole delay, from the logout request to the page it refuses to serve again.',
            $elapsed,
        ));
    } finally {
        $second->stop();
    }
}

/**
 * The second instance of the demo: the same checkout, the built-in server of PHP because the server of
 * the Symfony CLI is one per directory and the first instance already holds this one, and the client of
 * its own that the OP registers with a back-channel logout URI. Everything that tells the two instances
 * apart is passed as an environment variable, which the dotenv of the demo does not override; it listens
 * on every address, because the worker of the stack reaches it from its container.
 */
function demo_second_instance(string $dir, string $issuer, string $secret, string $ca): Process
{
    $port = (string) parse_url(DEMO_SECOND_URL, \PHP_URL_PORT);
    // variables_order: the built-in server of PHP does not put the environment of the process into
    // $_ENV unless it is asked to, and the dotenv of the demo only steps aside for what is there
    $server = new Process(
        [
            'php',
            '-d',
            'variables_order=EGPCS',
            '-d',
            'openssl.cafile=' . $ca,
            '-d',
            'curl.cainfo=' . $ca,
            '-S',
            '0.0.0.0:' . $port,
            '-t',
            'public',
            'public/index.php',
        ],
        $dir,
        [
            'APP_ENV' => 'dev',
            'OIDC_PROVIDER_URI' => $issuer,
            'OIDC_CLIENT_ID' => DEMO_SECOND_CLIENT_ID,
            'OIDC_CLIENT_SECRET' => $secret,
            'OIDC_RESPONSE_MODE' => 'query',
        ],
    );
    $server->setTimeout(null);
    $server->start();

    $cookies = [];
    for ($attempt = 0; $attempt < 50; ++$attempt) {
        try {
            [$status] = demo_request($cookies, $ca, 'GET', DEMO_SECOND_URL . '/');
            if ($status === 200) {
                demo_expect(true, sprintf('the second instance answers on %s as client "%s"', DEMO_SECOND_URL, DEMO_SECOND_CLIENT_ID));

                return $server;
            }
        } catch (Throwable) {
        }
        usleep(200_000);
    }

    io()->error(sprintf("The second instance of oidc-demo did not start on %s:\n%s", DEMO_SECOND_URL, $server->getErrorOutput()));
    $server->stop();
    exit(1);
}

/**
 * A sign-in of the second instance on the session the first one opened: the OP answers the authorization
 * request from the session it holds, without a page of its own, which is what makes the two logins one
 * session. The tokens of its /profile are returned.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @return array<string, array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}>
 */
function demo_second_sign_in(array &$cookies, string $issuer, string $ca): array
{
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_SECOND_URL . '/profile');
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/authorize?'),
        sprintf('the second instance sends the browser to the authorization endpoint (got %d %s)', $status, $location),
    );

    for ($hop = 0; $hop < 5 && str_starts_with($location, $issuer); ++$hop) {
        [$status, $location] = demo_resume($cookies, $ca, $issuer, $location);
        demo_expect($status === 302, sprintf('the OP answers from the session it holds, without asking anything (got %d)', $status));
    }
    demo_expect(
        str_starts_with($location, DEMO_SECOND_URL . '/oidc/callback?'),
        sprintf('the OP sends the browser to the callback of the second instance (got %s)', $location),
    );

    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_SECOND_URL . '/profile', sprintf(
        'the second instance signs the user in (got %d %s)',
        $status,
        $location,
    ));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_SECOND_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile of the second instance opens (got %d)', $status));
    $tokens = demo_tokens_of($page);
    demo_expect(isset($tokens['id_token']), '/profile of the second instance shows an ID token');

    return $tokens;
}

/**
 * Waits for the second instance to ask for a login again, which is the logout token having arrived, and
 * returns the seconds elapsed since the given instant. The page is asked for ten times a second: the
 * delay printed is that of the whole path, granular to the poll.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_wait_for_logout(array &$cookies, string $ca, float|int $startedAt, float $timeout = 60.0): float
{
    while (($elapsed = (hrtime(true) - $startedAt) / 1e9) < $timeout) {
        [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_SECOND_URL . '/profile');
        if ($status === 302 && str_starts_with($location, 'https://')) {
            return (hrtime(true) - $startedAt) / 1e9;
        }
        usleep(100_000);
    }

    io()->error(sprintf('The second instance was still signed in %.0f s after the logout. What the worker did with the logout token:', $timeout));
    run(['docker', 'compose', 'logs', 'worker', '--tail', '20'], context: context()->withAllowFailure());
    exit(1);
}

/**
 * The client the OP issues opaque access tokens to (apps/op/config/packages/beffroi.yaml): the same
 * demonstration, registered a second time, so that the two shapes of access token are played one after
 * the other without the OP being reconfigured between them.
 */
const DEMO_OPAQUE_CLIENT_ID = 'oidc-demo-opaque';

/**
 * Where the resource server of the demonstration introspects the tokens it is presented with
 * (config/packages/framework.yaml of oidc-demo), written into its .env.local from the discovery
 * document of the OP.
 */
const DEMO_INTROSPECTION_ENV = 'OIDC_INTROSPECTION_URI';

/**
 * RFC 8414 §3: where a resource server looks for the metadata of its authorization server, which is where
 * Symfony's "oauth2" token handler reads the keys a signed introspection response is verified against. The
 * issuer of the development OP is an origin, so the path is simply appended to it (§3 inserts it before
 * the path of an issuer that carries one, where OIDC Discovery §4.1 appends it).
 */
const DEMO_AUTHORIZATION_SERVER_METADATA_PATH = '/.well-known/oauth-authorization-server';

/**
 * The last acceptance step of issue #61, the one that lives in another repository (issue #64):
 * `oidc-demo` is also a resource server, and the access token it holds for its user is checked in the
 * three ways Symfony's `access_token` authenticator offers, each behind a firewall of its own
 * (`/api/me`, `/api/me/signed`, `/api/me/offline`).
 *
 * The walk is played twice, once per registration, because what the client registered is what the
 * shape of its access token is (architecture §4.6):
 *
 * - as `oidc-demo-opaque`, whose token says nothing to whoever reads it: the resource server asks the
 *   OP what it is (RFC 7662), first reading the JSON answer, then requiring the signed one (RFC 9701),
 *   whose keys it finds through the RFC 8414 metadata of the OP, the one thing the OP did not serve
 *   yet. The token is then revoked, and the next call is refused: the OP is asked at every request, so
 *   it answers with what it knows now.
 * - as `oidc-demo`, whose token is an `at+jwt` the resource server verifies itself against the JWK Set
 *   of the OP, without asking it anything. That one cannot be revoked at all, and the OP says so
 *   (`unsupported_token_type`, RFC 7009 §2.2.1); what ends it is the end of the session, after which
 *   the OP refuses it at UserInfo (issue #150) while the resource server, which asks the OP nothing,
 *   goes on accepting it until it expires. That is the trade between the two shapes, seen rather than
 *   described.
 */
function demo_resource_server_check(string $dir, string $issuer, string $password, string $opaqueSecret, string $demoSecret, string $ca): void
{
    io()->section('A resource server behind the introspection endpoint');
    $verified = [];

    // RFC 8414 §3 and OIDC Discovery §4.1: one document, two well-known locations, and the token
    // handler of Symfony reads the keys of a signed introspection response at the first one
    $metadata = demo_metadata($issuer . '/.well-known/openid-configuration', $ca);
    $authorizationServer = demo_metadata($issuer . DEMO_AUTHORIZATION_SERVER_METADATA_PATH, $ca);
    demo_expect(
        $authorizationServer === $metadata,
        'the OP serves the same document at /.well-known/oauth-authorization-server (RFC 8414 §3) as at /.well-known/openid-configuration',
    );
    $introspection = (string) ($metadata['introspection_endpoint'] ?? '');
    demo_expect(
        $introspection !== '' && is_string($metadata['jwks_uri'] ?? null),
        'the document names the introspection endpoint and the JWK Set the signed answer is verified against',
    );
    $verified[] = ['Authorization server metadata', sprintf('%s, jwks_uri %s', DEMO_AUTHORIZATION_SERVER_METADATA_PATH, $metadata['jwks_uri'])];

    try {
        // an opaque access token: nothing to read, everything to ask
        demo_write_env_local($dir . '/.env.local', [
            'OIDC_CLIENT_ID' => DEMO_OPAQUE_CLIENT_ID,
            'OIDC_CLIENT_SECRET' => $opaqueSecret,
            DEMO_INTROSPECTION_ENV => $introspection,
        ]);
        $cookies = [];
        $tokens = demo_resource_server_sign_in($cookies, $issuer, $password, $ca, DEMO_OPAQUE_CLIENT_ID);
        $accessToken = $tokens['access_token'];
        demo_expect(substr_count($accessToken, '.') !== 2, sprintf('the access token of %s is opaque, not a JWS: "%s"', DEMO_OPAQUE_CLIENT_ID, $accessToken));
        $subject = (string) (demo_jwt($tokens['id_token'])['claims']['sub'] ?? '?');
        $verified[] = ['Opaque access token', sprintf('%d characters, no structure to read, sub %s on the ID token', strlen($accessToken), $subject)];

        [$status, $body] = demo_api(DEMO_URL . '/api/me', $accessToken);
        demo_expect($status === 200 && ($body['sub'] ?? null) === $subject, sprintf(
            'the resource server introspects the token and answers the sub of its badge (got %d %s)',
            $status,
            json_encode($body),
        ));
        $verified[] = ['/api/me', sprintf('200, sub %s, scope %s, %s', $body['sub'], json_encode($body['scope'] ?? null), $body['user_class'] ?? '?')];

        [$status, $body] = demo_api(DEMO_URL . '/api/me/signed', $accessToken);
        demo_expect($status === 200 && ($body['sub'] ?? null) === $subject, sprintf(
            'the same answer required signed (RFC 9701), verified against the keys of the OP found through its RFC 8414 metadata (got %d %s)',
            $status,
            json_encode($body),
        ));
        $verified[] = ['/api/me/signed', sprintf('200, the JWT answer verified, typ "%s"', 'token-introspection+jwt')];

        [$status, $body] = demo_revoke($issuer, $ca, DEMO_OPAQUE_CLIENT_ID, $opaqueSecret, $accessToken);
        demo_expect($status === 200, sprintf('the client revokes its own access token at /revoke (RFC 7009, got %d %s)', $status, json_encode($body)));
        [$status, $body] = demo_api(DEMO_URL . '/api/me', $accessToken);
        demo_expect($status === 401, sprintf('the very next call is refused: the OP is asked at every request (got %d %s)', $status, json_encode($body)));
        $verified[] = ['Revoked, then /api/me', '401, without the resource server knowing anything of the revocation'];
        demo_logout($cookies, $issuer, $ca);

        // an at+jwt: everything to read, nothing asked
        demo_write_env_local($dir . '/.env.local', [
            'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
            'OIDC_CLIENT_SECRET' => $demoSecret,
        ]);
        $cookies = [];
        $tokens = demo_resource_server_sign_in($cookies, $issuer, $password, $ca, DEMO_CLIENT_ID);
        $accessToken = $tokens['access_token'];
        $header = demo_jwt($accessToken)['header'];
        demo_expect(($header['typ'] ?? null) === 'at+jwt', sprintf(
            'the access token of %s is an at+jwt (RFC 9068 §2.1, got "%s")',
            DEMO_CLIENT_ID,
            $header['typ'] ?? '',
        ));
        $subject = (string) (demo_jwt($tokens['id_token'])['claims']['sub'] ?? '?');

        [$status, $body] = demo_api(DEMO_URL . '/api/me/offline', $accessToken);
        demo_expect($status === 200 && ($body['sub'] ?? null) === $subject, sprintf(
            'the resource server verifies the token itself, against the JWK Set of the OP, and answers the sub of its badge (got %d %s)',
            $status,
            json_encode($body),
        ));
        $verified[] = ['/api/me/offline', sprintf('200, sub %s, kid %s, nothing asked of the OP', $body['sub'], $header['kid'] ?? '?')];

        [$status, $body] = demo_revoke($issuer, $ca, DEMO_CLIENT_ID, $demoSecret, $accessToken);
        demo_expect($status === 400 && ($body['error'] ?? null) === 'unsupported_token_type', sprintf(
            'that one cannot be revoked at all, and the OP says so rather than answering 200 (RFC 7009 §2.2.1, got %d %s)',
            $status,
            json_encode($body),
        ));
        $verified[] = ['/revoke of an at+jwt', sprintf('400 %s, "%s"', $body['error'], $body['error_description'] ?? '')];

        // what ends it is the end of the session, which the OP knows and the resource server does not
        demo_logout($cookies, $issuer, $ca);
        demo_expect(demo_userinfo($issuer, $ca, $accessToken) === 401, 'the session ended, and the OP refuses the same token at UserInfo (issue #150)');
        [$status, $body] = demo_api(DEMO_URL . '/api/me/offline', $accessToken);
        demo_expect($status === 200, sprintf(
            'the offline resource server accepts it still: nothing told it, and nothing could (got %d %s)',
            $status,
            json_encode($body),
        ));
        $verified[] = ['Session ended, then /api/me/offline', '200 until the token expires, while UserInfo of the OP answers 401'];

        io()->table(['Step', 'Verified'], $verified);
        io()->success('oidc-demo checked its access token in the three ways Symfony offers, on the two shapes the OP issues, without a patch.');
        io()->note('An "at+jwt" is accepted by a resource server that verifies it offline until it expires (ten minutes here, BEFFROI_ACCESS_TOKEN_TTL), whatever the OP knows of it: a deployment that needs a withdrawal to be felt at once registers its client for opaque tokens, and its resource server introspects them (architecture §4.6). The OP itself is not in that case: it knows where its sessions live, and refuses at UserInfo and at the introspection endpoint the token of a session that ended, whatever its shape (issue #150).');
    } finally {
        demo_write_env_local($dir . '/.env.local', [
            'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
            'OIDC_CLIENT_SECRET' => $demoSecret,
        ]);
    }
}

/**
 * A sign-in through the demo for the resource server check: the walk of demo_sign_in, but the tokens are
 * read raw from the page, because an opaque access token has nothing demo_tokens_of() could tell it by.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @return array{id_token: string, access_token: string}
 */
function demo_resource_server_sign_in(array &$cookies, string $issuer, string $password, string $ca, string $clientId): array
{
    $location = demo_authenticate($cookies, $issuer, $password, $ca, $clientId);
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/profile', sprintf('the demo signs the user in (got %d %s)', $status, $location));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile opens (got %d)', $status));
    $tokens = demo_raw_tokens_of($page);
    demo_expect($tokens['id_token'] !== '' && $tokens['access_token'] !== '', '/profile shows an ID token and an access token');

    return $tokens;
}

/**
 * The two tokens the profile page prints in full, in the order it prints them: the ID token, then the
 * access token, whatever they are made of. demo_tokens_of() tells them apart by what they carry, which
 * an opaque access token carries nothing of.
 *
 * @return array{id_token: string, access_token: string}
 */
function demo_raw_tokens_of(string $page): array
{
    preg_match_all('/<pre class="jwt">([^<]*)<\/pre>/', $page, $matches);
    $raw = $matches[1]
    + [
        0 => '',
        1 => '',
    ];

    return [
        'id_token' => trim(html_entity_decode($raw[0])),
        'access_token' => trim(html_entity_decode($raw[1])),
    ];
}

/**
 * A document of the OP read as JSON, the CA of Caddy trusted as everywhere else in this file.
 *
 * @return array<string, mixed>
 */
function demo_metadata(string $url, string $ca): array
{
    $response = http_request('GET', $url, [
        'cafile' => $ca,
        'max_redirects' => 0,
    ]);
    demo_expect($response->getStatusCode() === 200, sprintf('%s answers 200 (got %d)', $url, $response->getStatusCode()));

    return (array) json_decode($response->getContent(false), true);
}

/**
 * A call of the resource server of the demo with a bearer token (RFC 6750 §2.1): its status and the JSON
 * it answered with. The demo serves a certificate of the Symfony CLI, verified against nothing, as
 * demo_request() does for it.
 *
 * @return array{int, array<string, mixed>}
 */
function demo_api(string $url, string $accessToken): array
{
    $response = http_request('GET', $url, [
        'max_redirects' => 0,
        'verify_peer' => false,
        'verify_host' => false,
        'auth_bearer' => $accessToken,
    ]);

    return [$response->getStatusCode(), (array) json_decode($response->getContent(false), true)];
}

/**
 * RFC 7009 §2.1: an access token revoked at the endpoint of the OP by the client it was issued to, which
 * authenticates the way it registered (client_secret_basic for the clients of the demonstration). Its
 * status and what it answered, because a refusal names itself (§2.2.1).
 *
 * @return array{int, array<string, mixed>}
 */
function demo_revoke(string $issuer, string $ca, string $clientId, string $secret, string $accessToken): array
{
    $response = http_request('POST', $issuer . '/revoke', [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_basic' => $clientId . ':' . $secret,
        'body' => [
            'token' => $accessToken,
            'token_type_hint' => 'access_token',
        ],
    ]);

    return [$response->getStatusCode(), (array) json_decode($response->getContent(false), true)];
}

/**
 * The presets of the forge, as its page offers them (`App\Forge\Presets` of the demonstration), and what
 * each one has to show for this walk to be satisfied: what the browser carried to the authorization
 * endpoint, the shape the answer came back in, the fragments the page of the built client must hold, and
 * the items of the Symfony status document that composition hits.
 *
 * The five rungs of the ladder this page replaced are the first five, which is why they are written in
 * that order: what a reader saw there is still reachable in one click. The three below them are
 * compositions the ladder had no rung for.
 *
 * A preset the provider refuses for a reason that is written down carries its issue in "known", and the
 * walk then asserts the refusal rather than a success it will not get, as the "known" list of the
 * conformance plans does.
 */
const DEMO_FORGE_PRESETS = [
    'basic' => [
        'carries' => 'parameters',
        'mode' => 'query',
        'returns' => 'query',
        'holds' => ['client_secret_basic', 'a self-contained access token'],
        'gaps' => [],
    ],
    'form-post' => [
        'carries' => 'parameters',
        'mode' => 'form_post',
        'returns' => 'form',
        'holds' => ['client_secret_post'],
        'gaps' => [],
    ],
    'key' => [
        'carries' => 'parameters',
        'mode' => 'query',
        'returns' => 'query',
        'holds' => ['private_key_jwt', 'Front-Channel Logout'],
        'gaps' => ['RP-07'],
        // the one preset whose sign-out is played too: the forge holds its own RP-Initiated Logout, this
        // firewall being none of "oidc_login"'s (ForgeLogoutListener of the demonstration)
        'signs_out' => true,
    ],
    'rar' => [
        'carries' => 'parameters',
        'mode' => 'query',
        'returns' => 'query',
        'holds' => ['authorization_details', 'invoice_payment'],
        'gaps' => [],
    ],
    'fapi' => [
        'carries' => 'request_uri',
        'mode' => null,
        'returns' => 'signed',
        'holds' => ['private_key_jwt', 'a JWE RSA-OAEP-256', 'application/jwt', 'jkt'],
        'gaps' => ['RP-04', 'RP-05', 'RP-06', 'RP-07'],
    ],
    'fapi-mtls' => [
        'carries' => 'request_uri',
        'mode' => null,
        'returns' => 'signed',
        'holds' => ['self_signed_tls_client_auth', 'x5t#S256'],
        'gaps' => ['RP-04', 'RP-07'],
    ],
    'pairwise' => [
        'carries' => 'parameters',
        'mode' => 'query',
        'returns' => 'query',
        'holds' => ['a JWE RSA-OAEP-256', 'pairwise'],
        'gaps' => ['RP-05'],
    ],
    'public' => [
        'carries' => 'parameters',
        'mode' => 'query',
        'returns' => 'query',
        'holds' => ['a public client'],
        'gaps' => [],
    ],
];

/**
 * What the tenant calls the initial access token of this run, and the block of apps/op/.env.local the run
 * owns while it plays (demo_registration_mode).
 */
const DEMO_FORGE_TOKEN_NAME = 'castor demo --forge';

const DEMO_FORGE_ENV_MARKER = 'castor demo --forge';

/**
 * The mode this walk asks the tenant for, by the name the class that is that mode gives itself: a
 * credential the tenant issues, names, limits and revokes (RFC 7591 §1.2), which is the mode decision 0009
 * calls controlled by initial token and the one a real ecosystem of clients uses.
 */
const DEMO_FORGE_MODE = 'initial_access_token';

/**
 * The forge of clients (issue #582), played preset by preset, one request at a time.
 *
 * Every preset is composed on the page of the forge, registered at the provider by that page (RFC 7591
 * §3), signs the same user in and is deleted again (RFC 7592 §2.3). What changes from one to the next is
 * what the client registered and what travelled, which is what this walk looks at: the authorization
 * request of the FAPI presets carries nothing but a client and a URI, their answer is one signed
 * parameter, their ID token is a JWE and their access token names what it is bound to, where the first
 * preset has all of it in the open.
 *
 * Nothing of the provider is written for this: the tenant is asked for the mode decision 0009 calls
 * controlled by initial token for the length of the run, it is given back at the end, and the clients the
 * presets register are the clients any caller registering the same metadata would get.
 */
function demo_forge_check(string $issuer, string $password, string $ca): void
{
    io()->section('The forge of clients');

    // The tenant is asked for the mode decision 0009 calls controlled by initial token for the length of
    // this run, and given it back at the end; the credential it asks for is the one the demonstration was
    // started with, worth one registration per preset and one for the composition built by hand below.
    demo_registration_mode($issuer, $ca, DEMO_FORGE_ENV_MARKER, DEMO_FORGE_MODE);

    $verified = [];
    foreach (DEMO_FORGE_PRESETS as $slug => $preset) {
        $cookies = [];
        $profile = DEMO_URL . '/c/' . $slug . '/profile';

        // the page offers that preset, and what it submits is the form of the forge and nothing else
        [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/');
        demo_expect(
            $status === 200 && str_contains($page, 'name="preset" value="' . $slug . '"'),
            sprintf('%s: the page of the forge offers this preset (got %d)', $slug, $status),
        );

        // one request builds it: the client is registered at the provider and did not exist before it
        [$status, $location] = demo_request($cookies, $ca, 'POST', DEMO_URL . '/forge/build', [
            'preset' => $slug,
        ]);
        demo_expect($status === 302 && $location === $profile, sprintf(
            '%s: it is registered and the browser is sent to its page (RFC 7591 §3.2.1, got %d %s)',
            $slug,
            $status,
            $location,
        ));

        // and the page of a client that is not signed in starts its flow, which is the demonstration
        [$status, $location] = demo_request($cookies, $ca, 'GET', $profile);
        demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), sprintf(
            '%s: its page sends the browser to the authorization endpoint (got %d %s)',
            $slug,
            $status,
            $location,
        ));
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);

        if ($preset['carries'] === 'request_uri') {
            demo_expect(
                array_keys($authorization) === ['client_id', 'request_uri'],
                sprintf(
                    '%s: the browser carries the client and a request URI, and nothing else (RFC 9126 §4, got %s)',
                    $slug,
                    implode(', ', array_keys($authorization)),
                ),
            );
            $carried = 'client_id and request_uri';
        } else {
            demo_expect(
                ($authorization['response_type'] ?? null) === 'code'
                && ($authorization['code_challenge_method'] ?? null) === 'S256'
                && ($authorization['response_mode'] ?? null) === $preset['mode'],
                sprintf('%s: response_type=code, PKCE S256 and response_mode=%s in the query', $slug, (string) $preset['mode']),
            );
            $carried = sprintf('%d parameters in the query', count($authorization));
        }

        // the login of the provider, the same for every preset: what a composition changes is never how a
        // user proves who they are
        $location = demo_interaction_login($cookies, $issuer, $password, $ca, $location);

        [$status, $location, $page] = demo_resume($cookies, $ca, $issuer, $location);
        if ($preset['returns'] === 'form') {
            demo_expect($status === 200 && preg_match('/form[^>]+method="post"[^>]+action="([^"]+)"/i', $page, $form) === 1, sprintf(
                '%s: the provider answers with a page that posts the answer back (got %d)',
                $slug,
                $status,
            ));
            $action = html_entity_decode($form[1]);
            demo_expect($action === DEMO_URL . '/c/' . $slug . '/callback', sprintf(
                '%s: the form posts to the callback of this client (got %s)',
                $slug,
                $action,
            ));
            $answer = demo_form_fields($page);
            $returned = sprintf('a form of %d fields', count($answer));
            [$status, $location] = demo_request($cookies, $ca, 'POST', $action, $answer);
        } else {
            demo_expect($status === 302 && str_starts_with($location, DEMO_URL . '/c/' . $slug . '/callback'), sprintf(
                '%s: the provider sends the browser to the callback of this client (got %d %s)',
                $slug,
                $status,
                $location,
            ));
            parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
            if ($preset['returns'] === 'signed') {
                demo_expect(array_keys($callback) === ['response'], sprintf(
                    '%s: the answer is one signed parameter and nothing else (JARM §4.1, got %s)',
                    $slug,
                    implode(', ', array_keys($callback)),
                ));
                $returned = sprintf('one "response" of %d characters', strlen((string) $callback['response']));
            } else {
                demo_expect(isset($callback['code'], $callback['state']) && ($callback['iss'] ?? null) === $issuer, sprintf(
                    '%s: the callback carries code, state and iss (RFC 9207 §2)',
                    $slug,
                ));
                $returned = 'code, state and iss in the query';
            }
            [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
        }

        if (isset($preset['known'])) {
            $verified[] = [$slug, $carried, $returned, demo_forge_known($cookies, $ca, $slug, $status, $location, $preset['known']), 'nothing to delete'];

            continue;
        }

        demo_expect($status === 302 && $location === $profile, sprintf('%s: the built client signs the user in (got %d %s)', $slug, $status, $location));
        [$status, , $page] = demo_request($cookies, $ca, 'GET', $profile);
        demo_expect($status === 200, sprintf('%s: its page opens (got %d)', $slug, $status));
        $read = html_entity_decode($page);

        foreach ($preset['holds'] as $fragment) {
            demo_expect(str_contains($read, $fragment), sprintf('%s: its page says "%s"', $slug, $fragment));
        }

        // What `oidc_login` could not have served, which is the one thing the forge shows that the ladder
        // could not: the page names the item of the status document, or says that configuration alone
        // reaches this composition.
        foreach ($preset['gaps'] as $gap) {
            demo_expect(str_contains($read, $gap), sprintf('%s: its page names %s of the status document', $slug, $gap));
        }
        if ($preset['gaps'] === []) {
            demo_expect(
                str_contains($read, 'reaches this one with configuration alone'),
                sprintf('%s: its page says a Symfony application reaches this composition with configuration alone', $slug),
            );
        }
        $hops = demo_forge_hops($page);
        demo_expect($hops !== [], sprintf('%s: its page shows what travelled, hop by hop', $slug));

        // the identifier the provider assigned, which the page carries for this walk to read, and the
        // trace the provider recorded while that very client signed in (issue #462)
        demo_expect(
            preg_match('/data-client-id="([^"]+)"/', $page, $registered) === 1,
            sprintf('%s: its page names the client the provider registered', $slug),
        );
        $replayed = demo_forge_replay($cookies, $ca, $issuer, $slug, $registered[1]);
        demo_forge_read($cookies, $ca, $slug, $registered[1]);

        if ($preset['signs_out'] ?? false) {
            demo_forge_sign_out($cookies, $ca, $issuer, $slug);
        }

        $verified[] = [
            $slug,
            $carried,
            $returned,
            sprintf('%d hops: %s', count($hops), implode(', ', $hops)),
            sprintf('%s, then %s', $replayed, demo_forge_delete($cookies, $ca, $slug)),
        ];
    }

    // A composition nobody wrote down: the form is what is submitted, so a client of a shape no preset
    // holds is built the same way, which is what the page is for.
    $verified[] = demo_forge_by_hand($issuer, $password, $ca);

    demo_registration_mode($issuer, $ca, DEMO_FORGE_ENV_MARKER, null);

    io()->table(['Composition', 'To the provider', 'Back from it', 'What its page shows', 'Afterwards'], $verified);
    foreach (DEMO_FORGE_PRESETS as $slug => $preset) {
        if (isset($preset['known'])) {
            io()->note(sprintf('The preset "%s" is refused on purpose and the run says so: %s', $slug, $preset['known']));
        }
    }
    io()->success('Every composition of the forge registered itself, signed the same user in and deleted itself, from a client that puts the whole request in the URL of a browser to one that puts nothing there.');
}

/**
 * A composition the walk writes itself, posted field by field as the form of the page posts it: a client
 * that authenticates with a secret it signs rather than sends (RFC 7523 §2.2), asks for one scope and
 * reads an answer posted back. No preset holds it, which is the point: what the page submits is a form.
 *
 * @return array{string, string, string, string, string}
 */
function demo_forge_by_hand(string $issuer, string $password, string $ca): array
{
    $cookies = [];
    [$status, $location] = demo_request($cookies, $ca, 'POST', DEMO_URL . '/forge/build', [
        'client_name' => 'Composed by the walk',
        'token_endpoint_auth_method' => 'client_secret_jwt',
        'scope' => ['profile'],
        'response_mode' => 'form_post',
        'id_token_signed_response_alg' => 'ES256',
    ]);
    demo_expect($status === 302 && preg_match('#^' . preg_quote(DEMO_URL, '#') . '/c/(own-[0-9a-f]+)/profile$#', $location, $built) === 1, sprintf(
        'a composition no preset holds is built under a handle of its own (got %d %s)',
        $status,
        $location,
    ));
    $handle = $built[1];

    [, $location] = demo_request($cookies, $ca, 'GET', $location);
    $location = demo_interaction_login($cookies, $issuer, $password, $ca, $location);
    [$status, , $page] = demo_resume($cookies, $ca, $issuer, $location);
    demo_expect($status === 200 && preg_match('/form[^>]+method="post"[^>]+action="([^"]+)"/i', $page, $form) === 1, sprintf(
        '%s: the answer is posted back, as the form asked for (got %d)',
        $handle,
        $status,
    ));
    [$status, $location] = demo_request($cookies, $ca, 'POST', html_entity_decode($form[1]), demo_form_fields($page));
    demo_expect($status === 302 && $location === DEMO_URL . '/c/' . $handle . '/profile', sprintf(
        '%s: it signs the user in (got %d %s)',
        $handle,
        $status,
        $location,
    ));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    $read = html_entity_decode($page);
    demo_expect(
        $status === 200 && str_contains($read, 'client_secret_jwt') && str_contains($read, 'the scopes openid, profile'),
        sprintf('%s: its page says what was composed and nothing else (got %d)', $handle, $status),
    );
    demo_expect(
        str_contains($read, 'reaches this one with configuration alone'),
        sprintf('%s: and that an "oidc_login" firewall reaches this composition as it is', $handle),
    );
    demo_expect(preg_match('/data-client-id="([^"]+)"/', $page, $registered) === 1, sprintf('%s: its page names the client the provider registered', $handle));
    demo_forge_read($cookies, $ca, $handle, $registered[1]);

    return [
        $handle,
        '6 parameters in the query',
        sprintf('a form of %d fields', count(demo_form_fields($page)) ?: 3),
        sprintf('%d hops: %s', count(demo_forge_hops($page)), implode(', ', demo_forge_hops($page))),
        demo_forge_delete($cookies, $ca, $handle),
    ];
}

/**
 * RP-Initiated Logout §2 and Front-Channel Logout 1.0 §3 for a client of the forge: signing out of the
 * demonstration ends the session at the provider too, which no listener of "oidc_login" does here, this
 * firewall being none of its own (ForgeLogoutListener), and the provider then answers the page that loads
 * the front-channel URI of every client of that session in a frame.
 *
 * The frame is followed, in the browser that signed in and with its cookies, which is the whole of what
 * the front channel is: the request arrives in the browser of the user and the application writes that
 * route itself (`RP-07` of the status document, whose back channel has merged upstream and whose front
 * channel has not).
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_forge_sign_out(array &$cookies, string $ca, string $issuer, string $slug): void
{
    [$status, $location] = demo_request($cookies, $ca, 'POST', DEMO_URL . '/c/logout');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/logout?'), sprintf(
        '%s: signing out sends the browser to the provider to end its session (got %d %s)',
        $slug,
        $status,
        $location,
    ));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $logout);
    demo_expect(
        is_string($logout['id_token_hint'] ?? null) && ($logout['post_logout_redirect_uri'] ?? null) === DEMO_URL . '/',
        sprintf('%s: the logout request carries id_token_hint and post_logout_redirect_uri (RP-Initiated Logout §2)', $slug),
    );

    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    $frame = sprintf('%s/c/%s/frontchannel-logout', DEMO_URL, $slug);
    demo_expect(
        $status === 200 && preg_match('/<iframe[^>]+src="(' . preg_quote($frame, '/') . '[^"]*)"/', $page, $loaded) === 1,
        sprintf('%s: the provider answers the page that loads the front-channel URI of this client in a frame (got %d)', $slug, $status),
    );
    $loaded = html_entity_decode($loaded[1]);
    parse_str((string) parse_url($loaded, \PHP_URL_QUERY), $named);
    demo_expect(
        ($named['iss'] ?? null) === $issuer && is_string($named['sid'] ?? null),
        sprintf('%s: the frame names the issuer and the session that ended (Front-Channel Logout 1.0 §2.1, got %s)', $slug, $loaded),
    );
    demo_expect(
        preg_match('/http-equiv="refresh"[^>]+content="\d+;url=([^"]+)"/', $page, $back) === 1 && html_entity_decode($back[1]) === DEMO_URL . '/',
        sprintf('%s: and the page sends the browser back where this client asked to be sent', $slug),
    );

    // the frame itself, which is a request of this browser and carries its cookies
    [$status, , $ended] = demo_request($cookies, $ca, 'GET', $loaded);
    demo_expect(
        $status === 200 && str_contains($ended, 'was ended'),
        sprintf('%s: the frame ends the session of this client here (got %d)', $slug, $status),
    );
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/c/' . $slug . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), sprintf(
        '%s: so its page asks for a login again (got %d %s)',
        $slug,
        $status,
        $location,
    ));
}

/**
 * RFC 7592 §2.1: the built client reads itself at the URI it was handed, with the credential it was
 * handed, which is the one way a dynamic client reads its own registration. It is asked for from its page,
 * so it is asked for while that client is signed in.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_forge_read(array &$cookies, string $ca, string $handle, string $clientId): void
{
    [$status, , $page] = demo_request($cookies, $ca, 'GET', sprintf('%s/c/%s/profile?read=1', DEMO_URL, $handle));
    demo_expect(
        $status === 200 && preg_match('/data-read="([^"]+)"/', $page, $read) === 1 && $read[1] === $clientId,
        sprintf('%s: it reads its own registration at the URI it was handed (RFC 7592 §2.1, got "%s")', $handle, $read[1] ?? ''),
    );
}

/**
 * RFC 7592 §2.3: the client deletes itself at the provider, which answers 204 and no body, and the page
 * says what came back rather than claiming the deletion. The route is not behind the firewall of the
 * forge: a client that has signed out deletes itself all the same.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_forge_delete(array &$cookies, string $ca, string $handle): string
{
    [$status, $location] = demo_request($cookies, $ca, 'POST', DEMO_URL . '/forge/' . $handle . '/delete');
    demo_expect($status === 302 && str_starts_with($location, DEMO_URL . '/?'), sprintf(
        '%s: it deletes itself at the provider (RFC 7592 §2.3, got %d %s)',
        $handle,
        $status,
        $location,
    ));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect(
        $status === 200
        && preg_match('/data-deleted="' . preg_quote($handle, '/') . '" data-answered="([^"]+)"/', $page, $answered) === 1
        && $answered[1] === '204',
        sprintf('%s: and the page says what the provider answered (got "%s")', $handle, $answered[1] ?? ''),
    );
    demo_expect(
        ! str_contains($page, '/c/' . $handle . '/profile'),
        sprintf('%s: the page of the forge no longer offers it', $handle),
    );

    return 'deleted, the provider answering 204';
}

/**
 * A preset the provider refuses for a reason that is written down: the demonstration lands on the page
 * that says why, and the walk reads that reason rather than asserting a success it will not get.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_forge_known(array &$cookies, string $ca, string $slug, int $status, string $location, string $issue): string
{
    demo_expect($status === 302 && $location === DEMO_URL . '/c/' . $slug . '/login', sprintf(
        '%s: the demonstration refuses the login and says so on the page of this client (got %d %s)',
        $slug,
        $status,
        $location,
    ));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200 && preg_match('/<p><code>(.*?)<\/code><\/p>/s', $page, $reason) === 1, sprintf('%s: the page carries the reason', $slug));

    return sprintf('refused, see %s', basename($issue));
}

/**
 * The login of the provider for a client of the forge: the request is parked, the page carries the form,
 * the form is posted, and what comes back is where the interaction resumes. The same three requests for
 * every composition, whatever it registered: what a client asks for never changes how a user proves who
 * they are.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_interaction_login(array &$cookies, string $issuer, string $password, string $ca, string $authorization): string
{
    [$status, $location] = demo_request($cookies, $ca, 'GET', $authorization);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?interaction='), sprintf(
        'the OP parks the request and asks for a login (got %d %s)',
        $status,
        $location,
    ));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('the login page opens (got %d)', $status));
    $page = demo_past_the_address($cookies, $ca, $issuer, $page);
    $form = demo_form_with($page, '_username', 'the login page carries the form of the password');
    demo_expect(
        preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'which says where it posts and carries its token',
    );
    [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_username' => DEV_USERNAME,
        '_password' => $password,
        '_csrf_token' => $csrf[1],
    ]);
    demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));

    return $location;
}

/**
 * What the page of a built client says travelled, by the label of each hop and in the order it happened.
 * The page names those cards for this walk to read, the other cards of it being what the client is and
 * what Symfony's own authenticator could not have served.
 *
 * @return list<string>
 */
function demo_forge_hops(string $page): array
{
    preg_match_all('/<div class="card hop">\s*<h2>([^<]+)<\/h2>/', $page, $matches);

    return array_map(trim(...), $matches[1]);
}

/**
 * The API of the demonstration (issue #556): API Platform serves it under /api/v1 of oidc-demo, behind a
 * firewall of its own, and the access token the client holds for its user is described by the OP at every
 * request (RFC 7662).
 *
 * The six routes of /api/ next to it answer who a token names and nothing else: what they demonstrate is
 * how a token is checked. This is an API, so what is seen here is what a resource server does with the
 * answer it got: one scope per operation, a refusal that names the scope that is missing, and the window
 * during which the OP is not asked again.
 *
 * That window is the one thing a walk has to play on both sides, its whole subject being a few seconds of
 * disagreement between the two: the token is read fresh, the session is ended, and the same token is
 * accepted once more inside the window and refused once it has closed, the OP refusing it at UserInfo
 * throughout. The figure is read from what the API says of itself, so this walk cannot assert a lifetime
 * other than the one the firewall applies.
 */
const DEMO_API_BASE = DEMO_URL . '/api/v1';

/**
 * The invoice of the book of the API that "castor demo --rar" asks to pay, and what it is for: a scope
 * says a kind of thing, "invoices.pay" meaning any invoice of whoever holds the token, and the detail of
 * a rich authorization request names this one and the most that may be moved (RFC 9396 §2). The two
 * readings meet on the same invoice on purpose, and this walk pays it to the figure that detail bounds.
 */
const DEMO_API_INVOICE_AMOUNT = '45.00';

/**
 * The invoice this walk tries to write, which it never gets to: the demonstration is not granted
 * "invoices.write" (config/packages/security.yaml of oidc-demo).
 */
const DEMO_API_WRITTEN_INVOICE = ['reference' => 'INV-9000', 'label' => 'Written by the walk', 'amount' => '10.00', 'currency' => 'EUR'];

/**
 * What the document of the API has to say each operation requires, path and method as OpenAPI writes them.
 *
 * It is the expectation of this walk and not a list the API reads: the API derives what it documents from
 * the "security" expression that enforces it (`ScopesInTheDocument` of the demonstration), and this is the
 * other end, so a scope that changed on one side without the other shows up here.
 */
/**
 * A value of the shape an opaque access token of this OP has, which it never issued: what the API answers
 * when no client of the demonstration is told anything about the token it was handed.
 */
const DEMO_API_UNKNOWN_TOKEN = 'ZZZZnobodyZZZZissuedZZZZthisZZZZvalueZZZZZZZ';

/**
 * The page of the demonstration that calls the API with the access token of its session.
 */
const DEMO_API_PAGE_PATH = '/api-calls';

/**
 * The path of a call as the document of the API writes it: the reference of an invoice is a variable there
 * and a value on the page, so the two are compared on the template and not on the string.
 */
function demo_api_template(string $path): string
{
    return (string) preg_replace('#/invoices/INV-[0-9]+#', '/invoices/{reference}', $path);
}

/**
 * The page of the demonstration where the access token of a session calls the API (/api-calls): what each
 * call it offers is answered, and the scope the page says it needs.
 *
 * The page declares the calls itself (CallsOfThePage of the demonstration) and the walk replays what it
 * declares, as a browser would: a call the page offers and the API refuses, or a scope the page names and
 * the document does not require, is a page that would mislead whoever reads it.
 */
const DEMO_API_PAGE_CALLS = [
    'account' => ['status' => 200, 'scope' => 'profile'],
    'invoices' => ['status' => 200, 'scope' => 'invoices.read'],
    'invoice' => ['status' => 200, 'scope' => 'invoices.read'],
    'pay' => ['status' => 201, 'scope' => 'invoices.pay'],
    'write' => ['status' => 403, 'scope' => 'invoices.write'],
];

const DEMO_API_DOCUMENTED_SCOPES = [
    'get /api/v1/account' => 'profile',
    'get /api/v1/invoices' => 'invoices.read',
    'get /api/v1/invoices/{reference}' => 'invoices.read',
    'post /api/v1/invoices' => 'invoices.write',
    'post /api/v1/invoices/{reference}/payments' => 'invoices.pay',
];

function demo_api_check(string $dir, string $issuer, string $password, string $demoSecret, string $opaqueSecret, string $ca): void
{
    io()->section('An API behind the introspection endpoint');
    $verified = [];

    // The book of invoices and the answers the firewall kept both live in the cache pool of the
    // demonstration, so the run starts from the book a deployment starts with: a payment is something that
    // happened, and a walk asserting that it happens would pass once and conflict ever after. It is the
    // fixture of this walk, cleared where every other walk writes the .env.local it needs.
    run(['php', 'bin/console', 'cache:pool:clear', 'cache.app'], context: demo_context($dir)->withQuiet());

    // RFC 7662 §2.1: where the API asks, and with the credentials of the client the token was issued to,
    // because the OP describes a token to that client and to no other (§2.2)
    $metadata = demo_metadata($issuer . '/.well-known/openid-configuration', $ca);
    $introspection = (string) ($metadata['introspection_endpoint'] ?? '');
    demo_expect($introspection !== '', 'the document names the introspection endpoint the API asks at');
    demo_write_env_local($dir . '/.env.local', [
        'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
        'OIDC_CLIENT_SECRET' => $demoSecret,
        DEMO_INTROSPECTION_ENV => $introspection,
    ]);
    $verified[] = ['Introspection endpoint', $introspection];

    // RFC 6750 §3: a request carrying no token is not an authenticated one, and the challenge of the
    // firewall is what says so, naming the realm and nothing of anybody's invoices
    [$status, $body, $headers] = demo_api_request('GET', DEMO_API_BASE . '/invoices');
    demo_expect($status === 401, sprintf('a request carrying no token is refused (got %d %s)', $status, json_encode($body)));
    $challenge = (string) ($headers['www-authenticate'][0] ?? '');
    demo_expect(str_starts_with($challenge, 'Bearer realm='), sprintf('with the challenge of RFC 6750 §3 (got "%s")', $challenge));
    $verified[] = ['No token', sprintf('401, %s', $challenge)];

    // what an API says of itself is public; what it holds is not
    [$status] = demo_api_request('GET', DEMO_API_BASE . '/docs');
    demo_expect($status === 200, sprintf('the documentation of the API is served without a token (got %d)', $status));
    $verified[] = ['/api/v1/docs', '200 without a token: the shape of the API is public, the invoices are not'];

    // The document itself, in the media type OpenAPI defines for it: what the page offers to whoever reads
    // it is one way of being authorized, the bearer token of RFC 6750 §2.1, and what each operation
    // requires is written where the operation is described rather than left to be discovered by a 403.
    [$status, $document] = demo_api_request('GET', DEMO_API_BASE . '/docs', accept: 'application/vnd.openapi+json');
    demo_expect($status === 200, sprintf('the document is served in the media type OpenAPI defines for it (got %d)', $status));
    $schemes = $document['components']['securitySchemes'] ?? [];
    demo_expect(
        ($schemes['bearer']['type'] ?? null) === 'http' && ($schemes['bearer']['scheme'] ?? null) === 'bearer',
        sprintf('and declares the one scheme this API accepts, so the page has a button to be authorized with (got %s)', json_encode($schemes)),
    );
    demo_expect(
        ($document['security'] ?? null) === [['bearer' => []]],
        sprintf('required of the whole API, since no operation of it is open (got %s)', json_encode($document['security'] ?? null)),
    );
    $documented = [];
    foreach ((array) ($document['paths'] ?? []) as $path => $methods) {
        foreach ((array) $methods as $method => $operation) {
            if (! is_array($operation) || ! isset($operation['summary'])) {
                continue;
            }
            $documented[$method . ' ' . $path] = $operation['description'] ?? '';
        }
    }
    // the same operations, whatever order the document lists them in
    $listed = array_keys($documented);
    $expected = array_keys(DEMO_API_DOCUMENTED_SCOPES);
    sort($listed);
    sort($expected);
    demo_expect(
        $listed === $expected,
        sprintf('the document describes the operations of the API and no other (got %s)', json_encode($listed)),
    );
    foreach (DEMO_API_DOCUMENTED_SCOPES as $operation => $scope) {
        demo_expect(
            str_contains($documented[$operation], sprintf('scope "%s"', $scope)),
            sprintf('%s says it needs "%s" (got "%s")', $operation, $scope, $documented[$operation]),
        );
    }
    $verified[] = [
        'The OpenAPI document',
        sprintf('one "http" scheme, "bearer", and %d operations each naming the scope it needs', count(DEMO_API_DOCUMENTED_SCOPES)),
    ];

    // the client signs its user in and holds an access token, which is the one it sends to the API; the
    // token is read raw off the page, as the resource server walk reads it, because what travels to an API
    // is the string and not what this file could make of it
    $cookies = [];
    $tokens = demo_resource_server_sign_in($cookies, $issuer, $password, $ca, DEMO_CLIENT_ID);
    $accessToken = $tokens['access_token'];
    $claims = demo_claims_of($accessToken);
    $granted = explode(' ', (string) ($claims['scope'] ?? ''));
    demo_expect(
        in_array('invoices.read', $granted, true) && in_array('invoices.pay', $granted, true) && ! in_array('invoices.write', $granted, true),
        sprintf(
            'the token carries invoices.read and invoices.pay, and not invoices.write, which the client registered and never asks for (scope "%s")',
            $claims['scope'] ?? '',
        ),
    );
    $subject = (string) ($claims['sub'] ?? '?');
    $verified[] = ['The access token', sprintf('scope "%s", sub %s', $claims['scope'] ?? '', $subject)];

    // what the API knows of the request is what the OP answered about the token, and nothing else
    [$status, $account] = demo_api_request('GET', DEMO_API_BASE . '/account', $accessToken);
    demo_expect(
        $status === 200 && ($account['sub'] ?? null) === $subject,
        sprintf('/account answers the sub the OP named (got %d %s)', $status, json_encode($account)),
    );
    demo_expect(
        ($account['clientId'] ?? null) === DEMO_CLIENT_ID,
        sprintf('and the client the token was issued to, which the introspection response carries (got %s)', json_encode($account['clientId'] ?? null)),
    );
    demo_expect(
        preg_match('/at most (\d+) seconds/', (string) ($account['checkedBy'] ?? ''), $window) === 1,
        sprintf('and says how long it goes on believing that answer (got "%s")', $account['checkedBy'] ?? ''),
    );
    $ttl = (int) $window[1];
    $verified[] = ['/api/v1/account', sprintf('200 on "profile", the answer of the OP kept at most %d seconds', $ttl)];

    // one scope, one operation: the book of this subject
    [$status, $collection] = demo_api_request('GET', DEMO_API_BASE . '/invoices', $accessToken);
    $references = array_column($collection, 'reference');
    demo_expect(
        $status === 200 && in_array(DEMO_RAR_INVOICE, $references, true),
        sprintf('the collection is served on "invoices.read", with %s in it (got %d %s)', DEMO_RAR_INVOICE, $status, json_encode($references)),
    );
    $verified[] = ['GET /api/v1/invoices', sprintf('200 on "invoices.read", %d invoices, %s among them', count($collection), DEMO_RAR_INVOICE)];

    // the other scope, on the one operation that changes something
    [$status, $payment] = demo_api_request(
        'POST',
        DEMO_API_BASE . '/invoices/' . DEMO_RAR_INVOICE . '/payments',
        $accessToken,
        ['amount' => DEMO_API_INVOICE_AMOUNT],
    );
    demo_expect(
        $status === 201 && ($payment['paidAt'] ?? null) !== null,
        sprintf('the invoice is paid on "invoices.pay", for the amount the detail of --rar bounds (got %d %s)', $status, json_encode($payment)),
    );
    [$status, $invoice] = demo_api_request('GET', DEMO_API_BASE . '/invoices/' . DEMO_RAR_INVOICE, $accessToken);
    demo_expect(
        $status === 200 && ($invoice['paidAt'] ?? null) === $payment['paidAt'],
        sprintf('and it is paid from then on, for whoever reads it back (got %d %s)', $status, json_encode($invoice)),
    );
    $verified[] = ['POST .../payments', sprintf('201 on "invoices.pay", %s paid at %s', DEMO_RAR_INVOICE, $payment['paidAt'])];

    // RFC 6750 §3.1: a scope the token was never granted is a 403 and not a 401, the token being a good
    // one, and the challenge names what is missing rather than what was asked for
    [$status, $refused, $headers] = demo_api_request('POST', DEMO_API_BASE . '/invoices', $accessToken, DEMO_API_WRITTEN_INVOICE);
    demo_expect($status === 403, sprintf('a write is refused on that token (got %d %s)', $status, json_encode($refused)));
    $challenge = (string) ($headers['www-authenticate'][0] ?? '');
    demo_expect(
        str_contains($challenge, 'error="insufficient_scope"') && str_contains($challenge, 'scope="invoices.write"'),
        sprintf('with the challenge of RFC 6750 §3.1, naming the scope that is missing (got "%s")', $challenge),
    );
    [$status, $book] = demo_api_request('GET', DEMO_API_BASE . '/invoices', $accessToken);
    demo_expect(
        $status === 200 && ! in_array(DEMO_API_WRITTEN_INVOICE['reference'], array_column($book, 'reference'), true),
        sprintf('and nothing was written (got %d %s)', $status, json_encode(array_column($book, 'reference'))),
    );
    $verified[] = ['POST /api/v1/invoices', sprintf('403, %s', $challenge)];

    // RFC 7662 §2.2: the OP describes a token to the client it was issued to and to no other. The
    // demonstration is not one client, its main firewall and each declared client of the tenant being one, so
    // whoever reads one of its pages holds a token of whichever client that page belongs to: the API asks
    // the OP as each client whose secret the demonstration holds, and the first answer that describes the
    // token is the one its firewall reads (WhicheverClientKnowsTheToken of the demonstration). A token of
    // another client is therefore served here, and the account says which client it was issued to, which
    // is the OP's answer and not something the API decided.
    demo_write_env_local($dir . '/.env.local', [
        'OIDC_CLIENT_ID' => DEMO_OPAQUE_CLIENT_ID,
        'OIDC_CLIENT_SECRET' => $opaqueSecret,
        DEMO_INTROSPECTION_ENV => $introspection,
    ]);
    $otherCookies = [];
    $otherToken = demo_resource_server_sign_in($otherCookies, $issuer, $password, $ca, DEMO_OPAQUE_CLIENT_ID)['access_token'];
    demo_write_env_local($dir . '/.env.local', [
        'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
        'OIDC_CLIENT_SECRET' => $demoSecret,
        DEMO_INTROSPECTION_ENV => $introspection,
    ]);
    [$status, $other] = demo_api_request('GET', DEMO_API_BASE . '/account', $otherToken);
    demo_expect($status === 200 && ($other['sub'] ?? null) === $subject, sprintf(
        'a token the same user holds for another client of the demonstration is served here, for the same subject (got %d %s)',
        $status,
        json_encode($other),
    ));
    demo_expect(
        ($other['clientId'] ?? null) === DEMO_OPAQUE_CLIENT_ID,
        sprintf('and the answer names the client it was issued to, which is what the OP described (got %s)', json_encode($other['clientId'] ?? null)),
    );
    $described = demo_introspect($introspection, $ca, DEMO_OPAQUE_CLIENT_ID, $opaqueSecret, $otherToken);
    demo_expect(
        ($described['active'] ?? null) === true && ($described['client_id'] ?? null) === DEMO_OPAQUE_CLIENT_ID,
        sprintf('as the client it belongs to reads it at the introspection endpoint (got %s)', json_encode($described)),
    );
    $verified[] = [
        'A token of another client',
        sprintf('200, the account naming %s, the client the OP described it to', DEMO_OPAQUE_CLIENT_ID),
    ];
    demo_logout($otherCookies, $issuer, $ca);

    // and a value this OP never issued: every client of the demonstration is asked, none of them is
    // answered anything about it, and what the firewall reports is what the OP said of it
    [$status, $body, $headers] = demo_api_request('GET', DEMO_API_BASE . '/account', DEMO_API_UNKNOWN_TOKEN);
    demo_expect($status === 401, sprintf('a value this OP never issued is refused (got %d %s)', $status, json_encode($body)));
    demo_expect(
        ! str_contains((string) ($headers['www-authenticate'][0] ?? ''), 'insufficient_scope'),
        'as a token nothing is known of and not as one that lacks a scope (RFC 6750 §3)',
    );
    $verified[] = ['A token nobody issued', '401, after every client of the demonstration was asked about it'];

    // The page of the demonstration where a session uses its own access token against the API: the browser
    // makes the calls, so what the walk can judge is what the page hands it, the token and the calls it
    // offers, and whether the API answers each of them as the page says it will. The book of invoices is
    // opened again first, because the payment above is the payment this page offers.
    run(['php', 'bin/console', 'cache:pool:clear', 'cache.app'], context: demo_context($dir)->withQuiet());
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . DEMO_API_PAGE_PATH);
    demo_expect($status === 200, sprintf('%s opens on the session of the demonstration (got %d)', DEMO_API_PAGE_PATH, $status));
    demo_expect(
        preg_match('/id="api-token"[^>]*>([^<]+)</', $page, $carried) === 1 && trim($carried[1]) === $accessToken,
        'and carries the access token that session holds, so nothing is pasted by hand',
    );
    preg_match_all(
        '/data-api-call-param="([a-z]+)"\s+data-api-method-param="([A-Z]+)"\s+data-api-path-param="([^"]+)"\s+data-api-body-param="([^"]*)"/',
        $page,
        $offered,
        \PREG_SET_ORDER,
    );
    demo_expect(
        array_column($offered, 1) === array_keys(DEMO_API_PAGE_CALLS),
        sprintf('and offers the calls of the API, in the order it declares them (got %s)', json_encode(array_column($offered, 1))),
    );
    foreach ($offered as [, $key, $method, $path, $body]) {
        $expected = DEMO_API_PAGE_CALLS[$key];
        demo_expect(
            str_contains($page, sprintf('<code>%s %s</code> &middot; scope <code>%s</code>', $method, $path, $expected['scope'])),
            sprintf('%s: the page says what it asks for and which scope it needs (%s %s, %s)', $key, $method, $path, $expected['scope']),
        );
        $documented = DEMO_API_DOCUMENTED_SCOPES[strtolower($method) . ' ' . demo_api_template($path)] ?? null;
        demo_expect(
            $documented === $expected['scope'],
            sprintf('%s: and that scope is the one the document of the API requires (got %s)', $key, json_encode($documented)),
        );
        [$status, $answer] = demo_api_request(
            $method,
            DEMO_URL . $path,
            $accessToken,
            $body === '' ? null : (array) json_decode(html_entity_decode($body), true),
        );
        demo_expect(
            $status === $expected['status'],
            sprintf('%s: the API answers what the page says it will (expected %d, got %d %s)', $key, $expected['status'], $status, json_encode($answer)),
        );
    }
    $verified[] = [
        DEMO_API_PAGE_PATH,
        sprintf('200 with the token of the session, %d calls offered and each answered as the page says', count(DEMO_API_PAGE_CALLS)),
    ];

    // the window, played on both sides. The answer of an active token is read fresh here, so that what
    // follows is measured from a known moment rather than from whatever this walk asked a minute ago.
    sleep($ttl + 1);
    $readAt = microtime(true);
    [$status] = demo_api_request('GET', DEMO_API_BASE . '/account', $accessToken);
    demo_expect($status === 200, sprintf('the token is read again, the OP describing it as active (got %d)', $status));

    demo_logout($cookies, $issuer, $ca);
    demo_expect(demo_userinfo($issuer, $ca, $accessToken) === 401, 'the session ends, and the OP refuses that very token at UserInfo (issue #150)');
    $elapsed = microtime(true) - $readAt;
    demo_expect($elapsed < $ttl, sprintf('the window of %d seconds is still open, %.1f s after the answer was read', $ttl, $elapsed));
    [$status] = demo_api_request('GET', DEMO_API_BASE . '/account', $accessToken);
    demo_expect($status === 200, sprintf('and the API accepts the token once more, from the answer it kept (got %d)', $status));
    $verified[] = ['Inside the window', sprintf('200 while the OP answers 401 at UserInfo, %.1f s after the answer was read', microtime(true) - $readAt)];

    sleep(max(1, (int) ceil($ttl - (microtime(true) - $readAt)) + 1));
    [$status, $body, $headers] = demo_api_request('GET', DEMO_API_BASE . '/account', $accessToken);
    demo_expect($status === 401, sprintf('the window closes and the same token is refused (got %d %s)', $status, json_encode($body)));
    $verified[] = ['Window closed', sprintf('401, %.0f s after the answer was read, nothing having been told to the API', microtime(true) - $readAt)];

    io()->table(['Step', 'Verified'], $verified);
    io()->success(sprintf(
        'An API Platform API served the invoices of its user behind the introspection endpoint of the OP, one scope per operation, and forgot what it was told after %d seconds.',
        $ttl,
    ));
    io()->note('The page of the document offers one way of being authorized, the bearer token of RFC 6750 §2.1, and the token to paste is any one the demonstration handed out: the OP describes a token to the client it was issued to and to no other (RFC 7662 §2.2), so the API asks it as each client whose secret the demonstration holds, which is what the step above plays. A flow of an authorization code is not offered in that page: it runs in a browser, so the client it signed in as would hold its secret there.');
    io()->note(sprintf(
        'The %d seconds are the trade RFC 7662 §4 leaves to a resource server: a longer window spares the OP a round trip per request and carries a withdrawn token for longer, and the figure is one line of config/services.yaml of the demonstration. It is the other half of what --resource-server shows: an "at+jwt" verified offline is accepted until it expires, whatever the OP knows of it, where this API asks and so stops at the end of the window.',
        $ttl,
    ));
}

/**
 * What the OP says of a token to the client it was issued to (RFC 7662 §2.1): the client authenticates,
 * because an endpoint that described a token to whoever asked would tell a stranger that it exists.
 *
 * @return array<string, mixed>
 */
function demo_introspect(string $endpoint, string $ca, string $clientId, string $secret, string $token): array
{
    $response = http_request('POST', $endpoint, [
        'cafile' => $ca,
        'auth_basic' => [$clientId, $secret],
        'body' => ['token' => $token],
    ]);

    return (array) json_decode($response->getContent(false), true);
}

/**
 * A request to the API of the demonstration: the method, the token if the walk is sending one, and the
 * JSON of the body for an operation that takes one.
 *
 * The answer comes back with its headers, because what a refusal says is in one of them: the challenge of
 * RFC 6750 names the realm, the error and, for a missing scope, the scope.
 *
 * @param array<string, mixed>|null $payload
 * @param string $accept The media type the walk asks for, plain JSON unless it is reading the document
 * @return array{0: int, 1: array<mixed>, 2: array<string, list<string>>}
 */
function demo_api_request(
    string $method,
    string $url,
    ?string $accessToken = null,
    ?array $payload = null,
    string $accept = 'application/json',
): array {
    $options = [
        'max_redirects' => 0,
        'verify_peer' => false,
        'verify_host' => false,
        // the API serves JSON-LD and plain JSON, and a walk reading an object rather than a vocabulary
        // asks for the second (config/packages/api_platform.yaml)
        'headers' => ['Accept' => $accept],
    ];
    if ($accessToken !== null) {
        $options['auth_bearer'] = $accessToken;
    }
    if ($payload !== null) {
        $options['headers']['Content-Type'] = 'application/json';
        $options['body'] = json_encode($payload, \JSON_THROW_ON_ERROR);
    }
    $response = http_request($method, $url, $options);

    return [
        $response->getStatusCode(),
        (array) json_decode($response->getContent(false), true),
        $response->getHeaders(false),
    ];
}

/**
 * The DPoP side of the run, which lives under the autoloader of the monorepo: the key pair, the token
 * request that binds the token to it, and the five ways that token is then presented (tests/demo/).
 */
const DEMO_DPOP_CLIENT = 'tests/demo/dpop-client.php';

/**
 * The two routes of the demonstration behind a token bound by DPoP, one per shape of access token
 * (config/packages/security.yaml of oidc-demo).
 */
const DEMO_DPOP_PATH = '/api/me/dpop';

const DEMO_DPOP_INTROSPECTED_PATH = '/api/me/dpop/introspected';

/**
 * The pages of the demonstration (issue #462), where the flows of this provider are drawn: the index,
 * the page of one flow, and the two calls a live run is played with. A flow travels in the query and
 * not in a path, a grant type being named by an absolute URI often enough.
 */
const DEMO_FLOWS_PATH = '/demonstration/';

const DEMO_FLOW_PATH = '/demonstration/flow';

const DEMO_FLOW_ADVANCE_PATH = '/demonstration/flow/advance';

const DEMO_FLOW_OPEN_PATH = '/demonstration/flow/open';

/**
 * The two flows the demonstration plays from a page, named by the registries that name them (RFC 8628
 * §3.1, CIBA Core §4): what the demonstration can play is what the lab registered a client for, and
 * these two are the ones this walk follows hop by hop.
 */
const DEMO_DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

const DEMO_CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

/**
 * A name no grant of this provider gives itself (decision 0006 wired no password grant): the page of a
 * flow it does not serve is a 404, which is what says the set of pages is the set of pictures.
 */
const DEMO_UNSERVED_GRANT = 'password';

/**
 * How many advances a live run is given before this walk gives up on it: a device flow is three hops of
 * the client and one poll per interval, and a run needing more than this is a run that will not end.
 */
const DEMO_FLOW_ADVANCES = 24;

/**
 * Seconds between two polls, which is the interval this provider asks a client to wait (RFC 8628 §3.5).
 */
const DEMO_FLOW_POLL_INTERVAL = 5;

/**
 * Issue #462: every flow this provider serves is drawn, and two of them are played hop by hop from a
 * page, each hop showing the request that was sent and the answer that came back.
 *
 * What is asserted of the pictures is that they are the wiring: the page of every grant the discovery
 * document announces answers, the page of a grant it does not announce is a 404, and the index draws
 * those grants in that order. Nothing here writes down which flows those are.
 *
 * What is asserted of a run is that the demonstration took the hops of the client and stood in for
 * nobody: the code of the device flow is typed in a browser of this walk, the backchannel request is
 * allowed on the page of the user, and both of those hops are in the trace because this provider
 * recorded them while it served them.
 */
function demo_flows_check(string $issuer, string $password, string $ca): void
{
    io()->section('Every flow, drawn');
    $cookies = [];

    $announced = demo_metadata($issuer . '/.well-known/openid-configuration', $ca)['grant_types_supported'] ?? null;
    demo_expect(is_array($announced) && $announced !== [], 'the provider announces the grants it is wired with (OIDC Discovery §3)');
    $announced = array_values(array_map(strval(...), (array) $announced));

    [$status, , $index] = demo_request($cookies, $ca, 'GET', $issuer . DEMO_FLOWS_PATH);
    demo_expect($status === 200, sprintf('the index of the demonstration opens (got %d)', $status));
    preg_match_all('/' . preg_quote(DEMO_FLOW_PATH, '/') . '\?flow=([^"&]+)"/', $index, $links);
    $drawn = array_map(urldecode(...), $links[1]);
    demo_expect(
        $drawn === $announced,
        sprintf('the flows drawn are the grants announced, in that order (%s)', implode(', ', $drawn)),
    );

    foreach ($announced as $grantType) {
        [$status] = demo_request($cookies, $ca, 'GET', $issuer . DEMO_FLOW_PATH . '?flow=' . rawurlencode($grantType));
        demo_expect($status === 200, sprintf('the flow "%s" has its page (got %d)', $grantType, $status));
    }
    [$status] = demo_request($cookies, $ca, 'GET', $issuer . DEMO_FLOW_PATH . '?flow=' . DEMO_UNSERVED_GRANT);
    demo_expect($status === 404, sprintf('a flow this provider does not serve has no page (got %d)', $status));

    $verified = [
        ['Pictures', sprintf('%d, one per wired grant', count($drawn))],
        ['A grant nobody wired', sprintf('"%s": 404', DEMO_UNSERVED_GRANT)],
        demo_flow_device_run($issuer, $password, $ca),
        demo_flow_backchannel_run($issuer, $password, $ca),
    ];

    io()->table(['Step', 'Verified'], $verified);
    io()->success('Every flow this provider serves is drawn, and two of them were followed hop by hop, each hop showing what really travelled.');
}

/**
 * RFC 8628 played from a page, one hop per advance: the client asks, is handed a code to show, and polls
 * while nobody has answered; the user types that code in a browser that holds nothing else; the client
 * is answered and spends what it was given. Every poll is in the trace, each refusal with the reason
 * the provider gave for it.
 *
 * @return array{string, string}
 */
function demo_flow_device_run(string $issuer, string $password, string $ca): array
{
    $cookies = [];
    demo_flow_open($cookies, $ca, $issuer, DEMO_DEVICE_GRANT_TYPE);

    $drawing = demo_flow_advance($cookies, $ca, $issuer, DEMO_DEVICE_GRANT_TYPE);
    $asked = demo_flow_hop($drawing, 'device_authorization_response');
    demo_expect(($asked['status'] ?? null) === 200, 'the client with no browser is handed a code to show (RFC 8628 §3.2)');
    $answer = (array) json_decode((string) ($asked['raw'] ?? ''), true);
    $userCode = (string) ($answer['user_code'] ?? '');
    demo_expect(
        preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $userCode) === 1,
        sprintf('the page shows the code the provider really answered (got "%s")', $userCode),
    );
    $sent = demo_flow_hop($drawing, 'device_authorization_request');
    demo_expect(
        str_contains((string) ($sent['raw'] ?? ''), 'client_id=' . DEMO_DEVICE_CLIENT_ID),
        'the request drawn is the request sent, a public client naming itself in it (RFC 6749 §3.2.1)',
    );

    $drawing = demo_flow_advance($cookies, $ca, $issuer, DEMO_DEVICE_GRANT_TYPE);
    $pending = demo_flow_hop($drawing, 'token_response');
    demo_expect(
        ($pending['failed'] ?? null) === true && str_contains((string) ($pending['reason'] ?? ''), 'authorization_pending'),
        sprintf('a hop that failed is drawn as it failed (%s)', (string) ($pending['reason'] ?? '')),
    );

    // the other device: a browser that holds nothing of the flow but the code it was read
    demo_device_confirm($issuer, $password, $ca, $userCode);

    $drawing = demo_flow_run($cookies, $ca, $issuer, DEMO_DEVICE_GRANT_TYPE);
    $polls = demo_flow_taken($drawing, 'token_request');
    demo_expect($polls >= 2, sprintf('the polling is drawn every time it was asked (%d times)', $polls));
    $typed = demo_flow_hop($drawing, 'user_code');
    demo_expect(
        str_contains((string) ($typed['raw'] ?? ''), $userCode),
        'the hop the user took is in the trace with what their browser posted: the demonstration stood in for nobody',
    );
    $tokens = demo_flow_hop($drawing, 'token_response', true);
    demo_expect(($tokens['failed'] ?? null) === false, 'the client is answered its tokens once the user has answered (RFC 8628 §3.5)');
    demo_expect(
        count((array) ($tokens['jwts'] ?? [])) >= 1,
        'a compact JWT of that answer is drawn raw and decoded, header and claims',
    );
    demo_expect(
        (demo_flow_hop($drawing, 'userinfo_response')['status'] ?? null) === 200,
        'and the client is told who the user is with the token it holds (OIDC Core §5.3.2)',
    );
    demo_flow_drawn_is_planned($drawing);

    return ['A device flow, hop by hop', sprintf('%d hops, %d polls, the code typed in a browser', count((array) $drawing['hops']), $polls)];
}

/**
 * CIBA Core played from a page the same way: the client names the user it is asking for and waits, this
 * provider reaches them, and the answer comes from the page of what is waiting for that user.
 *
 * @return array{string, string}
 */
function demo_flow_backchannel_run(string $issuer, string $password, string $ca): array
{
    $cookies = [];
    demo_flow_open($cookies, $ca, $issuer, DEMO_CIBA_GRANT_TYPE);

    $drawing = demo_flow_advance($cookies, $ca, $issuer, DEMO_CIBA_GRANT_TYPE);
    demo_expect(
        (demo_flow_hop($drawing, 'backchannel_authentication_response')['status'] ?? null) === 200,
        'the client is told the request was taken (CIBA Core §7.3)',
    );
    $sent = (string) (demo_flow_hop($drawing, 'backchannel_authentication_request')['raw'] ?? '');
    parse_str($sent, $fields);
    demo_expect(
        ($fields['login_hint'] ?? '') !== '',
        'the request drawn names the user it is for, as it was sent (§7.1)',
    );
    $binding = (string) ($fields['binding_message'] ?? '');

    $drawing = demo_flow_advance($cookies, $ca, $issuer, DEMO_CIBA_GRANT_TYPE);
    $pending = demo_flow_hop($drawing, 'token_response');
    demo_expect(
        ($pending['failed'] ?? null) === true,
        sprintf('the client is told to wait (%s)', (string) ($pending['reason'] ?? '')),
    );

    // the user, on a device they already hold, reading the message the client wrote
    demo_ciba_approve($issuer, $password, $ca, DEMO_CIBA_CLIENTS['poll']['client'], $binding);

    $drawing = demo_flow_run($cookies, $ca, $issuer, DEMO_CIBA_GRANT_TYPE);
    demo_expect(
        demo_flow_hop($drawing, 'approval') !== null,
        'the answer of the user is in the trace: this provider recorded it as it served it',
    );
    demo_expect(
        (demo_flow_hop($drawing, 'token_response', true)['failed'] ?? null) === false,
        'the client is answered once the user has allowed the request (§10.1)',
    );
    demo_expect(
        (demo_flow_hop($drawing, 'introspection_response')['status'] ?? null) === 200,
        'and the resource server is told what that token is (RFC 7662 §2.2)',
    );
    demo_flow_drawn_is_planned($drawing);

    return ['A backchannel flow, hop by hop', sprintf('%d hops, allowed on the page of the user', count((array) $drawing['hops']))];
}

/**
 * A sign-in replayed after the fact (issue #462): the trace this provider recorded while a client of the
 * forge signed its user in, read from the page that draws it. The back-channel token request is in it,
 * which is the whole reason a narrator living in the page of a client cannot do this.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_forge_replay(array &$cookies, string $ca, string $issuer, string $slug, string $clientId): string
{
    $drawing = demo_flow_trace($cookies, $ca, $issuer, 'authorization_code', $clientId);
    foreach (['authorization_request', 'authorization_response', 'token_request', 'token_response'] as $hop) {
        demo_expect(
            demo_flow_hop($drawing, $hop) !== null,
            sprintf('%s: the hop "%s" of the sign-in is replayed from what this provider recorded', $slug, $hop),
        );
    }
    $sent = (string) (demo_flow_hop($drawing, 'token_request')['raw'] ?? '');
    demo_expect(
        str_contains($sent, 'grant_type=authorization_code'),
        sprintf('%s: the request no browser was in is one of the hops (RFC 6749 §4.1.3)', $slug),
    );
    demo_flow_drawn_is_planned($drawing);

    return sprintf('%d hops replayed', count((array) $drawing['hops']));
}

/**
 * A run started over: what the previous one exchanged is forgotten with it.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_flow_open(array &$cookies, string $ca, string $issuer, string $flow): void
{
    [$status] = demo_request($cookies, $ca, 'POST', $issuer . DEMO_FLOW_OPEN_PATH . '?flow=' . rawurlencode($flow));
    demo_expect($status === 302, sprintf('the run of "%s" is started over (got %d)', $flow, $status));
}

/**
 * One advance of a live run, which is what the next button of the page is: the demonstration takes the
 * next hop of the flow, for real, and answers the trace as it is once it has.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 *
 * @return array<string, mixed>
 */
function demo_flow_advance(array &$cookies, string $ca, string $issuer, string $flow): array
{
    [$status, , $body] = demo_request($cookies, $ca, 'POST', $issuer . DEMO_FLOW_ADVANCE_PATH . '?flow=' . rawurlencode($flow));
    demo_expect($status === 200, sprintf('the next hop of "%s" is taken (got %d: %s)', $flow, $status, $body));

    return (array) json_decode($body, true);
}

/**
 * The trace drawn on the page of a flow, read from the page as every walk of this file reads a page: it
 * carries what it draws in an attribute, so that the script of the page and this walk read one thing.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 *
 * @return array<string, mixed>
 */
function demo_flow_trace(array &$cookies, string $ca, string $issuer, string $flow, ?string $clientId = null): array
{
    $url = $issuer . DEMO_FLOW_PATH . '?flow=' . rawurlencode($flow) . ($clientId === null ? '' : '&client=' . rawurlencode($clientId));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $url);
    demo_expect($status === 200, sprintf('the page of "%s" opens (got %d)', $flow, $status));
    demo_expect(preg_match('/data-trace="([^"]*)"/', $page, $trace) === 1, sprintf('the page of "%s" carries the trace it draws', $flow));

    return [
        'hops' => (array) json_decode(html_entity_decode($trace[1], \ENT_QUOTES), true),
        'plan' => demo_flow_plan($page),
    ];
}

/**
 * The plan drawn on the page of a flow: one row per hop of the picture, with how many times it was
 * taken, read from the rows themselves.
 *
 * @return list<array{name: string, taken: int}>
 */
function demo_flow_plan(string $page): array
{
    preg_match_all('/data-hop="([^"]+)"(?:\s+data-taken="(\d+)")?/', $page, $rows, \PREG_SET_ORDER);
    $plan = [];
    foreach ($rows as $row) {
        $plan[] = [
            'name' => $row[1],
            'taken' => (int) ($row[2] ?? 0),
        ];
    }

    return $plan;
}

/**
 * A run advanced until the flow has nothing left to take, waiting out the interval this provider asks a
 * client to poll on: a client that asks faster is told to slow down, and the demonstration is a client
 * like any other.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 *
 * @return array<string, mixed>
 */
function demo_flow_run(array &$cookies, string $ca, string $issuer, string $flow): array
{
    $drawing = [];
    $hops = -1;
    for ($advance = 0; $advance < DEMO_FLOW_ADVANCES; ++$advance) {
        $drawing = demo_flow_advance($cookies, $ca, $issuer, $flow);
        $taken = count((array) ($drawing['hops'] ?? []));
        if ($taken === $hops) {
            return $drawing;
        }
        $hops = $taken;
        $answer = demo_flow_hop($drawing, 'token_response', true);
        if (($answer['failed'] ?? null) === true) {
            sleep(DEMO_FLOW_POLL_INTERVAL);
        }
    }
    demo_expect(false, sprintf('the run of "%s" ends within %d advances', $flow, DEMO_FLOW_ADVANCES));

    return $drawing;
}

/**
 * One hop of a drawing by name, the first one drawn or the last.
 *
 * @param array<string, mixed> $drawing
 *
 * @return array<string, mixed>|null
 */
function demo_flow_hop(array $drawing, string $name, bool $last = false): ?array
{
    $found = null;
    foreach ((array) ($drawing['hops'] ?? []) as $hop) {
        if (! is_array($hop) || ($hop['name'] ?? null) !== $name) {
            continue;
        }
        if (! $last) {
            return $hop;
        }
        $found = $hop;
    }

    return $found;
}

/**
 * How many times a hop was taken, as the plan of the drawing counts it.
 *
 * @param array<string, mixed> $drawing
 */
function demo_flow_taken(array $drawing, string $name): int
{
    foreach ((array) ($drawing['plan'] ?? []) as $planned) {
        if (is_array($planned) && ($planned['name'] ?? null) === $name) {
            return (int) ($planned['taken'] ?? 0);
        }
    }

    return 0;
}

/**
 * No page shows a payload that was not exchanged, and nothing is drawn that the picture does not plan:
 * every hop of the trace is a hop of the plan, and every hop that was answered says what it carried.
 *
 * @param array<string, mixed> $drawing
 */
function demo_flow_drawn_is_planned(array $drawing): void
{
    $planned = array_column(array_filter((array) ($drawing['plan'] ?? []), is_array(...)), 'name');
    $unplanned = [];
    foreach ((array) ($drawing['hops'] ?? []) as $hop) {
        if (is_array($hop) && ! in_array((string) ($hop['name'] ?? ''), $planned, true)) {
            $unplanned[] = (string) ($hop['name'] ?? '');
        }
    }
    demo_expect($unplanned === [], sprintf('every hop drawn is a hop the picture plans (%s)', implode(', ', $unplanned)));
}

/**
 * The two criteria of spike 5 that are judged at the client and not by the conformance suite (issue #167).
 *
 * The first is that nothing of FAPI 2 reaches a client that did not ask for it: the provider serves PAR,
 * request objects, JARM, DPoP and mTLS, and `oidc-demo` signs in as it always did, with no pushed request,
 * no request object and no proof, and gets a bearer token bound to nothing. No patch, no option, no
 * exception is written for it.
 *
 * The second is that a Symfony resource server verifies a token bound by DPoP. The run plays the client
 * that binds one: it walks the browser through an authorization request of its own, exchanges the code
 * with a proof made for the token endpoint (RFC 9449 §5), and presents what comes back to the two routes
 * `oidc-demo` serves for it, once as the holder of the key and four times as whoever took the token off
 * the wire would: the same proof again, a proof of another key, no proof at all, and as a bearer token.
 * The binding is checked on both shapes of access token, the "cnf.jkt" of an "at+jwt" read by the resource
 * server itself, and the "cnf" of an opaque token read from the introspection response (§7.1).
 *
 * That check is `RS-05` of the Symfony status document, written during this spike and merged into 8.2
 * (symfony/symfony#66465), so the demonstration asks for it of the released component like everything
 * else it uses.
 */
function demo_dpop_check(string $dir, string $issuer, string $password, string $demoSecret, string $opaqueSecret, string $ca): void
{
    io()->section('A token bound to a key, and a client that asked for none');
    $verified = [];

    $metadata = demo_metadata($issuer . '/.well-known/openid-configuration', $ca);
    $algorithms = $metadata['dpop_signing_alg_values_supported'] ?? [];
    demo_expect(
        $algorithms !== []
        && isset($metadata['pushed_authorization_request_endpoint'], $metadata['mtls_endpoint_aliases'])
        && ($metadata['request_parameter_supported'] ?? false) === true
        && ($metadata['authorization_signing_alg_values_supported'] ?? []) !== [],
        'the provider announces the pushed authorization request endpoint, request objects, JARM, DPoP and the mTLS aliases',
    );
    $verified[] = [
        'What the provider serves',
        sprintf(
            'PAR, request objects, JARM, mTLS aliases, and DPoP with %s',
            implode(' ', (array) $algorithms),
        ),
    ];

    $introspection = (string) ($metadata['introspection_endpoint'] ?? '');
    $tokenEndpoint = (string) ($metadata['token_endpoint'] ?? '');
    demo_expect($introspection !== '' && $tokenEndpoint !== '', 'the document names the token endpoint and the introspection endpoint');

    try {
        // the client that asked for none of it, on the very provider that serves all of it
        demo_write_env_local($dir . '/.env.local', [
            'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
            'OIDC_CLIENT_SECRET' => $demoSecret,
            DEMO_INTROSPECTION_ENV => $introspection,
        ]);
        $cookies = [];
        [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
        demo_expect($status === 302, sprintf('/profile sends the browser to the authorization endpoint (got %d)', $status));
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
        demo_expect(
            ! isset($authorization['request'], $authorization['request_uri'], $authorization['dpop_jkt'], $authorization['response_mode']),
            'the authorization request of oidc-demo carries no request object, no pushed request, no key and no response mode',
        );

        $session = demo_sign_in($cookies, $issuer, $password, $ca);
        $accessToken = $session['tokens']['access_token'];
        demo_expect(
            ! isset($accessToken['claims']['cnf']),
            'the access token it gets is bound to nothing: a bearer token, accepted from whoever holds it (RFC 6750 §1)',
        );
        [$status, $body] = demo_api(DEMO_URL . '/api/me/offline', $accessToken['raw']);
        demo_expect($status === 200 && ($body['sub'] ?? null) === ($accessToken['claims']['sub'] ?? null), sprintf(
            'its resource server answers it as before, on a bearer token and nothing else (got %d %s)',
            $status,
            json_encode($body),
        ));
        $verified[] = [
            'oidc-demo, unchanged',
            sprintf(
                'no request object, no pushed request, no proof; access token without cnf, /api/me/offline 200 for sub %s',
                $body['sub'] ?? '?',
            ),
        ];
        demo_logout($cookies, $issuer, $ca);

        // the client that binds its token to a key, on both shapes of access token
        foreach ([
            [DEMO_CLIENT_ID,        $demoSecret,   DEMO_DPOP_PATH,              'at+jwt, the binding read by the resource server itself'],
            [DEMO_OPAQUE_CLIENT_ID, $opaqueSecret, DEMO_DPOP_INTROSPECTED_PATH, 'opaque, the binding read from the introspection response'],
        ] as [$clientId, $secret, $path, $shape]) {
            demo_write_env_local($dir . '/.env.local', [
                'OIDC_CLIENT_ID' => $clientId,
                'OIDC_CLIENT_SECRET' => $secret,
                DEMO_INTROSPECTION_ENV => $introspection,
            ]);
            $cookies = [];
            $verifier = bin2hex(random_bytes(32));
            $callback = demo_login_at($cookies, $issuer, $password, $ca, demo_dpop_authorization($issuer, $clientId, $verifier));
            parse_str((string) parse_url($callback, \PHP_URL_QUERY), $callbackParameters);

            $run = demo_dpop_client([
                'token_endpoint' => $tokenEndpoint,
                'cafile' => $ca,
                'client_id' => $clientId,
                'client_secret' => $secret,
                'redirect_uri' => DEMO_URL . '/oidc/callback',
                'code' => (string) ($callbackParameters['code'] ?? ''),
                'code_verifier' => $verifier,
                'api_url' => DEMO_URL . $path,
            ]);

            demo_expect(($run['token_type'] ?? null) === 'DPoP', sprintf(
                'the token the provider issues on a request that carried a proof is a DPoP token, not a bearer one (RFC 9449 §5, got "%s")',
                $run['token_type'] ?? '',
            ));
            $binding = demo_dpop_binding($issuer, $ca, $clientId, $secret, $run['access_token'], $introspection);
            demo_expect($binding === $run['jkt'], sprintf(
                'the token names the key of the proof in its cnf.jkt (RFC 9449 §6, got "%s" for "%s")',
                $binding,
                $run['jkt'],
            ));

            demo_expect($run['held']['status'] === 200 && ($run['held']['body']['sub'] ?? '') !== '', sprintf(
                'the resource server answers the holder of the key, its proof checked against that cnf.jkt (got %d %s)',
                $run['held']['status'],
                json_encode($run['held']['body']),
            ));
            foreach ([
                'replayed' => 'the same proof a second time, which is a proof taken off the wire (§11.1)',
                'foreign_key' => 'a proof signed by another key, which is what someone holding the token alone can make',
                'no_proof' => 'the token with no proof at all',
                'as_bearer' => 'the token as a bearer token, which the scheme of a bound token is not (§7.1)',
            ] as $attempt => $what) {
                demo_expect($run[$attempt]['status'] === 401, sprintf(
                    '%s is refused (got %d %s)',
                    $what,
                    $run[$attempt]['status'],
                    json_encode($run[$attempt]['body']),
                ));
            }
            demo_expect(
                str_starts_with($run['no_proof']['challenge'], 'DPoP'),
                sprintf('the challenge names the scheme the token is presented under (RFC 9449 §7.1, got "%s")', $run['no_proof']['challenge']),
            );

            $verified[] = [
                sprintf('Bound by DPoP (%s)', $shape),
                sprintf(
                    'token_type DPoP, cnf.jkt %s…, %s 200 for sub %s',
                    substr((string) $run['jkt'], 0, 12),
                    $path,
                    $run['held']['body']['sub'] ?? '?',
                ),
            ];
            $verified[] = [
                'Refused, same token',
                sprintf(
                    'proof replayed %d, other key %d, no proof %d, as a bearer %d; challenge "%s"',
                    $run['replayed']['status'],
                    $run['foreign_key']['status'],
                    $run['no_proof']['status'],
                    $run['as_bearer']['status'],
                    $run['no_proof']['challenge'],
                ),
            ];
        }

        io()->table(['Step', 'Verified'], $verified);
        io()->success('oidc-demo signed in as before on a provider serving all of FAPI 2, and its resource server accepted a DPoP-bound token from the holder of the key and from nobody else.');
        io()->note('A resource server that binds its tokens declares "dpop: true" on its "access_token" firewall (RS-05 of docs/specs/symfony-oauth-oidc-status.md, symfony/symfony#66465); nothing of it reaches the firewalls that do not.');
    } finally {
        demo_write_env_local($dir . '/.env.local', [
            'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
            'OIDC_CLIENT_SECRET' => $demoSecret,
        ]);
    }
}

/**
 * The authorization request of the run itself, the one a client binding its tokens sends: the parameters
 * `oidc_login` would send, PKCE included, and nothing else. The code it comes back with is exchanged by
 * the DPoP client and never by the demonstration, whose callback is only where the browser lands.
 */
function demo_dpop_authorization(string $issuer, string $clientId, string $verifier): string
{
    return $issuer
    . '/authorize?'
    . http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => DEMO_URL . '/oidc/callback',
        'scope' => 'openid profile email',
        'state' => bin2hex(random_bytes(16)),
        'nonce' => bin2hex(random_bytes(16)),
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
        'code_challenge_method' => 'S256',
    ]);
}

/**
 * The DPoP client of tests/demo/, run under the autoloader of the monorepo, which castor does not load.
 *
 * @param array<string, string> $input
 * @return array<string, mixed>
 */
function demo_dpop_client(array $input): array
{
    $process = new Process(['php', DEMO_DPOP_CLIENT], input: (string) json_encode($input));
    $process->setTimeout(120.0);
    $process->run();
    demo_expect($process->isSuccessful(), sprintf('the DPoP client ran (exit %d): %s', $process->getExitCode() ?? -1, trim($process->getErrorOutput())));
    $run = json_decode($process->getOutput(), true);
    demo_expect(is_array($run), 'the DPoP client answered a JSON object: ' . $process->getOutput());

    return $run;
}

/**
 * What the provider says the token is bound to (RFC 7800 §3.1): the "cnf.jkt" of an "at+jwt", read from the
 * token itself, and the one of an opaque token, read where a resource server reads it, at the introspection
 * endpoint.
 */
function demo_dpop_binding(string $issuer, string $ca, string $clientId, string $secret, string $accessToken, string $introspection): string
{
    if (substr_count($accessToken, '.') === 2) {
        return (string) (demo_jwt($accessToken)['claims']['cnf']['jkt'] ?? '');
    }

    $response = http_request('POST', $introspection, [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_basic' => $clientId . ':' . $secret,
        'body' => [
            'token' => $accessToken,
            'token_type_hint' => 'access_token',
        ],
    ]);
    $claims = (array) json_decode($response->getContent(false), true);
    demo_expect(($claims['active'] ?? null) === true, 'the introspection endpoint describes the token to the client it was issued to');

    return (string) ($claims['cnf']['jkt'] ?? '');
}

/**
 * The JWK Set max-age and the JWS lifetimes of the rotation run, seconds: written into apps/op/.env.local
 * for the time of the run (BEFFROI_JWKS_MAX_AGE, BEFFROI_ACCESS_TOKEN_TTL, BEFFROI_ID_TOKEN_TTL, which
 * config/packages/beffroi.yaml reads at runtime), so that the staging delay (max-age plus the 60 s cooldown,
 * StagingDelay) and the retirement window (the longest lifetime) fit in minutes rather than in a quarter
 * of an hour. The max-age stays above the cooldown, or the last section could not tell the two apart: a
 * copy that expires before the cooldown elapsed is refreshed, never refetched.
 */
const DEMO_ROTATION_JWKS_MAX_AGE = 90;

const DEMO_ROTATION_TOKEN_TTL = 60;

/**
 * OidcSignatureVerifier::ROTATION_COOLDOWN of Symfony's oidc_login (StagingDelay::ROTATION_COOLDOWN in
 * the bundle): a JWK Set copy younger than this is not refetched on an unknown "kid".
 */
const DEMO_ROTATION_COOLDOWN = 60;

const DEMO_ROTATION_ENV_MARKER = 'castor demo --rotate';

/**
 * The second success criterion of spike 2 (issue #59): oidc-demo, on Symfony's oidc_login without a
 * patch, notices nothing across a rotation. The seven steps of the issue against the running OP and demo,
 * with the windows shortened for the run (DEMO_ROTATION_*): sign in twice; "beffroi:keys:rotate", a second
 * key in the JWK Set, staged; the scheduled step of the worker activates it when the staging delay
 * elapsed; a fresh browser session signs in and its ID token names the new key; the first session
 * refreshes its access token, signed by the new key; the second session logs out with the ID token of its
 * login, signed by the key now retiring, without a question; the old key retires at its due date, leaves
 * the JWK Set, and its access token is refused at UserInfo. Then the measurement the issue asks for, on
 * the emergency path ("rotate --now"): what oidc_login does on an unknown "kid" with a cold copy of the
 * JWK Set, a warm one younger than the cooldown, and one older. Every fetch of /jwks by the demo is read
 * in the access log of Caddy (docker compose logs op), by the User-Agent of Symfony's HttpClient.
 */
function demo_rotation_check(Context $server, string $issuer, string $password, string $ca): void
{
    io()->section('A rotation, as scheduled');
    $verified = [];
    $fetches = [];
    $utc = new DateTimeZone('UTC');
    $at = static fn (DateTimeImmutable $date): string => $date->setTimezone($utc)->format('H:i:s');

    $tenant = demo_keys();
    $active = array_keys(array_filter($tenant, static fn (array $key): bool => $key['status'] === 'active'));
    $staged = array_keys(array_filter($tenant, static fn (array $key): bool => $key['status'] === 'staged'));
    demo_expect(
        count($active) === 1 && $staged === [],
        sprintf(
            'the tenant has one active key and none staged before the run (got %d active, %d staged: "castor console beffroi:keys:list" says which)',
            count($active),
            count($staged),
        ),
    );
    $kid1 = $active[0];
    demo_rotation_lifetimes($issuer, $ca, true);
    // A cold JWK Set copy, whatever ran before: the demo caches it in cache.app, with the discovery document.
    run(['php', 'bin/console', 'cache:pool:clear', 'cache.app'], context: $server->withQuiet());
    $before = demo_jwks($issuer, $ca);
    io()->text(sprintf(
        ' <info>✓</info> the run: JWK Set max-age %d s, ID and access tokens %d s, staging delay %d s, retirement window %d s; the key "%s" signs, the JWK Set has %d key(s)',
        DEMO_ROTATION_JWKS_MAX_AGE,
        DEMO_ROTATION_TOKEN_TTL,
        DEMO_ROTATION_JWKS_MAX_AGE + DEMO_ROTATION_COOLDOWN,
        DEMO_ROTATION_TOKEN_TTL,
        $kid1,
        count($before),
    ));

    // 1. Two sessions, both signed by the first key: the first refreshes at step 5, the second logs out at
    // step 6 with the ID token of its login. The demo fetches the JWK Set once, for the first.
    io()->text('<comment>1.</comment> Sign in, twice');
    $start = new DateTimeImmutable();
    $first = [];
    $second = [];
    $sessionA = demo_sign_in($first, $issuer, $password, $ca);
    $sessionB = demo_sign_in($second, $issuer, $password, $ca);
    $signedBy = static fn (array $session, string $token): string => (string) ($session['tokens'][$token]['header']['kid'] ?? '?');
    demo_expect(
        $signedBy($sessionA, 'id_token') === $kid1 && $signedBy($sessionA, 'access_token') === $kid1 && $signedBy($sessionB, 'id_token') === $kid1,
        sprintf('the ID tokens and the access token name the active key "%s"', $kid1),
    );
    $fetched = demo_jwks_fetches($start);
    demo_expect(count($fetched) === 1, sprintf('the demo fetched the JWK Set once, for the first verification (got %d)', count($fetched)));
    $verified[] = ['1. Sign in, twice', sprintf('ID tokens and access token signed by %s; one fetch of /jwks at %s (cold copy)', $kid1, $at($fetched[0]))];
    $fetches[] = ['Cold copy', $at($fetched[0]), 'The first verification fetches the JWK Set; the second login used the copy'];
    $firstFetch = $fetched[0];

    // 2. The rotation as an operator does it: the new key is published at once and signs later.
    io()->text('<comment>2.</comment> beffroi:keys:rotate');
    $kid2 = demo_rotate([]);
    $keys = demo_keys();
    $activationDue = $keys[$kid2]['activates_at'] ?? null;
    demo_expect(($keys[$kid2]['status'] ?? null) === 'staged' && $activationDue !== null, sprintf('the key "%s" is staged with an activation date', $kid2));
    $published = demo_jwks($issuer, $ca);
    demo_expect(
        count($published) === (count($before) + 1) && in_array($kid2, $published, true) && in_array($kid1, $published, true),
        sprintf('the JWK Set has one key more, the staged one (got %s)', implode(', ', $published)),
    );
    $verified[] = [
        '2. beffroi:keys:rotate',
        sprintf('%s staged, activates at %s; the JWK Set has %d keys, %s still signs', $kid2, $at($activationDue), count($published), $kid1),
    ];

    // 3. Time activates it: the scheduled step of the worker, every minute (compose.yaml).
    io()->text('<comment>3.</comment> The scheduled step activates the key');
    demo_wait_until($activationDue, sprintf('the staging delay of "%s"', $kid2));
    $deadline = $activationDue->modify('+90 seconds');
    while (($keys = demo_keys())[$kid2]['status'] !== 'active' && new DateTimeImmutable() < $deadline) {
        sleep(3);
    }
    demo_expect($keys[$kid2]['status'] === 'active', sprintf(
        'the scheduled step activated "%s" within 90 s of its date: is the worker running ("docker compose ps worker")? "castor console beffroi:keys:activate %s" does it by hand',
        $kid2,
        $kid2,
    ));
    $activated = new DateTimeImmutable();
    $retirementDue = $keys[$kid1]['retirement_due_at'] ?? null;
    demo_expect($keys[$kid1]['status'] === 'retiring' && $retirementDue !== null, sprintf('the key "%s" is retiring with a retirement date', $kid1));
    io()->text(sprintf(
        ' <info>✓</info> "%s" active at %s, %d s after its date, by the scheduled step; "%s" retiring until %s',
        $kid2,
        $at($activated),
        $activated->getTimestamp() - $activationDue->getTimestamp(),
        $kid1,
        $at($retirementDue),
    ));
    $verified[] = [
        '3. Scheduled activation',
        sprintf(
            '%s active at %s (%d s after its date), %s retiring until %s',
            $kid2,
            $at($activated),
            $activated->getTimestamp() - $activationDue->getTimestamp(),
            $kid1,
            $at($retirementDue),
        ),
    ];

    // 4. A fresh browser: the ID token names the new key. The copy of the demo is older than the max-age
    // by now, the login refreshes it as any expired copy, and the new key was in the JWK Set before it signed.
    io()->text('<comment>4.</comment> Sign in again, in a fresh browser session');
    $third = [];
    $since = new DateTimeImmutable();
    $sessionC = demo_sign_in($third, $issuer, $password, $ca);
    demo_expect(
        $signedBy($sessionC, 'id_token') === $kid2 && $signedBy($sessionC, 'access_token') === $kid2,
        sprintf('the ID token and the access token name the new key "%s"', $kid2),
    );
    $fetched = demo_jwks_fetches($since);
    demo_expect(count($fetched) === 1, sprintf('the demo fetched the JWK Set once during the login (got %d)', count($fetched)));
    $age = $fetched[0]->getTimestamp() - $firstFetch->getTimestamp();
    io()->text(sprintf(
        ' <info>✓</info> one fetch of /jwks at %s, %d s after the copy of step 1, past its max-age of %d s: the refresh of an expired copy, the new key was in it',
        $at($fetched[0]),
        $age,
        DEMO_ROTATION_JWKS_MAX_AGE,
    ));
    $verified[] = [
        '4. Fresh session',
        sprintf('ID token and access token signed by %s; the demo verified them with a copy refreshed at %s', $kid2, $at($fetched[0])),
    ];
    $fetches[] = [
        'Expired copy',
        $at($fetched[0]),
        sprintf('%d s after the previous fetch, past the max-age: refreshed before any check, the staged key was in it', $age),
    ];

    // 5. The first session: its access token expired (lifetime minus the 30 s leeway of oidc_login), the
    // next request renews it with the refresh token grant; the new tokens are signed by the new key and
    // the demo verifies the new ID token; the refresh token, opaque, is not on the page and not concerned.
    io()->text('<comment>5.</comment> The first session refreshes its access token');
    [$status, , $page] = demo_request($first, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile of the first session opens (got %d)', $status));
    $refreshed = demo_tokens_of($page);
    $jtiBefore = $sessionA['tokens']['access_token']['claims']['jti'] ?? '?';
    $jtiAfter = $refreshed['access_token']['claims']['jti'] ?? '?';
    demo_expect($jtiAfter !== $jtiBefore && ($refreshed['access_token']['header']['kid'] ?? null) === $kid2, sprintf(
        'the access token was renewed (jti %s to %s) and is signed by "%s"',
        $jtiBefore,
        $jtiAfter,
        $kid2,
    ));
    demo_expect(($refreshed['id_token']['header']['kid'] ?? null) === $kid2
    && ($refreshed['id_token']['claims']['sub'] ?? null) === ($sessionA['tokens']['id_token']['claims']['sub'] ?? '?'), sprintf(
        'the ID token was re-issued, signed by "%s", same sub, and the demo verified it',
        $kid2,
    ));
    $verified[] = [
        '5. refresh_access_token',
        sprintf('new at+jwt signed by %s (jti %s to %s), ID token re-issued and verified, same sub', $kid2, $jtiBefore, $jtiAfter),
    ];

    // 6. Logout across the rotation, both ways. Through the demo: /logout runs the refresh listener first
    // (priority 0, the logout listener at -127), so the hint is the ID token just re-issued, signed by the
    // new key. As an oidc_login without refresh_access_token (its default) does it, with the ID token of
    // the login, signed by the key now retiring: the very request OidcEndSessionListener builds,
    // id_token_hint and post_logout_redirect_uri, on the OP session of the first browser.
    io()->text('<comment>6.</comment> Log out, with the re-issued ID token and with the one of the login');
    $hint = demo_logout($second, $issuer, $ca);
    demo_expect($hint === $kid2, sprintf(
        'through the demo, the id_token_hint is the ID token re-issued on the refresh, signed by "%s" (got "%s")',
        $kid2,
        $hint,
    ));
    [$status, $location] = demo_request(
        $first,
        $ca,
        'GET',
        $issuer . '/logout?'
            . http_build_query([
                'id_token_hint' => $sessionA['tokens']['id_token']['raw'],
                'post_logout_redirect_uri' => DEMO_URL . '/',
            ]),
    );
    demo_expect($status === 302 && $location === DEMO_URL . '/', sprintf(
        'with the ID token of the login, signed by "%s" (retiring), the OP ends the session without a question (got %d %s)',
        $kid1,
        $status,
        $location,
    ));
    $verified[] = [
        '6. Logout',
        sprintf(
            'through the demo, id_token_hint re-issued and signed by %s; with the ID token of the login, signed by %s (retiring): no confirmation page either way, back to %s/',
            $kid2,
            $kid1,
            DEMO_URL,
        ),
    ];

    // 7. The retirement, when due: every JWS the old key signed has expired.
    io()->text('<comment>7.</comment> The old key retires');
    demo_wait_until($retirementDue, sprintf('the retirement window of "%s"', $kid1));
    $retirement = op_console(['beffroi:keys:retire', '--due', '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect($retirement->isSuccessful(), 'beffroi:keys:retire --due ran (' . trim($retirement->getErrorOutput() . $retirement->getOutput()) . ')');
    $byWhom = str_contains($retirement->getOutput(), 'No key') ? 'by the scheduled step, before the command' : 'by beffroi:keys:retire --due';
    $keys = demo_keys();
    demo_expect(($keys[$kid1]['status'] ?? null) === 'retired', sprintf('the key "%s" is retired (%s)', $kid1, $byWhom));
    $published = demo_jwks($issuer, $ca);
    demo_expect(
        ! in_array($kid1, $published, true) && in_array($kid2, $published, true),
        sprintf('the JWK Set lost "%s" and keeps "%s" (%d key(s): %s)', $kid1, $kid2, count($published), implode(', ', $published)),
    );
    $status = demo_userinfo($issuer, $ca, $sessionA['tokens']['access_token']['raw']);
    demo_expect($status === 401, sprintf('the access token of step 1 is refused at UserInfo (got %d)', $status));
    $verified[] = [
        '7. beffroi:keys:retire --due',
        sprintf('%s retired %s, out of the JWK Set (%d key(s)); the access token of step 1 gets 401 at UserInfo', $kid1, $byWhom, count($published)),
    ];

    // What oidc_login does on an unknown "kid" (OidcSignatureVerifier::getKeys()): a copy older than the
    // max-age is refreshed before any check; a valid copy that lacks the "kid" is refetched once, if it
    // was fetched 60 s ago at least (ROTATION_COOLDOWN), and the verification fails otherwise. Measured on
    // the emergency path, "rotate --now", where the new key signs before any relying party could see it.
    io()->section('What oidc_login does on an unknown "kid"');
    run(['php', 'bin/console', 'cache:pool:clear', 'cache.app'], context: $server->withQuiet());
    $since = new DateTimeImmutable();
    $fourth = [];
    demo_sign_in($fourth, $issuer, $password, $ca);
    $fetched = demo_jwks_fetches($since);
    demo_expect(count($fetched) === 1, sprintf('the demo fetched the JWK Set once, its copy was cold (got %d)', count($fetched)));
    $copy = $fetched[0];
    $kid3 = demo_rotate(['--now']);
    io()->text(sprintf(
        ' <info>✓</info> "%s" signs at once (rotate --now), "%s" is retiring; the copy of the demo, fetched at %s, lacks it and is valid for %d s',
        $kid3,
        $kid2,
        $at($copy),
        DEMO_ROTATION_JWKS_MAX_AGE,
    ));
    $since = new DateTimeImmutable();
    $fifth = [];
    $refused = demo_sign_in_refused($fifth, $issuer, $password, $ca);
    $ageAtRefusal = $since->getTimestamp() - $copy->getTimestamp();
    demo_expect(
        str_contains($refused, 'signature is invalid'),
        sprintf('the login fails on the signature, %d s after the copy was fetched (the demo said: %s)', $ageAtRefusal, $refused),
    );
    demo_expect(demo_jwks_fetches($since) === [], 'the demo did not refetch the JWK Set: its copy is younger than the cooldown');
    $fetches[] = [
        'Warm copy, unknown "kid"',
        $at($since),
        sprintf('%d s after the fetch, under the cooldown: no refetch, the login fails ("%s")', $ageAtRefusal, $refused),
    ];
    demo_wait_until($copy->modify(sprintf('+%d seconds', DEMO_ROTATION_COOLDOWN + 1)), 'the refetch cooldown of oidc_login');
    $since = new DateTimeImmutable();
    $sixth = [];
    $sessionD = demo_sign_in($sixth, $issuer, $password, $ca);
    demo_expect($signedBy($sessionD, 'id_token') === $kid3, sprintf('the login succeeds, the ID token names "%s"', $kid3));
    $fetched = demo_jwks_fetches($since);
    $ageAtRefetch = $fetched === [] ? 0 : $fetched[0]->getTimestamp() - $copy->getTimestamp();
    demo_expect(
        count($fetched) === 1 && $ageAtRefetch < DEMO_ROTATION_JWKS_MAX_AGE,
        sprintf('the demo refetched the JWK Set once while its copy was still valid (got %d fetch(es), %d s after the copy)', count($fetched), $ageAtRefetch),
    );
    $fetches[] = [
        'Warm copy, unknown "kid", past the cooldown',
        $at($fetched[0]),
        sprintf('%d s after the fetch: one refetch, the new key is in it, the login succeeds', $ageAtRefetch),
    ];

    io()->table(['Step', 'Verified'], $verified);
    io()->table(['JWK Set copy of the demo', 'At (UTC)', 'What oidc_login did'], $fetches);
    demo_rotation_lifetimes($issuer, $ca, false);
    io()->note(sprintf(
        'The OP is left with "%s" active and "%s" retiring until %s, the retirement window of the run; the lifetimes of apps/op/.env are back.',
        $kid3,
        $kid2,
        $at(demo_keys()[$kid2]['retirement_due_at'] ?? new DateTimeImmutable()),
    ));
    io()->success('oidc-demo noticed nothing across a scheduled rotation; on an unknown "kid", oidc_login refetches the JWK Set once its copy is 60 s old, and refuses the token before that.');
}

/**
 * Shortens the windows of a rotation in apps/op/.env.local for the run, or removes them: a block the task
 * owns, rewritten every time (a run interrupted before its end leaves it, the next one removes it). The
 * workers of the op container restart on the change (the watch of compose.yaml), the console commands
 * read the file each time; the JWK Set says when the new values serve.
 */
function demo_rotation_lifetimes(string $issuer, string $ca, bool $shorten): void
{
    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    $block = sprintf('/\n*###> %1$s ###\n.*?###< %1$s ###\n/s', preg_quote(DEMO_ROTATION_ENV_MARKER, '/'));
    $content = rtrim((string) preg_replace($block, "\n", (string) file_get_contents($path)), "\n") . "\n";
    if ($shorten) {
        $content .= sprintf(
            "\n###> %1\$s ###\nBEFFROI_JWKS_MAX_AGE=%2\$d\nBEFFROI_ACCESS_TOKEN_TTL=%3\$d\nBEFFROI_ID_TOKEN_TTL=%3\$d\n###< %1\$s ###\n",
            DEMO_ROTATION_ENV_MARKER,
            DEMO_ROTATION_JWKS_MAX_AGE,
            DEMO_ROTATION_TOKEN_TTL,
        );
        // demo_expect() exits, and exit() skips finally blocks: the file is restored whatever ends the run.
        register_shutdown_function(static function () use ($path, $block): void {
            file_put_contents($path, rtrim((string) preg_replace($block, "\n", (string) file_get_contents($path)), "\n") . "\n");
        });
    }
    file_put_contents($path, $content);
    // The worker is the process that dates the retirement of the key it replaces (the longest lifetime of a
    // JWS, read on the issuers of its own container): a consumer reads the file once, at its start.
    run(['docker', 'compose', 'restart', 'worker'], context: context()->withQuiet());
    $deadline = time() + 60;
    do {
        $response = http_request('GET', $issuer . '/jwks', [
            'cafile' => $ca,
        ]);
        $maxAge = preg_match('/max-age=(\d+)/', $response->getHeaders(false)['cache-control'][0] ?? '', $match) === 1 ? (int) $match[1] : null;
        if (($maxAge === DEMO_ROTATION_JWKS_MAX_AGE) === $shorten) {
            io()->text(sprintf(
                ' <info>✓</info> %s %s; the JWK Set announces max-age=%d, the worker restarted',
                $shorten ? 'wrote the windows of the run into' : 'removed the windows of the run from',
                DEV_ENV_LOCAL,
                $maxAge,
            ));

            return;
        }
        sleep(1);
    } while (time() < $deadline);
    io()->error(sprintf(
        'The OP still announces max-age=%d on its JWK Set a minute after %s changed: do the workers of the op container watch .env.local (compose.yaml)?',
        $maxAge,
        DEV_ENV_LOCAL,
    ));
    exit(1);
}

/**
 * The published keys of the tenant, in the order of the JWK Set.
 *
 * @return list<string>
 */
function demo_jwks(string $issuer, string $ca): array
{
    $jwks = json_decode(http_request('GET', $issuer . '/jwks', [
        'cafile' => $ca,
    ])->getContent(), true);

    return array_values(array_map(static fn (array $key): string => (string) $key['kid'], is_array($jwks['keys'] ?? null) ? $jwks['keys'] : []));
}

/**
 * The keys of the tenant with their status and the two dates the run waits for, read from beffroi:keys:list.
 *
 * @return array<string, array{status: string, activates_at: ?DateTimeImmutable, retirement_due_at: ?DateTimeImmutable}>
 */
function demo_keys(): array
{
    $output = (string) preg_replace('/\s+/', ' ', op_console(['beffroi:keys:list', '--all', '--no-ansi'], context()->withQuiet())->getOutput());
    $keys = [];
    preg_match_all('/Key identifier (\S+) Algorithm \S+ Status (\S+)(.*?)(?=Key identifier|$)/', $output, $matches, \PREG_SET_ORDER);
    foreach ($matches as $match) {
        $date = static fn (string $label) => preg_match('/' . $label . ' (\S+)/', $match[3], $found) === 1 ? new DateTimeImmutable($found[1]) : null;
        $keys[$match[1]] = [
            'status' => $match[2],
            'activates_at' => $date('Activates at'),
            'retirement_due_at' => $date('Retirement due at'),
        ];
    }

    return $keys;
}

/**
 * Runs beffroi:keys:rotate on the OP, shows its output, and returns the identifier of the new key.
 *
 * @param array<string> $options
 */
function demo_rotate(array $options): string
{
    $rotated = op_console(['beffroi:keys:rotate', ...$options, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect($rotated->isSuccessful(), 'beffroi:keys:rotate ran (' . trim($rotated->getErrorOutput() . $rotated->getOutput()) . ')');
    demo_expect(preg_match('/Key identifier\s+(\S+)/', $rotated->getOutput(), $match) === 1, 'beffroi:keys:rotate named the new key');

    return $match[1];
}

/**
 * When the demo fetched the JWK Set of the OP since the given instant: the access log of Caddy (op
 * container), the requests on /jwks whose User-Agent is the one of Symfony's HttpClient, which the demo
 * uses (the conformance suite and a browser say otherwise). Caddy logs in UTC.
 *
 * @return list<DateTimeImmutable>
 */
function demo_jwks_fetches(DateTimeImmutable $since): array
{
    $log = run([
        'docker',
        'compose',
        'logs',
        'op',
        '--no-log-prefix',
        '--since',
        $since->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z'),
    ], context: context()->withQuiet())->getOutput();
    $fetches = [];
    foreach (preg_split('/\R/', $log) ?: [] as $line) {
        if (preg_match('/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\t.*handled request\t(\{.*\})$/', $line, $match) !== 1) {
            continue;
        }
        $entry = json_decode($match[2], true);
        if (
            ! is_array($entry)
            || ($entry['request']['uri'] ?? null) !== '/jwks'
            || ! str_contains(implode(' ', $entry['request']['headers']['User-Agent'] ?? []), 'Symfony HttpClient')
        ) {
            continue;
        }
        $at = new DateTimeImmutable(str_replace('/', '-', $match[1]), new DateTimeZone('UTC'));
        if ($at >= $since->modify('-1 second')) {
            $fetches[] = $at;
        }
    }

    return $fetches;
}

function demo_wait_until(DateTimeImmutable $when, string $what): void
{
    $seconds = $when->getTimestamp() - time() + 1;
    if ($seconds <= 0) {
        return;
    }
    io()->text(sprintf('   waiting %d s for %s, until %s UTC', $seconds, $what, $when->setTimezone(new DateTimeZone('UTC'))->format('H:i:s')));
    sleep($seconds);
}

/**
 * The status UserInfo gives a bearer access token.
 */
function demo_userinfo(string $issuer, string $ca, string $accessToken): int
{
    return http_request('GET', $issuer . '/userinfo', [
        'cafile' => $ca,
        'auth_bearer' => $accessToken,
    ])->getStatusCode();
}

/**
 * The walk of a browser from /profile of the demo to the callback of the demo, one request at a time (no
 * redirect followed), every step looked at: PKCE S256 in the authorization request, the login page of the
 * OP and its form, "iss" on the callback (RFC 9207). Returns the URL of the callback, for the caller to
 * see what the demo makes of it.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_authenticate(array &$cookies, string $issuer, string $password, string $ca, string $clientId = DEMO_CLIENT_ID): string
{
    // /profile: the demo starts the flow
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/authorize?'),
        sprintf('/profile sends the browser to the authorization endpoint (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
    demo_expect(($authorization['response_type'] ?? null) === 'code'
    && ($authorization['code_challenge_method'] ?? null) === 'S256'
    && ($authorization['client_id'] ?? null) === $clientId, sprintf('the authorization request is response_type=code with PKCE S256, client_id=%s', $clientId));

    return demo_login_at($cookies, $issuer, $password, $ca, $location);
}

/**
 * The login the provider asks for before it can answer an authorization request, one request at a time: it
 * parks the request, sends the browser to its login page, and that page carries the form. Returns where the
 * login sent the browser, which is the interaction to resume; what the provider then answers the request
 * with is the caller's to read, a redirection for most clients and a page for a response mode of its own.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_login(array &$cookies, string $issuer, string $password, string $ca, string $authorization): string
{
    // the OP parks the request and asks for a login
    [$status, $location] = demo_request($cookies, $ca, 'GET', $authorization);
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login?interaction='),
        sprintf('the OP asks for a login (got %d %s)', $status, $location),
    );
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('the login page opens (got %d)', $status));
    $page = demo_past_the_address($cookies, $ca, $issuer, $page);
    $form = demo_form_with($page, '_username', 'the login page carries the form of the password');
    demo_expect(
        preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'which says where it posts and carries its token',
    );

    // the form, then the login page resumes the interaction. The firewall sends the browser back to the
    // very URL the form was posted to, whether it took the password or not (LoginController): what the
    // outcome was is read where the interaction is resumed, not here (demo_resume).
    [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_username' => DEV_USERNAME,
        '_password' => $password,
        '_csrf_token' => $csrf[1],
    ]);
    demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));

    return $location;
}

/**
 * The browser from an authorization request to the callback it is sent to: the login above, then the
 * interaction resumed into the redirect the client registered. Returns that redirect, for the caller to
 * see what is on it; the authorization request is the caller's, whether the demo built it or the run did.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_login_at(array &$cookies, string $issuer, string $password, string $ca, string $authorization): string
{
    [$status, $location] = demo_resume($cookies, $ca, $issuer, demo_login($cookies, $issuer, $password, $ca, $authorization));
    demo_expect(
        $status === 302 && str_starts_with($location, DEMO_URL . '/oidc/callback?'),
        sprintf('the OP sends the browser to the callback of the demo (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(isset($callback['code'], $callback['state']) && ($callback['iss'] ?? null) === $issuer, 'the callback carries code, state and iss (RFC 9207)');

    return $location;
}

/**
 * The interaction resumed, and the consent given if the provider asks for one (architecture §4.3, OIDC
 * Core §3.1.2.4): the browser goes where the login sent it, and a client that is not exempt from the
 * consent puts one page more between that login and its response, which the walk answers as whoever is in
 * front of the browser would. A client the provider does not ask about, and a consent already in force,
 * go straight through: the page is answered when it is shown and never expected.
 *
 * What comes back is what the provider answers the request with, a redirection to the client or the page
 * a response mode of its own renders, so that every walk reads its answer where it already read it.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @param (callable(string): void)|null $onConsent handed the consent page before it is answered, for a walk
 *                                                that has something to read on it
 * @return array{int, string, string, array<string, list<string>>}
 */
function demo_resume(array &$cookies, string $ca, string $issuer, string $url, ?callable $onConsent = null): array
{
    [$status, $location, $page, $headers] = demo_request($cookies, $ca, 'GET', $url);
    // A login that was refused brings the browser back to the form, which says so; a login that was taken
    // resumes into what the provider answers the request with. The two are the same redirection, so this is
    // where a refusal is named, rather than three requests later (LoginController, the page of the login).
    demo_expect(! str_contains($page, 'data-error="authentication_failed"'), sprintf(
        'the login page does not come back saying the sign-in was refused ("beffroi:user:show %s" says which credentials that user holds, and a second factor is one no walk of this file answers)',
        DEV_USERNAME,
    ));
    if ($status !== 302 || ! str_starts_with($location, $issuer . '/consent?')) {
        return [$status, $location, $page, $headers];
    }
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('the consent page opens (got %d)', $status));
    $form = demo_form_with($page, 'answer', 'the consent page carries the form of the answer');
    demo_expect(
        preg_match('/name="_token" value="([^"]+)"/', $form, $token) === 1
        && preg_match('/name="interaction" value="([^"]+)"/', $form, $interaction) === 1
        && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'which names the interaction it answers, says where it posts and carries its token',
    );
    if ($onConsent !== null) {
        $onConsent($page);
    }

    return demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        'interaction' => $interaction[1],
        '_token' => $token[1],
        'answer' => 'allow',
    ]);
}

/**
 * A sign-in through the demo: the walk to the callback, then the demo exchanges the code, verifies the ID
 * token, reads UserInfo and opens /profile, whose tokens are returned.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @return array{page: string, tokens: array<string, array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}>}
 */
function demo_sign_in(array &$cookies, string $issuer, string $password, string $ca): array
{
    $location = demo_authenticate($cookies, $issuer, $password, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/profile', sprintf('the demo signs the user in (got %d %s)', $status, $location));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile opens (got %d)', $status));
    $tokens = demo_tokens_of($page);
    demo_expect(isset($tokens['id_token'], $tokens['access_token']), '/profile shows an ID token and an access token');

    return [
        'page' => $page,
        'tokens' => $tokens,
    ];
}

/**
 * The step of the address of the login page (spec/saml.md S-61): a tenant that federates an e-mail domain to an
 * upstream identity provider, as the development tenant does (beffroi.saml.identity_providers, "castor saml-idp"), asks
 * for the address first and offers nothing else. A username holds no "@" and is of no domain, so the page sends it on
 * to the usual login page, which this returns, its field of the username holding it; a login page that asks for no
 * address is returned as it is.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_past_the_address(array &$cookies, string $ca, string $issuer, string $page, string $username = DEV_USERNAME): string
{
    if (! str_contains($page, 'data-step="address"')) {
        return $page;
    }
    $form = demo_form_with($page, '_address', 'the login page asks for the address first');
    demo_expect(
        preg_match('/name="_token" value="([^"]+)"/', $form, $token) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'which carries its token and says where it posts',
    );
    [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_address' => $username,
        '_token' => $token[1],
    ]);
    demo_expect(
        in_array($status, [302, 303], true) && str_starts_with($location, $issuer . '/login'),
        sprintf('%s, of no domain, goes on to the usual login page (got %d %s)', $username, $status, $location),
    );
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('which opens (got %d)', $status));

    return $page;
}

/**
 * The form of a page that carries a field, from its opening tag to its closing one, which is the form a
 * browser would submit when somebody answers with that field.
 *
 * A page of an interaction carries the question it asks and the controls the layout of the deployment puts
 * on it, the language and the theme being two, each a form of its own with a token of its own
 * (apps/op/templates). A walk that posted to the first form of the page would send the answer of the
 * question to whichever control the layout happens to render first, and be refused for a token that was
 * never its own. So the form is named by the field that belongs to the question.
 */
function demo_form_with(string $page, string $field, string $what): string
{
    $pattern = sprintf('/<form\b(?:(?!<\/form>).)*?name="%s"(?:(?!<\/form>).)*<\/form>/s', preg_quote($field, '/'));
    demo_expect(preg_match($pattern, $page, $form) === 1, $what);

    return $form[0];
}

/**
 * A sign-in the demo refuses at the callback: the browser lands on the failure path of oidc_login, the
 * login page of the demo, which says why. Returns that reason.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_sign_in_refused(array &$cookies, string $issuer, string $password, string $ca): string
{
    $location = demo_authenticate($cookies, $issuer, $password, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/login', sprintf(
        'the demo refuses the login and sends the browser to its failure path (got %d %s)',
        $status,
        $location,
    ));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/login');
    demo_expect($status === 200 && preg_match('/<code>([^<]+)<\/code>/', $page, $detail) === 1, 'the login page of the demo says why');

    return html_entity_decode($detail[1]);
}

/**
 * RP-Initiated Logout through the demo: /logout ends its session and sends the browser to the end session
 * endpoint of the OP with id_token_hint and post_logout_redirect_uri, the OP ends its session and sends
 * the browser back. Returns the "kid" of the hint, the ID token the session held.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_logout(array &$cookies, string $issuer, string $ca): string
{
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/logout');
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/logout?'),
        sprintf('/logout sends the browser to the end session endpoint (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $logout);
    demo_expect(
        is_string($logout['id_token_hint'] ?? null) && ($logout['post_logout_redirect_uri'] ?? null) === DEMO_URL . '/',
        'the logout request carries id_token_hint and post_logout_redirect_uri',
    );
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/', sprintf(
        'the OP ends the session and sends the browser back to the demo (got %d %s)',
        $status,
        $location,
    ));

    return (string) (demo_jwt($logout['id_token_hint'])['header']['kid'] ?? '?');
}

/**
 * One request of the browser of the check, cookies kept per host, no redirect followed. The demo is a
 * development server with a certificate of the Symfony CLI, verified against nothing; the OP is verified
 * against the CA of Caddy.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @param array<string, string> $form
 * @param list<string> $setCookies filled with the Set-Cookie headers of the response, for a check that
 *                                 looks at the attributes of a cookie and not only at its value
 * @return array{int, string, string, array<string, list<string>>} status, Location, body, headers
 */
function demo_request(array &$cookies, string $ca, string $method, string $url, array $form = [], array &$setCookies = []): array
{
    $host = (string) parse_url($url, \PHP_URL_HOST);
    $options = [
        'max_redirects' => 0,
        'headers' => [
            'Cookie' => implode('; ', array_map(
                static fn (string $name, string $value): string => $name . '=' . $value,
                array_keys($cookies[$host] ?? []),
                array_values($cookies[$host] ?? []),
            )),
        ],
    ];
    if ($host === 'localhost') {
        $options['verify_peer'] = false;
        $options['verify_host'] = false;
    } else {
        $options['cafile'] = $ca;
    }
    if ($form !== []) {
        $options['body'] = $form;
    }
    $response = http_request($method, $url, $options);
    $headers = $response->getHeaders(false);
    $setCookies = $headers['set-cookie'] ?? [];
    foreach ($setCookies as $cookie) {
        [$pair] = explode(';', $cookie, 2);
        [$name, $value] = explode('=', $pair, 2)
        + [
            1 => '',
        ];
        $cookies[$host][trim($name)] = trim($value);
    }

    // a Location may be relative (RFC 9110 §10.2.2): resolved against the origin of the request
    $location = $headers['location'][0] ?? '';
    if (str_starts_with($location, '/')) {
        $port = parse_url($url, \PHP_URL_PORT);
        $location = sprintf('%s://%s%s%s', (string) parse_url($url, \PHP_URL_SCHEME), $host, $port === null ? '' : ':' . $port, $location);
    }

    return [$response->getStatusCode(), $location, $response->getContent(false), $headers];
}

function demo_expect(bool $condition, string $what): void
{
    if (! $condition) {
        io()->error('Not verified: ' . $what);
        exit(1);
    }
    io()->text(' <info>✓</info> ' . $what);
}

/**
 * The tokens the profile page prints in full, by their kind: the header "typ" tells the access token
 * (RFC 9068 §2.1), the audience the ID token (OIDC Core §2; the nonce would not do, an ID token issued on
 * a refresh carries none, §12.2).
 *
 * @return array<string, array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}>
 */
function demo_tokens_of(string $page): array
{
    $tokens = [];
    preg_match_all('/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/', $page, $matches);
    foreach (array_unique($matches[0]) as $jwt) {
        $token = demo_jwt($jwt);
        if (($token['header']['typ'] ?? null) === 'at+jwt') {
            $tokens['access_token'] = $token;
        } elseif (isset($token['claims']['aud'], $token['claims']['sub'])) {
            $tokens['id_token'] = $token;
        }
    }

    return $tokens;
}

/**
 * A compact JWS read, not verified: the check looks at what the demo shows, the demo verified it.
 *
 * @return array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}
 */
function demo_jwt(string $jwt): array
{
    [$header, $payload] = explode('.', $jwt)
    + [
        1 => '',
    ];
    $decode = static fn (string $part): array => (array) json_decode((string) base64_decode(strtr($part, '-_', '+/'), true), true);

    return [
        'raw' => $jwt,
        'header' => $decode($header),
        'claims' => $decode($payload),
    ];
}

/**
 * The CLI of the device grant (issue #228): tests/demo/device-cli.php, the program of an appliance with no
 * browser and no secret, and the client the application registers for it.
 */
const DEMO_DEVICE_CLI = 'tests/demo/device-cli.php';

const DEMO_DEVICE_CLIENT_ID = 'demo-appliance';

/**
 * The resource the service and the gateway ask their tokens for, which is the one the resource server of the
 * demonstration answers for (its OIDC_RESOURCE), and the one it does not: a token addressed elsewhere is
 * refused there rather than described (RFC 8707 §2).
 */
const DEMO_SERVICE_RESOURCE = DEMO_URL . '/api/service';

const DEMO_OTHER_RESOURCE = 'https://cal.example.com/';

const DEMO_SERVICE_CLIENT_ID = 'demo-service';

const DEMO_GATEWAY_CLIENT_ID = 'demo-gateway';

const DEMO_ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * The first interoperability criterion of spike 6 (issue #228): a PHP CLI obtains a token by the device
 * grant (RFC 8628), with the code it displays confirmed in a browser. What makes it a demonstration rather
 * than a test is that the two halves are really two: the CLI runs as its own process and polls the token
 * endpoint, while this walk goes to the address it printed and answers as whoever is in front of the browser
 * would, on a device that shares nothing with it but the code.
 *
 * Every step is asserted as the forge asserts its presets: what the provider hands the CLI to display
 * (§3.2), what the page shows of the request before anybody agrees to it (BCP 10027 §2: the provider that
 * asks, the client that asks, where it asked from, the code itself), and what the CLI ends up holding.
 */
function demo_device_check(string $issuer, string $password, string $ca): void
{
    io()->section('A CLI on the device grant');
    $verified = [];

    $cli = new Process(
        ['php', DEMO_DEVICE_CLI, '--issuer=' . $issuer, '--client-id=' . DEMO_DEVICE_CLIENT_ID, '--cafile=' . $ca, '--timeout=120'],
        timeout: 180.0,
    );
    $cli->start();

    try {
        // RFC 8628 §3.2: what the appliance is given to show, read from the first line it writes
        $asked = demo_cli_step($cli, 'device_authorization');
        $userCode = (string) ($asked['user_code'] ?? '');
        demo_expect(
            preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $userCode) === 1,
            sprintf('the CLI is given a code a user can read out loud (got "%s")', $userCode),
        );
        demo_expect(
            ($asked['verification_uri'] ?? null) === $issuer . '/device',
            sprintf('the code is typed at %s (got %s)', $issuer . '/device', (string) ($asked['verification_uri'] ?? '')),
        );
        demo_expect(
            is_string($asked['verification_uri_complete'] ?? null) && str_contains((string) $asked['verification_uri_complete'], $userCode),
            'the provider also hands it an address that carries the code (RFC 8628 §3.3.1)',
        );
        demo_expect(
            is_int($asked['interval'] ?? null) && $asked['interval'] > 0 && is_int($asked['expires_in'] ?? null),
            sprintf('it is told how often to ask and for how long (%s s, %s s)', (string) ($asked['interval'] ?? '?'), (string) ($asked['expires_in'] ?? '?')),
        );
        $verified[] = [
            'Device authorization',
            sprintf('code %s at %s, every %d s for %d s', $userCode, (string) $asked['verification_uri'], (int) $asked['interval'], (int) $asked['expires_in']),
        ];

        // the other device: a browser that knows nothing of the CLI but the code it was read
        demo_device_confirm($issuer, $password, $ca, $userCode);
        $verified[] = ['Confirmation in a browser', sprintf('%s signed in, read what the code asks for and allowed it', DEV_USERNAME)];

        // the CLI was polling all along, and answers itself once somebody has answered for it
        $tokens = demo_cli_step($cli, 'tokens');
        demo_expect(($tokens['token_type'] ?? null) === 'Bearer', sprintf('the CLI holds a bearer token (got %s)', (string) ($tokens['token_type'] ?? '')));
        demo_expect(($tokens['sub'] ?? null) !== null, 'the token names the user who confirmed the code');
        demo_expect(($tokens['refresh_token'] ?? false) === true, 'it also holds a refresh token, so it never pairs again (RFC 8628 §3.5)');
        demo_expect(($tokens['id_token'] ?? false) === true, 'and an ID token, the request having asked for "openid"');
        demo_expect(
            is_int($tokens['polls'] ?? null) && $tokens['polls'] >= 2,
            sprintf('it asked more than once and was told to wait before it was answered (%s polls)', (string) ($tokens['polls'] ?? '?')),
        );
        $verified[] = [
            'Tokens',
            sprintf(
                '%s token for "%s", with a refresh token, after %d polls',
                (string) $tokens['token_type'],
                (string) ($tokens['scope'] ?? '?'),
                (int) $tokens['polls'],
            ),
        ];

        $cli->wait();
        demo_expect($cli->isSuccessful(), sprintf('the CLI ends without an error (exit %s)', (string) $cli->getExitCode()));
    } finally {
        if ($cli->isRunning()) {
            $cli->stop();
        }
    }

    io()->table(['Step', 'Verified'], $verified);
    io()->success('A program with no browser and no secret signed a user in, on a code that user typed somewhere else.');
}

/**
 * The next step a CLI of tests/demo/ writes on its standard output, one JSON object per line: the device
 * grant, the backchannel client and the native client all report that way, because all three keep working
 * while the walk does something else. The lines are read as they come and never waited for all at once; a
 * line that says the flow ended is an error of the run and is reported as it is.
 *
 * @throws RuntimeException when the CLI ends before the step, or says the flow ended without tokens
 *
 * @return array<string, mixed>
 */
function demo_cli_step(Process $cli, string $step, float $timeout = 150.0): array
{
    $deadline = microtime(true) + $timeout;
    $consumed = 0;
    while (microtime(true) < $deadline) {
        $lines = explode("\n", $cli->getIncrementalOutput());
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            ++$consumed;
            $decoded = json_decode($line, true);
            if (! is_array($decoded)) {
                continue;
            }
            if (($decoded['step'] ?? null) === 'error') {
                throw new RuntimeException(sprintf('the CLI gave up: %s', (string) ($decoded['error'] ?? '')));
            }
            if (($decoded['step'] ?? null) === $step) {
                return $decoded;
            }
        }
        if (! $cli->isRunning() && $consumed > 0 && $cli->getIncrementalOutput() === '') {
            throw new RuntimeException(sprintf('the CLI ended before writing its "%s" step', $step));
        }
        usleep(200_000);
    }

    throw new RuntimeException(sprintf('the CLI did not write its "%s" step within %.0f s', $step, $timeout));
}

/**
 * The other device of the device grant (RFC 8628 §3.3): a browser that holds nothing of the flow but the
 * code, signs its user in at the provider, reads what the code is asking for and allows it. The page is
 * asserted against BCP 10027 §2, which is what tells this flow from one where a code is enough.
 */
function demo_device_confirm(string $issuer, string $password, string $ca, string $userCode): void
{
    $cookies = [];
    $page = $issuer . '/device?user_code=' . rawurlencode($userCode);

    // no session yet, so the page asks for a login and remembers the code it was carrying
    [$status, $location] = demo_request($cookies, $ca, 'GET', $page);
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login'),
        sprintf('the page of the code asks for a login first (got %d %s)', $status, $location),
    );
    [$status, , $login] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('the login page opens (got %d)', $status));
    $login = demo_past_the_address($cookies, $ca, $issuer, $login);
    $form = demo_form_with($login, '_username', 'the login page carries the form of the password');
    demo_expect(
        preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'which says where it posts and carries its token',
    );
    [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_username' => DEV_USERNAME,
        '_password' => $password,
        '_csrf_token' => $csrf[1],
    ]);
    demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));

    // the login brings the browser back to the code it was carrying (LoginTarget)
    [$status, , $approval] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect(
        $status === 200 && str_contains($approval, 'data-warning="unexpected"'),
        sprintf('the browser comes back to the page that asks about the code (got %d %s)', $status, $location),
    );
    demo_expect(
        str_contains($approval, $userCode),
        sprintf('the page shows the code as the appliance shows it, separator included (BCP 10027 §2: %s)', $userCode),
    );
    demo_expect(
        preg_match('/data-provider="([^"]+)"/', $approval) === 1 && preg_match('/data-origin="([^"]*)"/', $approval) === 1,
        'it names the provider that is asking and where the request came from (BCP 10027 §2)',
    );
    demo_expect(
        preg_match_all('/data-scope="([^"]+)"/', $approval, $scopes) >= 1 && in_array('openid', $scopes[1], true),
        sprintf('it names every scope of the request (%s)', implode(' ', $scopes[1] ?? [])),
    );

    // allow, with the token of the page and the code it carried
    $fields = demo_form_fields($approval);
    [$status, , $answered] = demo_request($cookies, $ca, 'POST', $issuer . '/device', [
        ...$fields,
        'answer' => 'allow',
    ]);
    demo_expect($status === 200, sprintf('the answer is accepted (got %d)', $status));
    demo_expect(
        ! str_contains($answered, 'data-warning="unexpected"'),
        'and the page no longer asks anything: the appliance is what continues the flow (RFC 8628 §3.3)',
    );
}

/**
 * The second and third interoperability criteria of spike 6 (issue #228): a service obtains a token for
 * itself (RFC 6749 §4.4) for a resource it named (RFC 8707 §2), a gateway exchanges that token to act on its
 * behalf (RFC 8693), and the resource server of the demonstration is handed the result.
 *
 * Three parties and no browser anywhere. What the resource server proves is what Symfony gives a resource
 * server: its `access_token` authenticator compares the `aud` of the token with the identifier of the
 * resource it answers for, so a token addressed to the other resource is refused there without the provider
 * being asked anything. Who is acting for the subject is in the token and not in what the authenticator
 * hands over, so the route reads it from the payload the firewall has already verified; that is the gap this
 * criterion measures, and it is written down as `RS-16` of the Symfony status document.
 */
function demo_service_check(string $dir, string $issuer, string $serviceSecret, string $gatewaySecret, string $ca): void
{
    io()->section('A service, a gateway acting for it, and a resource server');
    $verified = [];

    // the resource server answers for one resource, which is what its firewall compares an "aud" with
    demo_write_env_local($dir . '/.env.local', [
        'OIDC_RESOURCE' => DEMO_SERVICE_RESOURCE,
    ]);
    $server = demo_context($dir)->withQuiet();
    run(['symfony', 'server:stop'], context: $server->withAllowFailure());
    demo_server_start($server);

    // RFC 6749 §4.4: the service asks for itself, and names what the token is for
    $service = demo_client_credentials($issuer, $ca, DEMO_SERVICE_CLIENT_ID, $serviceSecret, DEMO_SERVICE_RESOURCE);
    $claims = demo_claims_of($service['access_token']);
    demo_expect(($claims['sub'] ?? null) === DEMO_SERVICE_CLIENT_ID, sprintf(
        'the token of the service names it in "sub" (got %s)',
        (string) ($claims['sub'] ?? ''),
    ));
    demo_expect(($claims['aud'] ?? null) === DEMO_SERVICE_RESOURCE, sprintf(
        'it is addressed to the resource it asked for (got %s)',
        json_encode($claims['aud'] ?? null),
    ));
    demo_expect(! isset($claims['sid'], $claims['auth_time']), 'and says nothing of a sign-in: nobody signed in for it (RFC 6749 §4.4)');
    demo_expect(! isset($service['refresh_token'], $service['id_token']), 'the response carries an access token and nothing else (§4.4.3)');
    demo_expect(
        ($claims['may_act']['sub'] ?? null) === DEMO_GATEWAY_CLIENT_ID,
        sprintf('the token says who may act for its subject (RFC 8693 §4.4: %s)', (string) ($claims['may_act']['sub'] ?? '')),
    );
    $verified[] = ['client_credentials', sprintf('%s holds a token for %s, may_act %s', DEMO_SERVICE_CLIENT_ID, DEMO_SERVICE_RESOURCE, DEMO_GATEWAY_CLIENT_ID)];

    // RFC 8693 §2.1: the gateway presents the token of the service and a token of its own, which is what
    // makes the exchange a delegation rather than an impersonation (§1.3)
    $gateway = demo_client_credentials($issuer, $ca, DEMO_GATEWAY_CLIENT_ID, $gatewaySecret, DEMO_SERVICE_RESOURCE);
    $exchanged = demo_token_exchange($issuer, $ca, $gatewaySecret, $service['access_token'], $gateway['access_token'], DEMO_SERVICE_RESOURCE);
    $claims = demo_claims_of($exchanged['access_token']);
    demo_expect(
        ($exchanged['issued_token_type'] ?? null) === DEMO_ACCESS_TOKEN_TYPE,
        sprintf('the exchange says what it issued (got %s)', (string) ($exchanged['issued_token_type'] ?? '')),
    );
    demo_expect(
        ($claims['sub'] ?? null) === DEMO_SERVICE_CLIENT_ID,
        sprintf('the new token is about the service and not about the gateway (got %s)', (string) ($claims['sub'] ?? '')),
    );
    demo_expect(
        ($claims['act']['sub'] ?? null) === DEMO_GATEWAY_CLIENT_ID,
        sprintf('and "act" names the gateway that holds it for it (RFC 8693 §4.1: %s)', (string) ($claims['act']['sub'] ?? '')),
    );
    demo_expect(($claims['client_id'] ?? null) === DEMO_GATEWAY_CLIENT_ID, 'while "client_id" names the client that asked (RFC 9068 §2.2)');
    $verified[] = ['Token exchange', sprintf('sub %s, act %s, client_id %s', DEMO_SERVICE_CLIENT_ID, DEMO_GATEWAY_CLIENT_ID, DEMO_GATEWAY_CLIENT_ID)];

    // the resource server: the token is accepted because it is addressed to this resource
    [$status, $answer] = demo_api_call(DEMO_SERVICE_RESOURCE, $exchanged['access_token']);
    demo_expect($status === 200, sprintf('the resource server accepts the exchanged token (got %d)', $status));
    demo_expect(
        ($answer['sub'] ?? null) === DEMO_SERVICE_CLIENT_ID && ($answer['act']['sub'] ?? null) === DEMO_GATEWAY_CLIENT_ID,
        sprintf('it names the subject and the actor (got %s acting for %s)', (string) ($answer['act']['sub'] ?? ''), (string) ($answer['sub'] ?? '')),
    );
    demo_expect(
        ($answer['aud'] ?? null) === DEMO_SERVICE_RESOURCE,
        sprintf('and the audience it answered for (got %s)', json_encode($answer['aud'] ?? null)),
    );
    $verified[] = ['Resource server', sprintf('%s accepted, sub %s, act %s', DEMO_SERVICE_RESOURCE, DEMO_SERVICE_CLIENT_ID, DEMO_GATEWAY_CLIENT_ID)];

    // RFC 8707 §2: and refuses one addressed somewhere else, without asking the provider anything
    $elsewhere = demo_client_credentials($issuer, $ca, DEMO_SERVICE_CLIENT_ID, $serviceSecret, DEMO_OTHER_RESOURCE);
    [$status] = demo_api_call(DEMO_SERVICE_RESOURCE, $elsewhere['access_token']);
    demo_expect($status === 401, sprintf('a token addressed to %s is refused there (got %d)', DEMO_OTHER_RESOURCE, $status));
    $verified[] = ['Another audience', sprintf('a token for %s is refused with 401', DEMO_OTHER_RESOURCE)];

    io()->table(['Step', 'Verified'], $verified);
    io()->success('A service was reached through a gateway acting for it, and the resource server knew which was which.');
}

/**
 * A token a client holds for itself (RFC 6749 §4.4), addressed to the resource it named.
 *
 * @return array<string, mixed>
 */
function demo_client_credentials(string $issuer, string $ca, string $clientId, string $secret, string $resource): array
{
    $response = http_request('POST', $issuer . '/token', [
        'cafile' => $ca,
        'auth_basic' => $clientId . ':' . $secret,
        'body' => [
            'grant_type' => 'client_credentials',
            'scope' => 'invoices.read',
            'resource' => $resource,
        ],
    ]);
    demo_expect($response->getStatusCode() === 200, sprintf(
        '%s obtains a token for itself (got %d %s)',
        $clientId,
        $response->getStatusCode(),
        $response->getContent(false),
    ));

    return (array) json_decode($response->getContent(false), true, 8, \JSON_THROW_ON_ERROR);
}

/**
 * RFC 8693 §2.1: the token of the service and a token of the gateway, exchanged for one the gateway holds on
 * the service's behalf.
 *
 * @return array<string, mixed>
 */
function demo_token_exchange(string $issuer, string $ca, string $gatewaySecret, string $subjectToken, string $actorToken, string $resource): array
{
    $response = http_request('POST', $issuer . '/token', [
        'cafile' => $ca,
        'auth_basic' => DEMO_GATEWAY_CLIENT_ID . ':' . $gatewaySecret,
        'body' => [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token' => $subjectToken,
            'subject_token_type' => DEMO_ACCESS_TOKEN_TYPE,
            'actor_token' => $actorToken,
            'actor_token_type' => DEMO_ACCESS_TOKEN_TYPE,
            'resource' => $resource,
            'scope' => 'invoices.read',
        ],
    ]);
    demo_expect(
        $response->getStatusCode() === 200,
        sprintf('the gateway exchanges it (got %d %s)', $response->getStatusCode(), $response->getContent(false)),
    );

    return (array) json_decode($response->getContent(false), true, 8, \JSON_THROW_ON_ERROR);
}

/**
 * The route of the demonstration that answers for a resource, called with the token it is handed.
 *
 * @return array{int, array<string, mixed>}
 */
function demo_api_call(string $url, string $accessToken): array
{
    $response = http_request('GET', $url, [
        'verify_peer' => false,
        'verify_host' => false,
        'headers' => [
            'Authorization' => 'Bearer ' . $accessToken,
        ],
    ]);
    $decoded = json_decode($response->getContent(false), true);

    return [$response->getStatusCode(), is_array($decoded) ? $decoded : []];
}

/**
 * The claims of a self-contained access token (RFC 9068 §2.2), read to assert on them; nothing is verified
 * here, the walk being the client and not a resource server.
 *
 * @return array<string, mixed>
 */
function demo_claims_of(mixed $accessToken): array
{
    $parts = explode('.', (string) $accessToken);
    demo_expect(count($parts) === 3, 'the access token is a compact JWS (RFC 9068 §2.1)');
    $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true, 8);

    return is_array($payload) ? $payload : [];
}

/**
 * The client of the two backchannel walks, run under the autoloader of the monorepo, which castor does not
 * load, and the two clients it is: one per delivery mode, because a client registers one and one only
 * (CIBA Core §4).
 */
const DEMO_CIBA_CLIENT = 'tests/demo/ciba-client.php';

const DEMO_CIBA_CLIENTS = [
    'poll' => [
        'client' => 'demo-ciba-poll',
        'secret' => 'DEMO_CIBA_POLL_SECRET',
        'asks' => 'the client asks the token endpoint again until the user has answered',
    ],
    'ping' => [
        'client' => 'demo-ciba-ping',
        'secret' => 'DEMO_CIBA_PING_SECRET',
        'asks' => 'the provider calls the client back, and it asks once',
    ],
];

/**
 * Where the client of the "ping" walk listens, as the worker of the stack reaches it: the port is registered
 * with that client (apps/op/config/packages/beffroi.yaml), so it is fixed rather than drawn.
 */
const DEMO_CIBA_NOTIFICATION_PORT = 8004;

/**
 * CIBA Core §7.1: what the client writes for the user to read on the device where they answer, which is what
 * ties the thing they are looking at to the thing that asked.
 */
const DEMO_CIBA_BINDING_MESSAGE = 'Invoice 4711';

/**
 * The first part of issue #299: a client asks for a user it names and waits, and that user answers on a
 * device of their own. Both delivery modes, one after the other.
 *
 * What it looks at is the part no specification writes for us. The request reaches the user as a line on a
 * page they went to themselves, found by who they are and never by a link they were sent (BCP 10027 §5.2),
 * and it carries the message the client wrote, so that somebody who started nothing sees a message they do
 * not recognise and refuses. The two modes differ in one thing and the walk measures exactly that: how many
 * times the client had to ask.
 *
 * @param string $subject what a "login_hint" names for this tenant: the subject this provider issued, which is
 *                        the reading the application wired (beffroi.backchannel_authentication.login_hint) and
 *                        what CIBA Core §15 asks for, an identifier that says nothing outside this provider
 * @param array<string, string> $secrets apps/op/.env.local, by the name of the variable each client's is under
 */
function demo_ciba_check(string $issuer, string $password, string $ca, string $subject, array $secrets, bool $byHand = false): void
{
    io()->section($byHand ? 'A backchannel client, and you are the other device' : 'A backchannel client, and the user who answers it elsewhere');
    $verified = [];
    // by hand there is one delivery mode and not two: what is being shown is the other device, which is a
    // person, and asking them to do it twice shows nothing the first one did not
    $clients = $byHand
        ? [
            'poll' => DEMO_CIBA_CLIENTS['poll'],
        ] : DEMO_CIBA_CLIENTS;

    foreach ($clients as $mode => $registration) {
        $cli = new Process(
            [
                'php',
                DEMO_CIBA_CLIENT,
                '--issuer=' . $issuer,
                '--client-id=' . $registration['client'],
                '--secret=' . $secrets[$registration['secret']],
                '--mode=' . $mode,
                '--login-hint=' . $subject,
                '--binding-message=' . DEMO_CIBA_BINDING_MESSAGE,
                '--notification-port=' . DEMO_CIBA_NOTIFICATION_PORT,
                '--cafile=' . $ca,
                '--timeout=' . ($byHand ? DEMO_CIBA_BY_HAND_TIMEOUT : 120),
            ],
            timeout: $byHand ? DEMO_CIBA_BY_HAND_TIMEOUT + 60 : 180.0,
        );
        $cli->start();

        try {
            // CIBA Core §7.3: the client is handed an identifier, a lifetime and an interval, and no token
            $asked = demo_cli_step($cli, 'backchannel_authentication');
            demo_expect(
                ($asked['mode'] ?? null) === $mode && is_int($asked['expires_in'] ?? null) && $asked['expires_in'] > 0,
                sprintf('%s: the request is accepted and lives for %s s', $mode, (string) ($asked['expires_in'] ?? '?')),
            );
            demo_expect(
                is_int($asked['interval'] ?? null) && $asked['interval'] > 0,
                sprintf('%s: the client is told how often it may ask (%s s)', $mode, (string) ($asked['interval'] ?? '?')),
            );

            // the other device: the browser of a user who holds nothing of the request and finds it by who
            // they are. By hand, that browser is yours and nothing here answers for you.
            if ($byHand) {
                demo_ciba_wait_for_you($issuer, $asked);
            } else {
                demo_ciba_approve($issuer, $password, $ca, $registration['client']);
            }

            if ($mode === 'ping') {
                // CIBA Core §10.2: the provider posts the identifier to the endpoint that client registered,
                // with the token that client gave it, and carries no token there
                $notified = demo_cli_step($cli, 'notification');
                demo_expect(
                    ($notified['auth_req_id_matches'] ?? false) === true && ($notified['token_matches'] ?? false) === true,
                    'ping: the provider calls the client back with the request it is waiting on and the token it gave (CIBA Core §10.2)',
                );
                $verified[] = ['ping: notification', sprintf('called back after %s s, on the token the client drew', (string) ($notified['waited'] ?? '?'))];
            }

            $tokens = demo_cli_step($cli, 'tokens', $byHand ? (float) DEMO_CIBA_BY_HAND_TIMEOUT : 150.0);
            demo_expect(($tokens['token_type'] ?? null) === 'Bearer', sprintf(
                '%s: the client holds a bearer token (got %s)',
                $mode,
                (string) ($tokens['token_type'] ?? ''),
            ));
            demo_expect(($tokens['sub'] ?? null) !== null, sprintf('%s: the token names the user who approved it', $mode));
            demo_expect(($tokens['id_token'] ?? false) === true, sprintf(
                '%s: and an ID token, "openid" being required of every request of this flow (CIBA Core §7.1)',
                $mode,
            ));
            $polls = is_int($tokens['polls'] ?? null) ? $tokens['polls'] : 0;
            if ($mode === 'poll') {
                demo_expect($polls >= 2, sprintf('poll: the client was told to wait before it was answered (%d requests)', $polls));
            } else {
                demo_expect($polls === 1, sprintf('ping: the client asked once, when it was told to (%d request)', $polls));
            }
            $verified[] = [
                sprintf('%s: tokens', $mode),
                sprintf('%s, "%s", after %d request(s) to the token endpoint', $registration['asks'], (string) ($tokens['scope'] ?? '?'), $polls),
            ];

            $cli->wait();
            demo_expect($cli->isSuccessful(), sprintf('%s: the client ends without an error (exit %s)', $mode, (string) $cli->getExitCode()));
        } finally {
            if ($cli->isRunning()) {
                $cli->stop();
            }
        }
    }

    io()->table(['Step', 'Verified'], $verified);
    io()->success(
        $byHand
            ? 'A request made by somebody else reached you, and the client was served the moment you allowed it.'
            : 'A request made by somebody else was found, read and allowed by the user it named, in both delivery modes.',
    );
}

/**
 * How long a run that waits for a person gives them, in seconds: the lifetime of a backchannel request is
 * five minutes on this stack, and there is no point waiting past the thing they would be answering.
 */
const DEMO_CIBA_BY_HAND_TIMEOUT = 300;

/**
 * The other device, when it is yours. Nothing here answers the request: the run says what is on its way to
 * you and where to answer it, and then waits for the client to be handed its token, which only happens
 * once you have allowed it.
 *
 * This is what the rest of this task is not: every other walk plays both sides, which is what makes it a
 * test, and a flow whose whole point is that somebody is asked cannot be shown by a program that answers
 * itself.
 *
 * @param array<string, mixed> $asked what the backchannel authentication endpoint answered
 */
function demo_ciba_wait_for_you(string $issuer, array $asked): void
{
    $lifetime = is_int($asked['expires_in'] ?? null) ? $asked['expires_in'] : DEMO_CIBA_BY_HAND_TIMEOUT;
    io()->newLine();
    io()->block(
        [
            sprintf('A client has asked for "%s", and wrote: "%s".', DEV_USERNAME, DEMO_CIBA_BINDING_MESSAGE),
            '',
            sprintf(
                'Every browser of that user this provider can reach has been sent a notification (%s/account/notifications lists them). It says that something is waiting and nothing else: no identifier of this request and no link that answers it (BCP 10027 §5.2).',
                $issuer,
            ),
            '',
            sprintf('Open %s/account/approvals, read what is asked, and allow or refuse it. Nothing here will answer for you.', $issuer),
            '',
            sprintf('The client is polling and will be handed its token the moment you allow it. You have %d s before the request expires.', $lifetime),
        ],
        'YOUR TURN',
        'fg=black;bg=yellow',
        ' ',
        true,
    );
}

/**
 * The other device of the backchannel flow (CIBA Core §10.1, BCP 10027 §5.2): a browser that holds nothing of
 * the request, signs its user in, finds what is waiting for them and allows it.
 *
 * There is no code to type here and no link that carries the request, which is what tells this page from the
 * one of the device grant: what reaches a user from outside says that something is waiting, and what they
 * find at the provider is found by who they are.
 */
function demo_ciba_approve(string $issuer, string $password, string $ca, string $clientId, ?string $bindingMessage = null): void
{
    $bindingMessage ??= DEMO_CIBA_BINDING_MESSAGE;
    $cookies = [];
    $page = $issuer . '/account/approvals';

    // no session yet, so the page asks for a login and brings the browser back to it (LoginTarget)
    $approvals = demo_browser_sign_in($cookies, $issuer, $password, $ca, $page);
    demo_expect(
        preg_match('/data-approval="([^"]+)"/', $approvals) === 1,
        'the page of what is waiting has something on it',
    );
    demo_expect(
        preg_match('/data-binding-message="([^"]*)"/', $approvals, $binding) === 1 && $binding[1] === $bindingMessage,
        sprintf('the page shows the message the client wrote, as it was sent (CIBA Core §7.1: "%s")', $binding[1] ?? ''),
    );
    demo_expect(
        str_contains($approvals, $clientId) || preg_match('/data-origin="([^"]*)"/', $approvals) === 1,
        'it names where the request came from (BCP 10027 §5.2)',
    );
    demo_expect(
        preg_match_all('/data-scope="([^"]+)"/', $approvals, $scopes) >= 1 && in_array('openid', $scopes[1], true),
        sprintf('it names every scope of the request (%s)', implode(' ', $scopes[1] ?? [])),
    );
    demo_expect(str_contains($approvals, 'data-warning="unexpected"'), 'and tells whoever started nothing to refuse (BCP 10027 §5.2)');

    // allow, with the token of the page and the handle of the request it named
    $fields = demo_form_fields($approvals);
    [$status, , $answered] = demo_request($cookies, $ca, 'POST', $page, [
        ...$fields,
        'answer' => 'allow',
    ]);
    demo_expect($status === 200, sprintf('the answer is accepted (got %d)', $status));
    demo_expect(
        str_contains($answered, 'data-answer="approved"'),
        'and the page says the request was allowed, there being nothing left to do in this browser (CIBA Core §10.1)',
    );
}

/**
 * The signing client of the assertion walk, and the issuer it signs for: the "iss" its assertions carry, the
 * subject the development user is known by over there, and one nobody resolves, which is what the walk gets
 * the same refusal for. They are what "castor provision" registered and linked (.castor/stack/provision.php).
 */
const DEMO_ASSERTION_CLIENT = 'tests/demo/assertion-client.php';

const DEMO_ASSERTION_CLIENT_ID = 'demo-assertion';

const DEMO_ASSERTION_ISSUER = 'https://issuer.demo.localhost';

const DEMO_ASSERTION_SUBJECT = 'alice@issuer.demo.localhost';

const DEMO_ASSERTION_UNKNOWN_SUBJECT = 'nobody@issuer.demo.localhost';

/**
 * Where "castor provision" left the private half of the key of that issuer.
 */
const DEMO_ASSERTION_JWKS = 'var/demo/demo-issuer.jwks.json';

/**
 * The second part of issue #299: an assertion signed by an issuer the tenant trusts, exchanged for an access
 * token for the user it names (RFC 7523 §2.1).
 *
 * It is one paragraph of a specification and a whole trust decision, so the walk plays the decision and not
 * only the grant: the assertion that works, the same one again, one about somebody no linked identity
 * resolves, and one asking for an authentication this grant performs for nobody. The three refusals say the
 * same thing, which is what the walk checks last: what a tenant trusts is not something an error teaches.
 */
function demo_assertion_check(string $issuer, string $ca, string $secret): void
{
    io()->section('An assertion of a trusted issuer, exchanged for a token');
    $verified = [];

    $run = demo_assertion_client([
        'token_endpoint' => $issuer . '/token',
        'cafile' => $ca,
        'client_id' => DEMO_ASSERTION_CLIENT_ID,
        'client_secret' => $secret,
        'trusted_issuer' => DEMO_ASSERTION_ISSUER,
        // RFC 7523 §3, FAPI 2.0 §5.3.2.1: the issuer identifier of the provider is the one name an assertion
        // may be addressed to (issue #267)
        'audience' => $issuer,
        'subject' => DEMO_ASSERTION_SUBJECT,
        'unknown_subject' => DEMO_ASSERTION_UNKNOWN_SUBJECT,
        'scope' => 'invoices.read',
        'resource' => DEMO_SERVICE_RESOURCE,
        'jwks_file' => DEMO_ASSERTION_JWKS,
    ]);

    $granted = is_array($run['granted'] ?? null) ? $run['granted'] : [];
    demo_expect(($granted['status'] ?? 0) === 200, sprintf(
        'the assertion is exchanged for a token (got %s %s)',
        (string) ($granted['status'] ?? '?'),
        (string) ($granted['error_description'] ?? ''),
    ));
    $claims = is_array($granted['claims'] ?? null) ? $granted['claims'] : [];
    demo_expect(
        is_string($claims['sub'] ?? null) && $claims['sub'] !== DEMO_ASSERTION_SUBJECT,
        sprintf(
            'the token names the user of this tenant and not the subject the issuer gave (got %s, the issuer said %s)',
            (string) ($claims['sub'] ?? ''),
            DEMO_ASSERTION_SUBJECT,
        ),
    );
    demo_expect(($claims['aud'] ?? null) === DEMO_SERVICE_RESOURCE, sprintf(
        'it is addressed to the resource the request named (RFC 8707 §2, got %s)',
        json_encode($claims['aud'] ?? null),
    ));
    demo_expect(($granted['id_token'] ?? false) === false, 'and carries no ID token: this grant authenticated nobody (OIDC Core §2)');
    demo_expect(! isset($claims['sid'], $claims['auth_time']), 'nor anything about a sign-in that happened somewhere else');
    $verified[] = [
        'The assertion',
        sprintf('sub %s for %s, "%s"', (string) ($claims['sub'] ?? '?'), DEMO_SERVICE_RESOURCE, (string) ($granted['scope'] ?? '?')),
    ];

    // The three refusals, each one a rule of the grant, and all three the same words: an error response of
    // this grant says that the assertion was not accepted and nothing else.
    $refusals = [];
    foreach (['replayed', 'unknown_subject', 'openid_refused'] as $attempt) {
        $refused = is_array($run[$attempt] ?? null) ? $run[$attempt] : [];
        demo_expect(($refused['status'] ?? 0) === 400, sprintf('%s: refused (got %s)', $attempt, (string) ($refused['status'] ?? '?')));
        $refusals[$attempt] = (string) ($refused['error'] ?? '');
        $verified[] = [$attempt, sprintf('%s, "%s"', (string) $refused['status'], $refusals[$attempt])];
    }
    demo_expect($refusals['replayed'] === 'invalid_grant', sprintf('an assertion is exchanged once (RFC 7523 §3, got %s)', $refusals['replayed']));
    demo_expect(
        $refusals['unknown_subject'] === $refusals['replayed'],
        sprintf(
            'an assertion about somebody no identity resolves is refused the same way as a replay, so neither says which (decision 0002: %s against %s)',
            $refusals['unknown_subject'],
            $refusals['replayed'],
        ),
    );
    demo_expect($refusals['openid_refused'] === 'invalid_scope', sprintf('and "openid" is refused rather than dropped (got %s)', $refusals['openid_refused']));

    io()->table(['Step', 'Verified'], $verified);
    io()->success('A third party named a user of this tenant, once, and only the one it is trusted for.');
}

/**
 * The assertion client of tests/demo/, run under the autoloader of the monorepo, which castor does not load.
 *
 * @param array<string, string> $input
 * @return array<string, mixed>
 */
function demo_assertion_client(array $input): array
{
    $process = new Process(['php', DEMO_ASSERTION_CLIENT], input: (string) json_encode($input));
    $process->setTimeout(120.0);
    $process->run();
    demo_expect($process->isSuccessful(), sprintf('the assertion client ran (exit %d): %s', $process->getExitCode() ?? -1, trim($process->getErrorOutput())));
    $run = json_decode($process->getOutput(), true);
    demo_expect(is_array($run), 'the assertion client answered a JSON object: ' . $process->getOutput());

    return $run;
}

/**
 * The client of the rich authorization request walk, the one type of detail this deployment wires
 * (App\AuthorizationDetails\InvoicePaymentType) and a type it does not, which is what the refusal is asked
 * for. The detail says what may be done, to what, and how much, which is the whole difference with a scope.
 */
const DEMO_RAR_CLIENT_ID = 'demo-rar';

const DEMO_RAR_INVOICE = 'INV-4711';

const DEMO_RAR_DETAILS = [
    [
        'type' => 'invoice_payment',
        'locations' => [DEMO_SERVICE_RESOURCE],
        'actions' => ['read', 'pay'],
        'identifier' => DEMO_RAR_INVOICE,
        'maximumAmount' => [
            'currency' => 'EUR',
            'amount' => '45.00',
        ],
    ],
];

/**
 * The same detail as the type built it, which is what comes back everywhere it is rendered: the members in the
 * order that type chose, and its lists sorted, where the request above wrote the two actions the other way
 * round.
 *
 * It is not a detail of this walk. Two requests that ask for the same thing have to be the same detail whatever
 * order they were written in, or a consent given for one would not cover the other
 * (AuthorizationDetail::equals()), so what a token carries is what the type made of the request and never the
 * request as it arrived.
 */
const DEMO_RAR_GRANTED = [
    [
        'type' => 'invoice_payment',
        'locations' => [DEMO_SERVICE_RESOURCE],
        'actions' => ['pay', 'read'],
        'identifier' => DEMO_RAR_INVOICE,
        'maximumAmount' => [
            'currency' => 'EUR',
            'amount' => '45.00',
        ],
    ],
];

const DEMO_RAR_UNWIRED_DETAILS = [
    [
        'type' => 'account_information',
        'actions' => ['read'],
    ],
];

/**
 * The third part of issue #299: a request that asks for what it may do, to what and how much (RFC 9396).
 *
 * A scope is a kind of thing and a detail is a thing, so a detail is the one part of an authorization a user
 * has to be able to read before agreeing to it: the walk therefore reads the consent page before answering
 * it, and only then follows the detail into the access token (§7) and into the introspection (§9), which is
 * where a resource server finds it. Then a type nobody wired, refused at the endpoint the browser is on.
 */
function demo_rar_check(string $issuer, string $password, string $ca, string $secret): void
{
    io()->section('A request that asks for what it may do, to what and how much');
    $verified = [];
    $cookies = [];
    $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $redirectUri = DEMO_URL . '/c/rar/callback';

    // RFC 9396 §2: the parameter is the JSON of the array, in the query of the browser like every other
    $authorization = demo_rar_authorization($issuer, $verifier, $redirectUri, DEMO_RAR_DETAILS);
    $shown = null;
    [$status, $location] = demo_resume(
        $cookies,
        $ca,
        $issuer,
        demo_login($cookies, $issuer, $password, $ca, $authorization),
        static function (string $page) use (&$shown): void {
            $shown = $page;
        },
    );
    demo_expect(
        is_string($shown),
        sprintf(
            'the provider shows the consent the request asked for, a detail being what a user has to agree to (RFC 9396 §5; it answered %d %s)',
            $status,
            $location,
        ),
    );
    $page = (string) $shown;
    demo_expect(
        preg_match('/data-authorization-detail="([^"]+)"/', $page, $rendered) === 1 && $rendered[1] === 'invoice_payment',
        sprintf('the consent page says the request carries a detail, and of which type (got "%s")', $rendered[1] ?? ''),
    );
    demo_expect(
        str_contains($page, DEMO_RAR_INVOICE) && str_contains($page, '45.00') && str_contains($page, 'EUR'),
        'and says what it asks for in words: the invoice, and the most that may be moved (the message of the type, apps/op/translations)',
    );
    $verified[] = ['Consent', sprintf('the detail rendered as "%s", invoice %s, at most 45.00 EUR', $rendered[1], DEMO_RAR_INVOICE)];

    // the code, then the token it is spent for
    demo_expect(
        $status === 302 && str_starts_with($location, $redirectUri . '?'),
        sprintf('the provider answers the request with a redirection to the client (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(isset($callback['code']), 'which carries a code');
    $tokens = demo_exchange_code($issuer, $ca, DEMO_RAR_CLIENT_ID, $secret, (string) $callback['code'], $redirectUri, $verifier);
    $claims = demo_claims_of($tokens['access_token'] ?? '');
    demo_expect(
        isset($claims['authorization_details']) && $claims['authorization_details'] === DEMO_RAR_GRANTED,
        sprintf('the access token carries the detail, as the type built it (RFC 9396 §7: %s)', json_encode($claims['authorization_details'] ?? null)),
    );
    demo_expect(
        DEMO_RAR_GRANTED[0]['actions'] !== DEMO_RAR_DETAILS[0]['actions'],
        'and in the order of its type rather than of the request, which is what lets one consent cover two requests that ask for the same thing',
    );
    demo_expect(
        ($tokens['authorization_details'] ?? null) === DEMO_RAR_GRANTED,
        sprintf('and the token response says what it granted (RFC 9396 §7: %s)', json_encode($tokens['authorization_details'] ?? null)),
    );
    $verified[] = ['Access token', sprintf('authorization_details of %d object(s), in the order of its type', count(DEMO_RAR_GRANTED))];
    $verified[] = ['The token response', sprintf('says what it granted, %d object(s)', count(DEMO_RAR_GRANTED))];

    // RFC 9396 §9: where a resource server that does not read the token itself finds the same thing
    $described = demo_rar_introspection($issuer, $ca, $secret, (string) ($tokens['access_token'] ?? ''));
    demo_expect(
        ($described['authorization_details'] ?? null) === DEMO_RAR_GRANTED,
        sprintf(
            'the introspection renders the detail to the client the token was issued to (§9: %s)',
            json_encode($described['authorization_details'] ?? null),
        ),
    );
    $verified[] = ['Introspection', 'the same detail, rendered for a resource server that asks'];

    // RFC 9396 §11: what a client may ask for is the closed list of its registration, and a type nobody
    // wired is a detail nothing could describe or show
    $refused = [];
    [$status, $location] = demo_request(
        $refused,
        $ca,
        'GET',
        demo_rar_authorization($issuer, $verifier, $redirectUri, DEMO_RAR_UNWIRED_DETAILS),
    );
    demo_expect(
        $status === 302 && str_starts_with($location, $redirectUri . '?'),
        sprintf('a request naming a type nobody wired is answered to the client and not on a page (got %d %s)', $status, $location),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $error);
    demo_expect(
        ($error['error'] ?? null) === 'invalid_authorization_details',
        sprintf('with the error RFC 9396 §5 names (got %s)', (string) ($error['error'] ?? '')),
    );
    demo_expect(
        ! str_contains((string) ($error['error_description'] ?? ''), 'account_information'),
        'and a description that names neither the type asked for nor what the client registered',
    );
    $verified[] = ['A type nobody wired', sprintf('%s, without naming it', (string) $error['error'])];

    io()->table(['Step', 'Verified'], $verified);
    io()->success('A user read what a request asked to do to one invoice, agreed to it, and it travelled into the token.');
}

/**
 * RFC 9396 §2: the authorization request of that client, carrying the JSON of the details it asks for.
 *
 * @param list<array<string, mixed>> $details
 */
function demo_rar_authorization(string $issuer, string $verifier, string $redirectUri, array $details): string
{
    return $issuer
    . '/authorize?'
    . http_build_query([
        'response_type' => 'code',
        'client_id' => DEMO_RAR_CLIENT_ID,
        'redirect_uri' => $redirectUri,
        'scope' => 'openid profile',
        'state' => bin2hex(random_bytes(16)),
        'nonce' => bin2hex(random_bytes(16)),
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
        'code_challenge_method' => 'S256',
        // OIDC Core §3.1.2.1: the page is what this walk reads, and a consent already in force would answer
        // the request without showing one, so it is asked for rather than hoped for
        'prompt' => 'consent',
        'authorization_details' => json_encode($details, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES),
    ]);
}

/**
 * A code spent by the client it was issued to, with the verifier of its challenge when it sent one
 * (RFC 6749 §4.1.3, RFC 7636 §4.5): the one exchange of the laboratory, whatever the walk asks for it,
 * because a client that registered itself spends a code exactly as a declared one does.
 *
 * @return array<string, mixed>
 */
function demo_exchange_code(
    string $issuer,
    string $ca,
    string $clientId,
    string $secret,
    string $code,
    string $redirectUri,
    ?string $verifier = null,
): array {
    $body = [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $redirectUri,
    ];
    if ($verifier !== null) {
        $body['code_verifier'] = $verifier;
    }
    $response = http_request('POST', $issuer . '/token', [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_basic' => $clientId . ':' . $secret,
        'body' => $body,
    ]);
    // What the endpoint answered belongs in the message only when there is something wrong with it: a token
    // response printed on success buries the assertions that read it.
    $exchanged = $response->getStatusCode() === 200;
    demo_expect($exchanged, sprintf(
        'the code is exchanged%s',
        $exchanged ? '' : sprintf(' (got %d %s)', $response->getStatusCode(), $response->getContent(false)),
    ));

    return (array) json_decode($response->getContent(false), true, 8, \JSON_THROW_ON_ERROR);
}

/**
 * RFC 7662 §2.2, RFC 9396 §9: the token described to the client it was issued to.
 *
 * @return array<string, mixed>
 */
function demo_rar_introspection(string $issuer, string $ca, string $secret, string $accessToken): array
{
    $response = http_request('POST', $issuer . '/introspect', [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_basic' => DEMO_RAR_CLIENT_ID . ':' . $secret,
        'body' => [
            'token' => $accessToken,
            'token_type_hint' => 'access_token',
        ],
    ]);
    $described = (array) json_decode($response->getContent(false), true);
    demo_expect(($described['active'] ?? null) === true, sprintf('the introspection describes the token (got %d)', $response->getStatusCode()));

    return $described;
}

/**
 * The native client of the loopback walk, and the two runs it makes: the port is what varies between them,
 * and it is the one thing of the redirection this provider does not compare byte for byte (RFC 8252 §7.3).
 */
const DEMO_NATIVE_CLI = 'tests/demo/native-cli.php';

const DEMO_NATIVE_CLIENT_ID = 'demo-native';

/**
 * RFC 8252 §8.3: the loopback interface named by a name rather than by its IP literal, which a native client
 * must not be sent back to, whatever resolves it on the machine of the user.
 */
const DEMO_NATIVE_REFUSED_REDIRECT = 'http://localhost/callback';

/**
 * The fourth part of issue #299: a program on the machine of its user, receiving the authorization response on
 * the loopback interface (RFC 8252 §7.3).
 *
 * The walk is the run twice, because one run proves nothing: what is claimed is that the port varies and the
 * provider serves it, so two runs on two ports are what says so. Then the exception is shown to be an
 * exception and not a hole: a redirection on a name rather than on the IP literal is refused, the path is
 * compared as it is for every other client, and the code is worth nothing without the verifier of its
 * challenge, this client holding no secret at all.
 */
function demo_native_check(string $issuer, string $password, string $ca): void
{
    io()->section('A native client on the loopback interface');
    $verified = [];
    $ports = [];

    foreach ([1, 2] as $run) {
        $cli = new Process(
            ['php', DEMO_NATIVE_CLI, '--issuer=' . $issuer, '--client-id=' . DEMO_NATIVE_CLIENT_ID, '--cafile=' . $ca, '--timeout=120'],
            timeout: 180.0,
        );
        $cli->start();

        try {
            // the operating system hands it a port, and the redirection it gives the provider carries that
            // port and nothing else of its own
            $listening = demo_cli_step($cli, 'listening');
            $port = is_int($listening['port'] ?? null) ? $listening['port'] : 0;
            demo_expect($port > 0, sprintf('run %d: the client is listening on a port it was given (got %s)', $run, (string) $port));
            demo_expect(
                ($listening['redirect_uri'] ?? null) === sprintf('http://127.0.0.1:%d/callback', $port),
                sprintf(
                    'run %d: and names it by the IP literal it registered, with the port it was given (got %s)',
                    $run,
                    (string) ($listening['redirect_uri'] ?? ''),
                ),
            );
            $ports[] = $port;

            // the browser of the user: the provider serves the request, the login and the consent, and sends
            // the browser back to the port of this run
            $cookies = [];
            [$status, $location] = demo_resume(
                $cookies,
                $ca,
                $issuer,
                demo_login($cookies, $issuer, $password, $ca, (string) $listening['authorization_url']),
            );
            demo_expect(
                $status === 302 && str_starts_with($location, $listening['redirect_uri'] . '?'),
                sprintf('run %d: the provider sends the browser back to the port of this run (got %d %s)', $run, $status, $location),
            );
            // the browser goes there, which is what hands the code to the program waiting behind it
            demo_request($cookies, $ca, 'GET', $location);

            $redirected = demo_cli_step($cli, 'redirected');
            demo_expect(
                ($redirected['state_matches'] ?? false) === true && ($redirected['iss_matches'] ?? false) === true,
                sprintf('run %d: the client recognises its own flow, by its state and by the issuer (RFC 9207 §2.4)', $run),
            );
            $tokens = demo_cli_step($cli, 'tokens');
            demo_expect(($tokens['token_type'] ?? null) === 'Bearer', sprintf(
                'run %d: it holds a bearer token (got %s)',
                $run,
                (string) ($tokens['token_type'] ?? ''),
            ));
            demo_expect(($tokens['sub'] ?? null) !== null && ($tokens['id_token'] ?? false) === true, sprintf(
                'run %d: the token names the user, and an ID token came with it',
                $run,
            ));
            $verified[] = [sprintf('Run %d', $run), sprintf('port %d, "%s", signed in', $port, (string) ($tokens['scope'] ?? '?'))];

            $cli->wait();
            demo_expect($cli->isSuccessful(), sprintf('run %d: the client ends without an error (exit %s)', $run, (string) $cli->getExitCode()));
        } finally {
            if ($cli->isRunning()) {
                $cli->stop();
            }
        }
    }

    demo_expect(
        count($ports) === 2 && $ports[0] !== $ports[1],
        sprintf('the two runs were given two different ports, and both were served (%s)', implode(' and ', $ports)),
    );
    $verified[] = ['The exception', sprintf('two ports served on one registration, %s', implode(' and ', $ports))];

    // RFC 8252 §8.3: the exception is the port and nothing else. A name is resolved by whatever answers for
    // it on the machine of the user, and a redirection carrying a code is not a thing to hand to that.
    $cookies = [];
    [$status, , $page] = demo_request(
        $cookies,
        $ca,
        'GET',
        $issuer . '/authorize?'
            . http_build_query([
                'response_type' => 'code',
                'client_id' => DEMO_NATIVE_CLIENT_ID,
                'redirect_uri' => DEMO_NATIVE_REFUSED_REDIRECT,
                'scope' => 'openid profile',
                'state' => bin2hex(random_bytes(16)),
                'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', 'whatever', true)), '+/', '-_'), '='),
                'code_challenge_method' => 'S256',
            ]),
    );
    demo_expect(
        $status === 400,
        sprintf('a redirection on a name rather than on the IP literal is refused on a page, there being nowhere to send the browser (got %d)', $status),
    );
    demo_expect(
        ! str_contains($page, DEMO_NATIVE_REFUSED_REDIRECT),
        'and the page does not echo the URI it was given',
    );
    $verified[] = ['A name, not the literal', sprintf('%s refused with %d', DEMO_NATIVE_REFUSED_REDIRECT, $status)];

    io()->table(['Step', 'Verified'], $verified);
    io()->success('A program on somebody\'s machine signed its user in twice, on two ports, against one registration.');
}

const DEMO_PUSH_SERVICE = 'tests/demo/push-service.php';

const DEMO_PUSH_BROWSER = 'tests/demo/push-browser.php';

/**
 * Where the push service of the walk listens, and the name the containers of the stack reach it by: the
 * same ".localhost" name the second instance of the demonstration and the listener of the ping client are
 * reached by, since from inside a container "localhost" is the container (compose.yaml, extra_hosts).
 */
const DEMO_PUSH_PORT = 8005;

const DEMO_PUSH_HOST = 'demo.localhost';

/**
 * The certificate that push service answers with, and where the container that pushes is made to trust
 * it. Under var/, which the repository ignores, beside the key material of the other clients of the lab:
 * an endpoint of a subscription is an absolute HTTPS URL (RFC 8030 §2), so there is no plain listener to
 * fall back on as the ping client has.
 */
const DEMO_PUSH_CERTIFICATE = 'var/demo/push-service.crt';

const DEMO_PUSH_KEY = 'var/demo/push-service.key';

const DEMO_PUSH_TRUSTED_CERTIFICATE = '/usr/local/share/ca-certificates/beffroi-lab-push.crt';

/**
 * The user this walk asks for, and never the development user. What it measures of a push service that
 * answers 503 is the notifications lane coming back, and the lane comes back only when **no** browser at
 * all was reached (architecture §5.6): a browser somebody enrolled by hand on the account they use would
 * answer that question instead of it. So the walk holds a user whose only browser is the one it draws, and
 * anybody looking at this flow in a browser of their own is left alone.
 *
 * Created on the first run and kept, with the password of the development user, which is the one secret a
 * development stack has for a person.
 */
const DEMO_PUSH_USERNAME = 'push-walk';

/**
 * What the user calls this browser of theirs on the page that subscribes it.
 */
const DEMO_PUSH_LABEL = 'The browser of the push walk';

/**
 * The "sub" of every signed request this provider sends a push service (RFC 8292 §2.1), as the
 * application wires it (apps/op/config/packages/beffroi.yaml, beffroi.web_push.subject).
 */
const DEMO_PUSH_SUBJECT = 'mailto:operator@op.localhost';

/**
 * The seconds the notifications lane waits before the first retry (NotificationRetryPolicy): the lower
 * bound of what a walk may read between two attempts at the same message.
 */
const DEMO_PUSH_FIRST_RETRY = 2;

/**
 * Issue #311: the first notification this provider has ever had decrypted. The channel of issue #265 was
 * verified against a mock and against nothing else, which is a channel nobody has sent through, and it is
 * the argument issue #299 made about the grants no client of the lab played.
 *
 * Three things stand where a third party stands. A push service that keeps what it was POSTed and answers
 * what it is told to (tests/demo/push-service.php), over HTTPS because nothing else is a subscription
 * (RFC 8030 §2), trusted by the container that pushes for the time of the walk. A browser that draws the
 * pair and the secret a subscription is made of and holds the private half (tests/demo/push-browser.php),
 * which is all a browser is on this path. And the walk, which asks for an authorization for "alice" and
 * then reads what the push service was handed: the signature of RFC 8292, the payload of RFC 8291, and
 * the one rule the channel exists to keep, that nothing anywhere in it names the request or answers one
 * (BCP 10027 §5.2).
 *
 * Then the two answers a push service gives that are not a yes: 503, and the message coming back under
 * the patience of the notifications lane; 410, and the row taken out rather than tried for ever.
 *
 * @param array<string, string> $secrets apps/op/.env.local, by the name of the variable each client's is under
 */
function demo_push_check(string $issuer, string $password, string $ca, array $secrets): void
{
    io()->section('A push service of the lab, and a notification opened');
    $verified = [];
    $registration = DEMO_CIBA_CLIENTS['poll'];
    $subject = demo_push_user($password);
    $metadata = demo_metadata($issuer . '/.well-known/openid-configuration', $ca);
    $backchannel = is_string($metadata['backchannel_authentication_endpoint'] ?? null) ? $metadata['backchannel_authentication_endpoint'] : '';
    demo_expect($backchannel !== '', 'the provider announces a backchannel authentication endpoint (CIBA Core §4)');
    [$certificate, $privateKey] = demo_push_certificate();
    demo_push_trust($certificate);
    // a fresh path per run, as a push service hands a browser one: a row of a previous run is then not
    // what this one measures
    $endpoint = sprintf('https://%s:%d/push/%s', DEMO_PUSH_HOST, DEMO_PUSH_PORT, bin2hex(random_bytes(8)));
    [$service, $told] = demo_push_service($certificate, $privateKey);

    try {
        // the browser: its own key pair, and the secret that makes holding the public half not enough
        $browser = demo_push_browser([
            'action' => 'draw',
        ]);
        demo_expect(
            is_string($browser['p256dh'] ?? null) && is_string($browser['auth'] ?? null),
            'the browser drew the key pair and the authentication secret of a subscription (RFC 8291 §3.1)',
        );

        // the page of the account hands out the application server key, and takes back the endpoint
        $cookies = [];
        $applicationServerKey = demo_push_subscribe($cookies, $issuer, $password, $ca, $browser, $endpoint);
        $verified[] = ['Subscribed', sprintf('under the application server key %s… of the tenant', substr($applicationServerKey, 0, 12))];

        // a client asks for something only that user can answer, and this is what has to reach them
        $asked = demo_push_backchannel($backchannel, $ca, $registration['client'], $secrets[$registration['secret']], $subject);
        $push = demo_cli_step($service, 'push', 60.0);
        demo_expect(
            ($push['method'] ?? null) === 'POST' && str_ends_with((string) ($push['path'] ?? ''), substr($endpoint, strrpos($endpoint, '/') + 1)),
            sprintf('the provider posted to the endpoint the browser gave, and to no other (%s)', (string) ($push['path'] ?? '')),
        );
        demo_expect(
            preg_match('/^content-encoding:\s*aes128gcm/im', (string) ($push['head'] ?? '')) === 1,
            'the body is encrypted with the one content encoding of RFC 8291 §4, "aes128gcm" and not the draft before it',
        );

        // the browser opens it, which is the thing no double has ever done here
        $opened = demo_push_browser([
            'action' => 'open',
            'private_key' => $browser['private_key'],
            'auth' => $browser['auth'],
            'p256dh' => $browser['p256dh'],
            'body' => $push['body'],
            'authorization' => demo_push_header((string) ($push['head'] ?? ''), 'authorization'),
            'endpoint' => $endpoint,
            'application_server_key' => $applicationServerKey,
        ]);
        $vapid = is_array($opened['vapid'] ?? null) ? $opened['vapid'] : [];
        demo_expect(
            ($vapid['key_matches'] ?? false) === true && ($vapid['algorithm'] ?? null) === 'ES256',
            'the request is signed by the application server key the page handed this browser, and by no other (RFC 8292 §4.2)',
        );
        demo_expect(
            ($vapid['aud'] ?? null) === ($vapid['expected_aud'] ?? null),
            sprintf('the signature is addressed to the origin of this push service (%s)', (string) ($vapid['aud'] ?? '')),
        );
        demo_expect(
            ($vapid['sub'] ?? null) === DEMO_PUSH_SUBJECT,
            sprintf('and names somebody the push service can reach about it (RFC 8292 §2.1: %s)', (string) ($vapid['sub'] ?? '')),
        );
        $verified[] = ['Signed request', sprintf('ES256, aud %s, sub %s', (string) ($vapid['aud'] ?? ''), (string) ($vapid['sub'] ?? ''))];

        demo_expect(
            ($opened['title'] ?? null) === parse_url($issuer, \PHP_URL_HOST),
            sprintf('the payload decrypts and names the provider that is asking (RFC 8291 §3.4: "%s")', (string) ($opened['title'] ?? '')),
        );
        demo_expect(
            str_contains((string) ($opened['body'] ?? ''), DEMO_CIBA_BINDING_MESSAGE),
            sprintf('and carries what the client wrote for the user to read (CIBA Core §7.1: "%s")', DEMO_CIBA_BINDING_MESSAGE),
        );
        demo_expect(
            ($opened['url'] ?? null) === $issuer . '/account/approvals',
            sprintf('and sends them to the page of the provider where requests are answered (%s)', (string) ($opened['url'] ?? '')),
        );
        demo_expect(
            ($opened['members'] ?? []) === ['title', 'body', 'url'],
            sprintf('three strings and nothing else (%s)', implode(', ', array_map(strval(...), (array) ($opened['members'] ?? [])))),
        );
        $verified[] = ['Opened', sprintf('"%s" / "%s"', (string) ($opened['title'] ?? ''), (string) ($opened['body'] ?? ''))];

        // BCP 10027 §5.2: the rule the channel exists to keep, read on everything that left this provider
        $authRequestId = (string) ($asked['auth_req_id'] ?? '');
        $carried = ($push['head'] ?? '') . ($push['body'] ?? '') . ($opened['payload'] ?? '');
        demo_expect(
            $authRequestId !== '' && ! str_contains($carried, $authRequestId) && ! str_contains($carried, 'auth_req_id'),
            'nothing of what reached that browser names the request, and nothing in it answers one (BCP 10027 §5.2)',
        );
        $verified[] = ['Names nothing', 'neither the identifier of the request nor a link that answers it'];

        // RFC 8030 §5.2: what is worth delivering is the request it is about
        $ttl = (int) demo_push_header((string) ($push['head'] ?? ''), 'ttl');
        $expiresIn = is_int($asked['expires_in'] ?? null) ? $asked['expires_in'] : 0;
        demo_expect(
            $ttl > 0 && $ttl <= $expiresIn && $ttl >= ($expiresIn - 15),
            sprintf('the push service is asked to keep it for what is left of the request, and not longer (TTL %d s of %d s)', $ttl, $expiresIn),
        );
        $verified[] = ['Worth delivering', sprintf('TTL %d s, the request living %d s', $ttl, $expiresIn)];

        // a push service having a bad minute: the lane comes back, as it does for a logout token
        demo_push_told($told, 503);
        demo_push_backchannel($backchannel, $ca, $registration['client'], $secrets[$registration['secret']], $subject);
        $refused = demo_cli_step($service, 'push', 60.0);
        demo_expect(
            ($refused['answer'] ?? null) === 503,
            'a push service that cannot answer for a browser now is answered 503',
        );
        // and the row is taken out on the attempt that is told the browser is gone (RFC 8030 §7.3)
        demo_push_told($told, 410);
        $retried = demo_cli_step($service, 'push', 120.0);
        demo_expect(
            ($retried['answer'] ?? null) === 410 && (float) ($retried['since_previous'] ?? 0) >= DEMO_PUSH_FIRST_RETRY,
            sprintf(
                'the message came back %.1f s later under the patience of the notifications lane (architecture §5.6)',
                (float) ($retried['since_previous'] ?? 0),
            ),
        );
        $verified[] = ['Came back', sprintf('%.1f s after the 503, on the schedule of the lane', (float) ($retried['since_previous'] ?? 0))];

        [, , $page] = demo_request($cookies, $ca, 'GET', $issuer . '/account/notifications');
        demo_expect(
            str_contains($page, 'data-subscriptions="none"'),
            'and the browser the push service says is gone is out of the page of the account (RFC 8030 §7.3)',
        );
        $verified[] = ['Taken out', 'the row revoked on a 410, not tried for ever'];
    } finally {
        if ($service->isRunning()) {
            $told->close();
            $service->stop();
        }
    }

    io()->table(['Step', 'Verified'], $verified);
    io()->success('A notification of this provider was signed, encrypted, carried by a push service and opened by the browser it was for.');
}

/**
 * How long a run that waits for a push service to answer gives it, in seconds: the first attempt leaves at
 * once, so a browser nobody reached in this long is one nothing is reaching today.
 */
const DEMO_PUSH_BY_HAND_TIMEOUT = 45;

/**
 * Issue #311 by hand: nothing of the laboratory stands in for anybody. No push service of ours, no browser
 * of ours, no user of ours. The request is made for the development user, the notification goes to the
 * browsers that user subscribed, through their own push services, and what this says is which of them this
 * provider reached and when.
 *
 * It is the other half of "castor demo --push", and the half a program cannot assert: whether a person sees
 * a notification is between their browser, their push service and their operating system, and the most this
 * can do is say what left here and what came back. What it reads it reads from the page of the account and
 * from nowhere else, so what it reports is what that user reads for themselves.
 */
function demo_push_by_hand(string $issuer, string $password, string $ca, string $clientId, string $secret, string $subject): void
{
    io()->section('A notification to a browser of yours, and nobody answering for you');
    $page = $issuer . '/account/notifications';
    $cookies = [];
    demo_browser_sign_in($cookies, $issuer, $password, $ca, $issuer . '/account/approvals');
    [$status, , $rendered] = demo_request($cookies, $ca, 'GET', $page);
    demo_expect($status === 200, sprintf('the page of the browsers this provider may reach opens (got %d)', $status));
    $before = demo_push_browsers($rendered);
    if ($before === []) {
        io()->error(sprintf(
            'No browser of "%s" is subscribed, so there is nobody for this provider to reach. Open %s in your own browser, subscribe it, and run this again.',
            DEV_USERNAME,
            $page,
        ));
        exit(1);
    }
    io()->text(sprintf('%d browser(s) of "%s" are subscribed; every one of them is pushed to.', count($before), DEV_USERNAME));

    $metadata = demo_metadata($issuer . '/.well-known/openid-configuration', $ca);
    $backchannel = is_string($metadata['backchannel_authentication_endpoint'] ?? null) ? $metadata['backchannel_authentication_endpoint'] : '';
    demo_expect($backchannel !== '', 'the provider announces a backchannel authentication endpoint (CIBA Core §4)');
    $asked = demo_push_backchannel($backchannel, $ca, $clientId, $secret, $subject);

    // the page is what says a browser was told, and it is the page that user reads themselves
    $deadline = microtime(true) + DEMO_PUSH_BY_HAND_TIMEOUT;
    $after = $before;
    while (microtime(true) < $deadline) {
        [, , $rendered] = demo_request($cookies, $ca, 'GET', $page);
        $after = demo_push_browsers($rendered);
        if (demo_push_reached($before, $after) !== []) {
            break;
        }
        usleep(2_000_000);
    }
    $reached = demo_push_reached($before, $after);
    $rows = [];
    foreach ($after as $id => $browser) {
        $rows[] = [$browser['label'], demo_push_said_of($browser, isset($reached[$id]))];
    }
    io()->table(['Browser', 'What the page says'], $rows);
    if ($reached === []) {
        io()->warning(sprintf(
            'No browser was reached within %d s. The provider is still trying, on the patience of the notifications lane: "castor logs worker" says what each push service answered. A browser whose subscription its push service has dropped is taken out of the page rather than tried for ever (RFC 8030 §7.3).',
            DEMO_PUSH_BY_HAND_TIMEOUT,
        ));
    } else {
        io()->success(sprintf(
            '%d browser(s) were told, and this provider knows nothing more: what a push service does with a message it took is between it and that browser (RFC 8030 §5).',
            count($reached),
        ));
    }

    io()->newLine();
    io()->block(
        [
            sprintf('A client has asked for "%s", and wrote: "%s".', DEV_USERNAME, DEMO_CIBA_BINDING_MESSAGE),
            '',
            'What your browser was sent says that something is waiting and nothing else: no identifier of this request and no link that answers it (BCP 10027 §5.2). What it does carry is the address of this provider, which is where an answer is given.',
            '',
            sprintf(
                'Open %s/account/approvals and answer it. The request lives %d s; nothing here will answer for you, and no client is polling for it in this run ("castor demo --ciba --by-hand" is the one that is).',
                $issuer,
                is_int($asked['expires_in'] ?? null) ? $asked['expires_in'] : 300,
            ),
        ],
        'YOUR TURN',
        'fg=black;bg=yellow',
        ' ',
        true,
    );
}

/**
 * What the page says of one browser, in the words of a run that waits for a person: told by this run, told
 * before it, or never told at all.
 *
 * @param array{label: string, told: string} $browser
 */
function demo_push_said_of(array $browser, bool $reached): string
{
    if ($reached) {
        return 'told just now, at ' . $browser['told'];
    }

    return $browser['told'] === '' ? 'never told' : 'last told ' . $browser['told'];
}

/**
 * The browsers the page of the account lists, by the identifier it gives each row: what the user called it,
 * and when this provider last left a message for it, as that page says it (an empty string for a browser it
 * never has).
 *
 * @return array<string, array{label: string, told: string}>
 */
function demo_push_browsers(string $page): array
{
    $browsers = [];
    foreach (demo_push_rows($page, null) as $row) {
        if (preg_match('/data-subscription="([^"]+)"/', $row, $id) !== 1) {
            continue;
        }
        preg_match_all('/<time datetime="([^"]+)"/', $row, $dates);
        preg_match('#<td>([^<]*)</td>#', $row, $label);
        $browsers[$id[1]] = [
            // the first date of a row is when the browser subscribed, the second, when there is one, is when
            // this provider last left a message for it
            'label' => trim(html_entity_decode($label[1] ?? '')),
            'told' => $dates[1][1] ?? '',
        ];
    }

    return $browsers;
}

/**
 * The browsers this provider left a message for between the two readings of the page: a row whose date
 * moved, and a row that has one where it had none.
 *
 * @param array<string, array{label: string, told: string}> $before
 * @param array<string, array{label: string, told: string}> $after
 *
 * @return array<string, array{label: string, told: string}>
 */
function demo_push_reached(array $before, array $after): array
{
    $reached = [];
    foreach ($after as $id => $browser) {
        if ($browser['told'] !== '' && $browser['told'] !== ($before[$id]['told'] ?? '')) {
            $reached[$id] = $browser;
        }
    }

    return $reached;
}

/**
 * The user this walk asks for, created on the first run and kept, with the password of the development
 * user: the account it subscribes a browser on, and the one a backchannel request names.
 *
 * Its own user rather than the development one, because the browsers of a user are what the lane reaches:
 * this walk needs the only browser of whoever it asks for, and somebody looking at this flow by hand uses
 * the development user.
 *
 * @return string the subject this provider issued it, which is what a "login_hint" names for this tenant
 */
function demo_push_user(string $password): string
{
    // created if it is not there, kept if it is: the command says so itself and the run reads its own user
    op_console(
        ['beffroi:user:create', DEMO_PUSH_USERNAME, '--email', DEMO_PUSH_USERNAME . '@op.localhost', '--email-verified'],
        context()->withAllowFailure()->withQuiet(),
    );
    // never on the command line: the command reads it on its standard input
    op_console(
        ['beffroi:user:set-password', DEMO_PUSH_USERNAME, '--password-stdin'],
        context()->withQuiet()->withInput($password . "\n"),
    );
    $shown = op_console(['beffroi:user:show', DEMO_PUSH_USERNAME, '--no-ansi'], context()->withQuiet())->getOutput();
    if (preg_match('/^\s*Subject\s+(\S+)\s*$/m', $shown, $subject) !== 1) {
        io()->error(sprintf('"beffroi:user:show %s" does not say which subject the user was issued.', DEMO_PUSH_USERNAME));
        exit(1);
    }
    io()->text(sprintf('The walk asks for "%s", whose only browser is the one it draws.', DEMO_PUSH_USERNAME));

    return $subject[1];
}

/**
 * The certificate the push service of the walk answers with: one self-signed certificate on a P-256 key,
 * kept while it is valid, as the client certificate of "castor provision" is. It names the host the
 * containers reach this machine by, in a subject alternative name, which is what a client verifies; and it
 * is a certificate authority as well as a leaf, because what makes it verifiable inside a container is
 * being installed there as a trust anchor and nothing signs above it.
 *
 * @return array{string, string} the certificate and its private key, absolute paths
 */
function demo_push_certificate(): array
{
    $certificateFile = getcwd() . '/' . DEMO_PUSH_CERTIFICATE;
    $keyFile = getcwd() . '/' . DEMO_PUSH_KEY;
    $directory = dirname($certificateFile);
    if (! is_dir($directory) && ! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }
    if (provision_mtls_valid_certificate($certificateFile, $keyFile) === null) {
        provision_self_signed_certificate(DEMO_PUSH_HOST, provision_p256_key(), $certificateFile, $keyFile, DEMO_PUSH_HOST);
        io()->text(sprintf('Issued %s for https://%s:%d, self-signed.', DEMO_PUSH_CERTIFICATE, DEMO_PUSH_HOST, DEMO_PUSH_PORT));
    }

    return [$certificateFile, $keyFile];
}

/**
 * What makes the worker able to push to that service at all: the certificate added to the trust store of
 * the container, which is the same thing its entrypoint does for the certificate of the conformance
 * suite (docker/worker/entrypoint.sh). The worker is the one process that pushes, the notification being a
 * Notification and leaving on the lane of its own (apps/op/config/packages/messenger.yaml), so it is the
 * one container this is done to.
 *
 * Replayed on every run, which is what a container recreated by "castor start" needs.
 */
function demo_push_trust(string $certificate): void
{
    run(['docker', 'compose', 'cp', $certificate, 'worker:' . DEMO_PUSH_TRUSTED_CERTIFICATE], context: context()->withQuiet());
    run(['docker', 'compose', 'exec', '-T', 'worker', 'update-ca-certificates'], context: context()->withQuiet());
    io()->text(sprintf('The worker trusts %s for the time of this walk.', DEMO_PUSH_TRUSTED_CERTIFICATE));
}

/**
 * The push service of the walk, started and listening. Its standard input is kept open so that it can be
 * told what to answer next: a push service that takes the message, one that says the subscription is gone
 * and one that cannot answer now are the same service on the same port, a subscription being recognised by
 * its endpoint.
 *
 * @return array{Process, InputStream}
 */
function demo_push_service(string $certificate, string $privateKey): array
{
    $told = new InputStream();
    $service = new Process(
        [
            'php',
            DEMO_PUSH_SERVICE,
            '--port=' . DEMO_PUSH_PORT,
            '--cert=' . $certificate,
            '--key=' . $privateKey,
            '--answer=201',
        ],
        timeout: null,
    );
    $service->setInput($told);
    $service->start();
    demo_cli_step($service, 'listening', 15.0);
    io()->text(sprintf('A push service of the lab answers on https://%s:%d.', DEMO_PUSH_HOST, DEMO_PUSH_PORT));

    return [$service, $told];
}

/**
 * Tells the running push service what to answer the next push.
 */
function demo_push_told(InputStream $told, int $answer): void
{
    $told->write(
        json_encode(
            [
                'answer' => $answer,
            ],
            \JSON_THROW_ON_ERROR,
        )
            . "\n",
    );
}

/**
 * The browser of the lab, in one process per question asked of it: it draws, and it opens. The private
 * half travels on the standard input of that process and never on a command line.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function demo_push_browser(array $input): array
{
    $browser = new Process(['php', DEMO_PUSH_BROWSER], timeout: 30.0);
    $browser->setInput(json_encode($input, \JSON_THROW_ON_ERROR));
    $browser->run();
    if (! $browser->isSuccessful()) {
        io()->error(sprintf('The browser of the lab gave up: %s', trim($browser->getErrorOutput())));
        exit(1);
    }
    $answer = json_decode(trim($browser->getOutput()), true, 16, \JSON_THROW_ON_ERROR);

    return is_array($answer) ? $answer : [];
}

/**
 * The page of the account where a user says which of their browsers this provider may reach (Push API §4):
 * the application server key it hands out, and the endpoint and the two keys it takes back.
 *
 * @param array<string, array<string, string>> $cookies
 * @param array<string, mixed> $browser what the browser of the lab drew
 *
 * @return string the application server key the page handed out, base64url (RFC 8292 §3.2)
 */
function demo_push_subscribe(array &$cookies, string $issuer, string $password, string $ca, array $browser, string $endpoint): string
{
    $page = $issuer . '/account/notifications';
    // a page of the account belongs to no client and to no interaction, so it answers a browser without a
    // session 401 and sends it nowhere (AccountAccess): the browser signs in where a user of this flow goes
    // by themselves, the page of what is waiting for them, and walks to the account from there
    demo_browser_sign_in($cookies, $issuer, $password, $ca, $issuer . '/account/approvals', DEMO_PUSH_USERNAME);
    [$status, , $rendered] = demo_request($cookies, $ca, 'GET', $page);
    demo_expect($status === 200, sprintf('the page of the browsers this provider may reach opens (got %d)', $status));
    // this walk has to be the only browser this provider can reach; a browser of a previous run of itself is
    // taken out here, one somebody else enrolled is not
    $rendered = demo_push_alone($cookies, $ca, $issuer, $page, $rendered);
    demo_expect(
        preg_match('/data-application-server-key="([^"]+)"/', $rendered, $key) === 1,
        'the page hands this browser the application server key of the tenant, without which it cannot subscribe at all (RFC 8292 §3.2)',
    );
    $fields = demo_form_fields($rendered);
    [$status, $location] = demo_request($cookies, $ca, 'POST', $page, [
        '_token' => $fields['_token'] ?? '',
        'endpoint' => $endpoint,
        'p256dh' => (string) ($browser['p256dh'] ?? ''),
        'auth' => (string) ($browser['auth'] ?? ''),
        'label' => DEMO_PUSH_LABEL,
    ]);
    demo_expect($status === 302 && $location === $page, sprintf('the subscription is recorded (got %d %s)', $status, $location));
    [, , $rendered] = demo_request($cookies, $ca, 'GET', $page);
    demo_expect(
        str_contains($rendered, 'data-subscriptions="1"') && str_contains($rendered, DEMO_PUSH_LABEL),
        'and the page shows one browser, under the name the user gave it',
    );

    return $key[1];
}

/**
 * This walk has to hold the only browser of the user it asks for. What it measures of a push service that
 * answers 503 is the lane coming back, and the lane comes back only when **no** browser of that user was
 * reached (architecture §5.6): a second browser that took the message would answer that question instead of
 * it. The user is the walk's own (DEMO_PUSH_USERNAME), so nothing anybody enrolled by hand is in the way.
 *
 * A browser a run of this walk left behind is taken out here, recognised by the name it subscribes under.
 * Anything else on that account is not this walk's to revoke, and it says which and stops.
 *
 * @param array<string, array<string, string>> $cookies
 *
 * @return string the page once this walk is alone on it
 */
function demo_push_alone(array &$cookies, string $ca, string $issuer, string $page, string $rendered): string
{
    foreach (demo_push_rows($rendered, DEMO_PUSH_LABEL) as $row) {
        if (preg_match('#<form method="post" action="([^"]*revoke)">(.*?)</form>#s', $row, $form) !== 1) {
            continue;
        }
        [$status] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($form[1]), demo_form_fields($form[2]));
        demo_expect($status === 302, sprintf('a browser of an earlier run of this walk is taken out (got %d)', $status));
    }
    [, , $rendered] = demo_request($cookies, $ca, 'GET', $page);
    $others = demo_push_rows($rendered, null);
    if ($others !== []) {
        io()->error(sprintf(
            'The account of "%s" carries %d browser(s) this walk did not enrol, and it needs to hold the only one: what it measures of a push service that cannot answer is the notifications lane coming back, which only happens when no browser of that user was reached. Take them out on %s, signed in as "%s".',
            DEMO_PUSH_USERNAME,
            count($others),
            $page,
            DEMO_PUSH_USERNAME,
        ));
        exit(1);
    }
    demo_expect(str_contains($rendered, 'data-subscriptions="none"'), 'and this walk starts on a provider that reaches nobody');

    return $rendered;
}

/**
 * The rows of the page of the browsers, as the table renders one per subscription; those whose name is the
 * one given, or every one of them when no name is.
 *
 * @return list<string>
 */
function demo_push_rows(string $page, ?string $label): array
{
    if (preg_match_all('#<tr data-subscription="[^"]+">(.*?)</tr>#s', $page, $rows) === 0) {
        return [];
    }
    $matching = [];
    foreach ($rows[0] as $row) {
        if ($label === null || str_contains($row, $label)) {
            $matching[] = $row;
        }
    }

    return $matching;
}

/**
 * A browser on a page of this provider it went to itself, which is where two walks of this task start: no
 * session yet, so the page remembers where the browser was going, sends it to the login of the firewall
 * and brings it back (LoginTarget). No client and no interaction anywhere in it.
 *
 * @param array<string, array<string, string>> $cookies
 *
 * @return string the page, once the browser is signed in and on it
 */
function demo_browser_sign_in(array &$cookies, string $issuer, string $password, string $ca, string $page, string $username = DEV_USERNAME): string
{
    [$status, $location, $rendered] = demo_request($cookies, $ca, 'GET', $page);
    if ($status === 200) {
        return $rendered;
    }
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login'),
        sprintf('%s asks for a login first (got %d %s)', $page, $status, $location),
    );
    [$status, , $login] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('the login page opens (got %d)', $status));
    $login = demo_past_the_address($cookies, $ca, $issuer, $login, $username);
    $form = demo_form_with($login, '_username', 'the login page carries the form of the password');
    demo_expect(
        preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'which says where it posts and carries its token',
    );
    [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_username' => $username,
        '_password' => $password,
        '_csrf_token' => $csrf[1],
    ]);
    demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));
    [$status, , $rendered] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200, sprintf('and the browser comes back to the page it was going to (got %d %s)', $status, $location));

    return $rendered;
}

/**
 * A backchannel authorization request for the development user, which is what has to reach them (CIBA Core
 * §7.1). The walk makes it itself rather than through a client of tests/demo/: what is measured here is
 * what leaves the provider towards the user, and nothing of this walk waits for a token.
 *
 * @param string $endpoint the backchannel authentication endpoint the provider announces
 *
 * @return array<string, mixed> the response of the backchannel authentication endpoint
 */
function demo_push_backchannel(string $endpoint, string $ca, string $clientId, string $secret, string $loginHint): array
{
    $response = http_request('POST', $endpoint, [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_basic' => $clientId . ':' . $secret,
        'body' => [
            'scope' => 'openid profile',
            'login_hint' => $loginHint,
            'binding_message' => DEMO_CIBA_BINDING_MESSAGE,
        ],
    ]);
    $answer = json_decode($response->getContent(false), true, 8, \JSON_THROW_ON_ERROR);
    demo_expect(
        is_array($answer) && is_string($answer['auth_req_id'] ?? null) && is_int($answer['expires_in'] ?? null),
        sprintf('a client asked for something only that user can answer (got %d)', $response->getStatusCode()),
    );

    return is_array($answer) ? $answer : [];
}

/**
 * One header of a request the push service was handed, by its lowercased name; "" when it carries none.
 */
function demo_push_header(string $head, string $name): string
{
    return preg_match('/^' . preg_quote($name, '/') . ':\s*(.+)$/im', $head, $matches) === 1 ? trim($matches[1]) : '';
}

/**
 * The self-registering client of the walk below, and the mode the tenant has to be in for it to exist at
 * all: a credential this provider issued, named, limited in number and revocable (RFC 7591 §1.2). The
 * development tenant serves the conformance suite in "open" mode the rest of the time, so the walk asks
 * for the mode it needs and gives it back.
 */
const DEMO_REGISTER_CLIENT = 'tests/demo/registration-client.php';

const DEMO_REGISTER_ENV_MARKER = 'castor demo --register';

const DEMO_REGISTER_MODE = 'initial_access_token';

/**
 * What the initial access token of the run is called and what it is worth: two registrations, which is the
 * number the walk needs and therefore the number the third one is refused for.
 */
const DEMO_REGISTER_TOKEN_NAME = 'castor demo --register';

const DEMO_REGISTER_REGISTRATIONS = 2;

/**
 * The two clients that write themselves, on two hosts. The host is the whole point of the pair: with
 * "subject_type=pairwise" and no "sector_identifier_uri", the sector of a client is the host of its
 * redirection URI (OIDC Core §8.1), so these two are two sectors and the same user is two subjects. Both
 * are loopback names, which is what the provider allows plain HTTP for (RFC 8252 §7.3), and nothing ever
 * connects to them: the walk reads the code off the redirection, as every walk of this file does.
 */
const DEMO_REGISTER_CLIENTS = [
    'first' => [
        'client_name' => 'A client that registered itself',
        'redirect_uri' => 'http://127.0.0.1:9101/callback',
    ],
    'second' => [
        'client_name' => 'Another client, another sector',
        'redirect_uri' => 'http://second.localhost:9102/callback',
    ],
];

/**
 * The scopes the pair asks for, all of them announced by the tenant: a registration is held to what the
 * provider says it serves (issue #278), so asking for these is asking for nothing of its own.
 */
const DEMO_REGISTER_SCOPE = 'openid profile email';

/**
 * Issue #345, the third success criterion of spike 7 played rather than asserted: a client this provider
 * had never seen registers itself and gets exactly what a declared client gets, and exactly the same
 * refusals.
 *
 * Every other client of this demonstration is a registration in apps/op/config/packages/beffroi.yaml. This
 * walk is the one that declares nothing: the console issues a credential, a program of tests/demo/ spends
 * it, and what it is answered is what it signs a user in with. The pairwise pair is the property of the
 * spike that a unit test proves and a walk shows: the same user, two clients, two subjects, printed side
 * by side.
 */
function demo_register_check(string $issuer, string $password, string $ca): void
{
    io()->section('A client nobody declared registers itself, signs in, and is two subjects');
    $verified = [];

    // The mode first, and given back whatever ends the run: the tenant registers whoever asks the rest of
    // the time, which is what the conformance plans need and what this walk must not leave behind.
    demo_registration_mode($issuer, $ca, DEMO_REGISTER_ENV_MARKER, DEMO_REGISTER_MODE);

    $token = demo_initial_access_token(DEMO_REGISTER_TOKEN_NAME, DEMO_REGISTER_REGISTRATIONS);
    $verified[] = [
        'Initial access token',
        sprintf('"%s", worth %d registrations (beffroi:client:token:issue)', DEMO_REGISTER_TOKEN_NAME, DEMO_REGISTER_REGISTRATIONS),
    ];

    // Phase one: the two registrations, then one more than the credential was issued for.
    $clients = [];
    foreach (DEMO_REGISTER_CLIENTS as $key => $wanted) {
        $clients[$key] = [
            'metadata' => [
                'client_name' => $wanted['client_name'],
                'redirect_uris' => [$wanted['redirect_uri']],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['authorization_code'],
                'response_types' => ['code'],
                'scope' => DEMO_REGISTER_SCOPE,
                // OIDC Core §8.1: what makes the two of them two subjects of the same user
                'subject_type' => 'pairwise',
            ],
        ];
    }
    $run = demo_register_client([
        'action' => 'register',
        'cafile' => $ca,
        'registration_endpoint' => $issuer . '/register',
        'authorization_endpoint' => $issuer . '/authorize',
        'initial_access_token' => $token,
        'clients' => $clients,
        // the registration the spent credential does not buy
        'beyond' => [
            'client_name' => 'One registration too many',
            'redirect_uris' => ['http://127.0.0.1:9103/callback'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'scope' => DEMO_REGISTER_SCOPE,
        ],
        // and the one no credential at all buys, which is the mode this tenant is not in
        'without_token' => [
            'client_name' => 'A client presenting nothing',
            'redirect_uris' => ['http://127.0.0.1:9104/callback'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'scope' => DEMO_REGISTER_SCOPE,
        ],
    ]);

    $registered = is_array($run['registered'] ?? null) ? $run['registered'] : [];
    foreach (array_keys(DEMO_REGISTER_CLIENTS) as $key) {
        $each = is_array($registered[$key] ?? null) ? $registered[$key] : [];
        $body = is_array($each['body'] ?? null) ? $each['body'] : [];
        demo_expect(($each['status'] ?? 0) === 201, sprintf(
            '%s: the registration is answered 201 (got %s %s)',
            $key,
            (string) ($each['status'] ?? '?'),
            (string) ($body['error_description'] ?? $body['error'] ?? ''),
        ));
        demo_expect(
            is_string($body['client_id'] ?? null) && is_string($body['client_secret'] ?? null),
            sprintf('%s: it is answered a client_id and a secret it never chose (RFC 7591 §3.2.1)', $key),
        );
        demo_expect(
            is_string($body['registration_access_token'] ?? null) && is_string($body['registration_client_uri'] ?? null),
            sprintf('%s: and the token and the URI it is now at (RFC 7592 §3)', $key),
        );
        demo_expect(($body['subject_type'] ?? null) === 'pairwise', sprintf(
            '%s: registered for a pairwise subject (got %s)',
            $key,
            json_encode($body['subject_type'] ?? null),
        ));
    }
    $verified[] = [
        'Two registrations',
        sprintf(
            '%s on %s, %s on %s',
            substr((string) $registered['first']['body']['client_id'], 0, 12) . '…',
            parse_url(DEMO_REGISTER_CLIENTS['first']['redirect_uri'], \PHP_URL_HOST),
            substr((string) $registered['second']['body']['client_id'], 0, 12) . '…',
            parse_url(DEMO_REGISTER_CLIENTS['second']['redirect_uri'], \PHP_URL_HOST),
        ),
    ];

    $beyond = is_array($run['beyond'] ?? null) ? $run['beyond'] : [];
    demo_expect(($beyond['status'] ?? 0) >= 400, sprintf(
        'the credential is spent: a registration beyond the two it was issued for is refused (got %s)',
        (string) ($beyond['status'] ?? '?'),
    ));
    $verified[] = [
        'Token spent',
        sprintf('%s "%s"', (string) ($beyond['status'] ?? '?'), (string) ($beyond['body']['error'] ?? null ?? '')),
    ];

    $without = is_array($run['without_token'] ?? null) ? $run['without_token'] : [];
    demo_expect(($without['status'] ?? 0) >= 400, sprintf(
        'and a registration presenting no credential at all is refused: this tenant is not the one the suite registers on (got %s)',
        (string) ($without['status'] ?? '?'),
    ));
    $verified[] = [
        'No credential',
        sprintf('%s "%s"', (string) ($without['status'] ?? '?'), (string) ($without['body']['error'] ?? null ?? '')),
    ];

    // Phase two: each client signs the development user in, with what its registration was answered. One
    // browser per client, so that each sees its own subject and not the session of the other.
    $exchange = [];
    foreach (array_keys(DEMO_REGISTER_CLIENTS) as $key) {
        $each = $registered[$key];
        $body = $each['body'];
        $cookies = [];
        [$status, $location] = demo_resume(
            $cookies,
            $ca,
            $issuer,
            demo_login($cookies, $issuer, $password, $ca, (string) $each['authorization_url']),
        );
        $redirect = DEMO_REGISTER_CLIENTS[$key]['redirect_uri'];
        demo_expect($status === 302 && str_starts_with($location, $redirect . '?'), sprintf(
            '%s: the OP sends the browser to the redirection this client registered and to no other (got %d %s)',
            $key,
            $status,
            $location,
        ));
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
        demo_expect(
            isset($callback['code']) && ($callback['state'] ?? null) === $each['state'] && ($callback['iss'] ?? null) === $issuer,
            sprintf('%s: the callback carries a code, the state this client sent, and iss (RFC 9207)', $key),
        );
        $exchange[$key] = [
            'client_id' => (string) $body['client_id'],
            'client_secret' => (string) $body['client_secret'],
            'code' => (string) $callback['code'],
            'redirect_uri' => $redirect,
            'code_verifier' => (string) $each['code_verifier'],
        ];
    }

    $exchanged = demo_register_client([
        'action' => 'exchange',
        'cafile' => $ca,
        'token_endpoint' => $issuer . '/token',
        'clients' => $exchange,
    ]);
    $tokens = is_array($exchanged['exchanged'] ?? null) ? $exchanged['exchanged'] : [];
    $subjects = [];
    foreach (array_keys(DEMO_REGISTER_CLIENTS) as $key) {
        $each = is_array($tokens[$key] ?? null) ? $tokens[$key] : [];
        demo_expect(($each['status'] ?? 0) === 200, sprintf(
            '%s: the code is exchanged with the secret the registration gave (got %s %s)',
            $key,
            (string) ($each['status'] ?? '?'),
            (string) ($each['error_description'] ?? ''),
        ));
        demo_expect(is_string($each['sub'] ?? null) && $each['sub'] !== '', sprintf('%s: the ID token names a subject', $key));
        demo_expect(($each['nonce'] ?? null) === $registered[$key]['nonce'], sprintf(
            '%s: it carries the nonce this client sent (OIDC Core §3.1.3.7)',
            $key,
        ));
        demo_expect(($each['aud'] ?? null) === $exchange[$key]['client_id'], sprintf(
            '%s: and is addressed to this client and to no other (got %s)',
            $key,
            json_encode($each['aud'] ?? null),
        ));
        $subjects[$key] = (string) $each['sub'];
    }

    // The property of the spike, shown: the same user, two sectors, two subjects.
    demo_expect($subjects['first'] !== $subjects['second'], sprintf(
        'the same user is a different subject to each of the two clients (OIDC Core §8.1): "%s" and "%s"',
        $subjects['first'],
        $subjects['second'],
    ));
    io()->text(sprintf(' <info>✓</info> %s sees sub %s', parse_url(DEMO_REGISTER_CLIENTS['first']['redirect_uri'], \PHP_URL_HOST), $subjects['first']));
    io()->text(sprintf(' <info>✓</info> %s sees sub %s', parse_url(DEMO_REGISTER_CLIENTS['second']['redirect_uri'], \PHP_URL_HOST), $subjects['second']));
    $verified[] = ['Pairwise', sprintf('%s and %s, the same "alice"', $subjects['first'], $subjects['second'])];

    // Phase three: the client reads and replaces itself, and is refused what the provider does not offer.
    $first = $registered['first'];
    $configured = demo_register_client([
        'action' => 'configure',
        'cafile' => $ca,
        'registration_client_uri' => (string) $first['body']['registration_client_uri'],
        'registration_access_token' => (string) $first['body']['registration_access_token'],
        'another_token' => (string) $registered['second']['body']['registration_access_token'],
        'replacement' => [
            'client_id' => (string) $first['body']['client_id'],
            'client_name' => 'The name it chose for itself',
            'redirect_uris' => [DEMO_REGISTER_CLIENTS['first']['redirect_uri']],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'scope' => DEMO_REGISTER_SCOPE,
            'subject_type' => 'pairwise',
        ],
        // a grant nobody wired: the member exists, the value is not one this provider has (RFC 7591 §3.2.2)
        'refused' => [
            'client_id' => (string) $first['body']['client_id'],
            'redirect_uris' => [DEMO_REGISTER_CLIENTS['first']['redirect_uri']],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'grant_types' => ['password'],
            'response_types' => ['code'],
            'scope' => DEMO_REGISTER_SCOPE,
            'subject_type' => 'pairwise',
        ],
    ]);

    $read = is_array($configured['read'] ?? null) ? $configured['read'] : [];
    demo_expect(($read['status'] ?? 0) === 200, sprintf('the client reads itself back (RFC 7592 §2.1, got %s)', (string) ($read['status'] ?? '?')));
    demo_expect(
        ($read['body']['client_id'] ?? null) === (string) $first['body']['client_id'],
        'and what it reads is itself',
    );
    demo_expect(
        ! isset($read['body']['client_secret']),
        'the read gives back no secret: a credential this provider showed once is not shown again',
    );

    $withoutToken = is_array($configured['read_without_token'] ?? null) ? $configured['read_without_token'] : [];
    demo_expect(($withoutToken['status'] ?? 0) === 401, sprintf(
        'the same read with no registration access token is refused (got %s)',
        (string) ($withoutToken['status'] ?? '?'),
    ));
    $another = is_array($configured['read_with_another_token'] ?? null) ? $configured['read_with_another_token'] : [];
    demo_expect(($another['status'] ?? 0) >= 400, sprintf(
        'and with the token of the other client, which is a client reading a client that is not itself (got %s)',
        (string) ($another['status'] ?? '?'),
    ));

    $updated = is_array($configured['updated'] ?? null) ? $configured['updated'] : [];
    demo_expect(($updated['status'] ?? 0) === 200, sprintf('it replaces itself (RFC 7592 §2.2, got %s)', (string) ($updated['status'] ?? '?')));
    demo_expect(
        ($updated['body']['client_name'] ?? null) === 'The name it chose for itself',
        sprintf('and the member it changed is what it changed it to (got %s)', json_encode($updated['body']['client_name'] ?? null)),
    );

    $refused = is_array($configured['refused'] ?? null) ? $configured['refused'] : [];
    demo_expect(($refused['status'] ?? 0) === 400, sprintf(
        'a replacement asking for a grant nobody wired is refused (got %s)',
        (string) ($refused['status'] ?? '?'),
    ));
    demo_expect(($refused['body']['error'] ?? null) === 'invalid_client_metadata', sprintf(
        'and says which member it was (RFC 7591 §3.2.2, got %s)',
        json_encode($refused['body']['error'] ?? null),
    ));
    $verified[] = [
        'Itself',
        sprintf(
            'read 200, replaced 200, a grant nobody wired %s "%s", no token 401',
            (string) ($refused['status'] ?? '?'),
            (string) ($refused['body']['error'] ?? ''),
        ),
    ];

    // Phase four: the client removes itself, and what it held is worth nothing.
    $gone = demo_register_client([
        'action' => 'delete',
        'cafile' => $ca,
        'registration_client_uri' => (string) $first['body']['registration_client_uri'],
        'registration_access_token' => (string) $first['body']['registration_access_token'],
    ]);
    $deleted = is_array($gone['deleted'] ?? null) ? $gone['deleted'] : [];
    demo_expect(($deleted['status'] ?? 0) === 204, sprintf('the client deletes itself (RFC 7592 §2.3, got %s)', (string) ($deleted['status'] ?? '?')));
    $after = is_array($gone['read_after'] ?? null) ? $gone['read_after'] : [];
    demo_expect(($after['status'] ?? 0) >= 400, sprintf(
        'and the token it held is worth nothing afterwards (got %s)',
        (string) ($after['status'] ?? '?'),
    ));
    $verified[] = ['Deleted', sprintf('204, then %s on the same URI', (string) ($after['status'] ?? '?'))];

    // The second client is left to the purge that decision 0009 put on the scheduled step: it was used, so
    // it lives as long as the tenant said a used client does. The walk says so rather than tidying, because
    // what removes a dynamic client here is the provider and not the run.
    demo_registration_mode($issuer, $ca, DEMO_REGISTER_ENV_MARKER, null);

    io()->table(['Step', 'Verified'], $verified);
    io()->success(sprintf(
        'A client this provider had never seen registered itself, signed "%s" in, read and replaced itself, and deleted itself; the same user is two subjects to two sectors.',
        DEV_USERNAME,
    ));
    io()->note(sprintf(
        'The client on %s is left registered: it was used, so the scheduled step deletes it after the period this tenant named (decision 0009, keep_a_client_unused_for). "beffroi:client:list" shows it until then.',
        parse_url(DEMO_REGISTER_CLIENTS['second']['redirect_uri'], \PHP_URL_HOST),
    ));
}

/**
 * Writes the registration mode a walk asks the tenant for into apps/op/.env.local, or takes it back out: a
 * block named after the walk that owns it, rewritten every time, restored by a shutdown function because
 * demo_expect() exits and an exit skips a finally. The tenant serves the conformance plans in "open" mode, so
 * a run that left another mode behind would turn every registration module red.
 *
 * What says the mode is in force is the endpoint itself: a registration presenting no credential is refused
 * in every mode but the open one, and answered 201 in that one, so the walk polls on that and on nothing
 * else. A mode of null is the default the tenant is given back.
 */
function demo_registration_mode(string $issuer, string $ca, string $marker, ?string $mode): void
{
    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    $block = sprintf('/\n*###> %1$s ###\n.*?###< %1$s ###\n/s', preg_quote($marker, '/'));
    $content = rtrim((string) preg_replace($block, "\n", (string) file_get_contents($path)), "\n") . "\n";
    if ($mode !== null) {
        $content .= sprintf(
            "\n###> %1\$s ###\nBEFFROI_REGISTRATION_MODE=%2\$s\n###< %1\$s ###\n",
            $marker,
            $mode,
        );
        register_shutdown_function(static function () use ($path, $block): void {
            file_put_contents($path, rtrim((string) preg_replace($block, "\n", (string) file_get_contents($path)), "\n") . "\n");
        });
    }
    file_put_contents($path, $content);
    $deadline = time() + 60;
    do {
        $response = http_request('POST', $issuer . '/register', [
            'cafile' => $ca,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => (string) json_encode([
                'redirect_uris' => ['http://127.0.0.1:9109/probe'],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['authorization_code'],
                'response_types' => ['code'],
            ]),
        ]);
        $status = $response->getStatusCode();
        if ($status >= 400 === ($mode !== null)) {
            io()->text(sprintf(
                ' <info>✓</info> the tenant registers %s (a registration with no credential is answered %d)',
                $mode === null ? 'whoever asks again' : 'only whoever presents what "' . $mode . '" asks for',
                $status,
            ));
            // The open mode answers the probe with a client; it is not left behind.
            if ($mode === null && $status === 201) {
                $body = json_decode($response->getContent(false), true);
                if (is_array($body) && is_string($body['registration_client_uri'] ?? null) && is_string($body['registration_access_token'] ?? null)) {
                    http_request('DELETE', $body['registration_client_uri'], [
                        'cafile' => $ca,
                        'headers' => ['Authorization' => 'Bearer ' . $body['registration_access_token']],
                    ])->getStatusCode();
                }
            }

            return;
        }
        sleep(1);
    } while (time() < $deadline);
    io()->error(sprintf(
        'The registration endpoint still answers %d a minute after %s changed: do the workers of the op container watch it (compose.yaml)?',
        $status,
        DEV_ENV_LOCAL,
    ));
    exit(1);
}

/**
 * An initial access token of the tenant, issued by the console command a tenant issues them with (#344):
 * the value is printed once, on the last line, and this provider cannot show it again. Two walks ask for
 * one, under a name of their own and worth what they will spend, so it is written here once.
 */
function demo_initial_access_token(string $name, int $registrations): string
{
    $process = new Process([
        'docker',
        'compose',
        'exec',
        '-T',
        'op',
        'php',
        'bin/console',
        'beffroi:client:token:issue',
        $name,
        '--registrations',
        (string) $registrations,
        '--days',
        '1',
    ]);
    $process->setTimeout(120.0);
    $process->run();
    demo_expect($process->isSuccessful(), sprintf(
        'the console issues an initial access token (exit %d): %s',
        $process->getExitCode() ?? -1,
        trim($process->getErrorOutput() . $process->getOutput()),
    ));
    $lines = array_values(array_filter(array_map(trim(...), explode("\n", $process->getOutput())), static fn (string $line): bool => $line !== ''));
    $token = $lines === [] ? '' : end($lines);
    demo_expect(
        preg_match('/^[A-Za-z0-9_-]{20,}$/', $token) === 1,
        'and prints it once, on its last line: ' . $process->getOutput(),
    );

    return $token;
}

/**
 * The self-registering client of tests/demo/, one phase per call: it holds nothing between them, because
 * the browser step in the middle is the walk's.
 *
 * @param array<string, mixed> $input
 * @return array<string, mixed>
 */
function demo_register_client(array $input): array
{
    $phase = (string) ($input['action'] ?? '?');
    $process = new Process(['php', DEMO_REGISTER_CLIENT], input: (string) json_encode($input));
    $process->setTimeout(120.0);
    $process->run();
    // What the phase answered belongs in the message only when there is something wrong with it: three
    // phases printing their whole JSON on success would bury the assertions that follow them.
    demo_expect($process->isSuccessful(), sprintf(
        'the registration client ran its "%s" phase%s',
        $phase,
        $process->isSuccessful() ? '' : sprintf(' (exit %d): %s', $process->getExitCode() ?? -1, trim($process->getErrorOutput())),
    ));
    $run = json_decode($process->getOutput(), true);
    demo_expect(
        is_array($run),
        sprintf(
            'and answered a JSON object%s',
            is_array($run) ? '' : ': ' . $process->getOutput(),
        ),
    );

    return $run;
}

/**
 * The client of the attested mode, run under the autoloader of the monorepo: it is the only party of this
 * walk that signs anything, the statements being the authority's and the browser and the token the walk's.
 */
const DEMO_ATTESTED_CLIENT = 'tests/demo/attestation-client.php';

/**
 * The block this walk writes in apps/op/.env.local while it runs, and the mode it asks the tenant for: the
 * conformance plans need the open mode the rest of the time, so the block is named and taken back out.
 */
const DEMO_ATTESTED_ENV_MARKER = 'castor demo --attested';

const DEMO_ATTESTED_MODE = 'software_statement';

/**
 * The authority this tenant pinned for statements, and the key of it the laboratory holds whole, which
 * "castor provision" generates and publishes the public half of (DEV_DEMO_ATTESTATION_AUTHORITY).
 */
const DEMO_ATTESTED_AUTHORITY = 'https://attestation.demo.localhost';

const DEMO_ATTESTED_AUTHORITY_KEYS = 'var/demo/demo-attestation.jwks.json';

/**
 * An authority this tenant pinned for something else: it signs the assertions of "castor demo --assertion"
 * about the users it knows, and a tenant that trusts it about a user has not pinned it about a piece of
 * software. Its statement is refused for that reason and for no other, which is what makes it the right
 * stranger to play.
 */
const DEMO_ATTESTED_STRANGER = 'https://issuer.demo.localhost';

const DEMO_ATTESTED_STRANGER_KEYS = 'var/demo/demo-issuer.jwks.json';

/**
 * The provider a statement of the walk names when it is addressed to somebody else (RFC 7591 §2.3): a name
 * no tenant of this stack answers to.
 */
const DEMO_ATTESTED_ELSEWHERE = 'https://another.op.example';

const DEMO_ATTESTED_REDIRECT_URI = 'http://127.0.0.1:9105/callback';

const DEMO_ATTESTED_SCOPE = 'openid profile email';

/**
 * What the authority says of the software: the identifier it calls the product by across every installation
 * of it, the version of this one, and the name a user will read on the consent page. The client sends a name
 * of its own, which the statement outranks (RFC 7591 §3.1.1), and that is the whole point of an attestation:
 * what a stranger says of itself is not what its publisher signed.
 */
const DEMO_ATTESTED_SOFTWARE_ID = 'invoice-reader';

const DEMO_ATTESTED_SOFTWARE_VERSION = '2.1.0';

const DEMO_ATTESTED_NAME = 'Invoice reader, attested by its publisher';

const DEMO_ATTESTED_CLAIMED_NAME = 'The name the client wrote for itself';

/**
 * RFC 7591 §2.3, the fourth mode of decision 0009: a registration this provider authorises on nothing it
 * issued. No initial access token, no credential in any header, and a statement signed by an authority the
 * policy of the tenant pinned; the client is answered credentials it never had before and is a client like
 * any other from that moment, which the sign-in below is what proves.
 *
 * The refusals are played as the acceptance is, because a mode that crosses the boundary of an organisation
 * is only as good as what it turns away: the same statement twice, one signed by an authority pinned for
 * something else, one an authority signed for another provider, and a body carrying none at all.
 */
function demo_attested_check(string $issuer, string $password, string $ca): void
{
    io()->section('A client an authority attested registers, and nothing of this provider authorises it');
    $verified = [];

    // The mode first, and given back whatever ends the run: the tenant registers whoever asks the rest of
    // the time, which is what the conformance plans need and what this walk must not leave behind.
    demo_registration_mode($issuer, $ca, DEMO_ATTESTED_ENV_MARKER, DEMO_ATTESTED_MODE);

    $run = demo_attested_client([
        'cafile' => $ca,
        'registration_endpoint' => $issuer . '/register',
        'audience' => $issuer,
        'authority' => DEMO_ATTESTED_AUTHORITY,
        'jwks_file' => getcwd() . '/' . DEMO_ATTESTED_AUTHORITY_KEYS,
        'stranger_authority' => DEMO_ATTESTED_STRANGER,
        'stranger_jwks_file' => getcwd() . '/' . DEMO_ATTESTED_STRANGER_KEYS,
        'elsewhere' => DEMO_ATTESTED_ELSEWHERE,
        'metadata' => [
            'client_name' => DEMO_ATTESTED_CLAIMED_NAME,
            'redirect_uris' => [DEMO_ATTESTED_REDIRECT_URI],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'scope' => DEMO_ATTESTED_SCOPE,
        ],
        'attested' => [
            'software_id' => DEMO_ATTESTED_SOFTWARE_ID,
            'software_version' => DEMO_ATTESTED_SOFTWARE_VERSION,
            'client_name' => DEMO_ATTESTED_NAME,
        ],
    ]);

    $registered = is_array($run['registered'] ?? null) ? $run['registered'] : [];
    $body = is_array($registered['body'] ?? null) ? $registered['body'] : [];
    demo_expect(($registered['status'] ?? 0) === 201, sprintf(
        'the statement of the pinned authority registers a client, with no credential of this provider presented (got %s %s)',
        (string) ($registered['status'] ?? '?'),
        (string) ($body['error_description'] ?? $body['error'] ?? ''),
    ));
    $clientId = (string) ($body['client_id'] ?? '');
    $secret = (string) ($body['client_secret'] ?? '');
    demo_expect($clientId !== '' && $secret !== '', 'and answers credentials this client never had before (RFC 7591 §3.2.1)');
    demo_expect(($body['client_name'] ?? null) === DEMO_ATTESTED_NAME, sprintf(
        'what the authority signed outranks what the client said of itself (RFC 7591 §3.1.1: got "%s" for a client that sent "%s")',
        (string) ($body['client_name'] ?? ''),
        DEMO_ATTESTED_CLAIMED_NAME,
    ));
    demo_expect(
        ($body['software_id'] ?? null) === DEMO_ATTESTED_SOFTWARE_ID && ($body['software_version'] ?? null) === DEMO_ATTESTED_SOFTWARE_VERSION,
        sprintf(
            'and the software the statement names is kept on the client (RFC 7591 §2: %s %s)',
            (string) ($body['software_id'] ?? ''),
            (string) ($body['software_version'] ?? ''),
        ),
    );
    $verified[] = [
        'Registration',
        sprintf('%s… on a statement of %s, no credential of this provider presented', substr($clientId, 0, 12), DEMO_ATTESTED_AUTHORITY),
    ];
    $verified[] = [
        'Attested members',
        sprintf('"%s" and %s %s, over the name the client sent', DEMO_ATTESTED_NAME, DEMO_ATTESTED_SOFTWARE_ID, DEMO_ATTESTED_SOFTWARE_VERSION),
    ];

    // Every refusal about a statement is the same refusal, and whoever presents one learns nothing else
    // (SoftwareStatementVerifier, decision 0006).
    foreach (DEMO_ATTESTED_REFUSALS as $key => $what) {
        $refused = is_array($run[$key] ?? null) ? $run[$key] : [];
        $answered = is_array($refused['body'] ?? null) ? $refused['body'] : [];
        demo_expect(($refused['status'] ?? 0) === $what['status'] && ($answered['error'] ?? null) === $what['error'], sprintf(
            '%s (got %s "%s")',
            $what['says'],
            (string) ($refused['status'] ?? '?'),
            (string) ($answered['error'] ?? ''),
        ));
    }
    $verified[] = [
        'Refused',
        'the same statement again, an authority pinned for something else, one addressed elsewhere, and none at all',
    ];

    // And it is a client like any other from there: the code flow of every other walk, with the credentials
    // the registration handed it and the name its publisher signed on the page the user reads.
    $cookies = [];
    $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $state = bin2hex(random_bytes(16));
    $authorization =
        $issuer
        . '/authorize?'
        . http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => DEMO_ATTESTED_REDIRECT_URI,
            'scope' => DEMO_ATTESTED_SCOPE,
            'state' => $state,
            'nonce' => bin2hex(random_bytes(16)),
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]);
    [$status, $location] = demo_resume(
        $cookies,
        $ca,
        $issuer,
        demo_login($cookies, $issuer, $password, $ca, $authorization),
        static function (string $page): void {
            demo_expect(
                str_contains($page, DEMO_ATTESTED_NAME),
                sprintf('the consent page shows the name the authority signed and not the one the client sent ("%s")', DEMO_ATTESTED_NAME),
            );
        },
    );
    demo_expect($status === 302 && str_starts_with($location, DEMO_ATTESTED_REDIRECT_URI . '?'), sprintf(
        'the OP sends the browser to the redirection the statement registered (got %d %s)',
        $status,
        $location,
    ));
    $callback = [];
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(
        is_string($callback['code'] ?? null) && ($callback['state'] ?? null) === $state && ($callback['iss'] ?? null) === $issuer,
        'and the callback carries a code, the state this client sent, and iss (RFC 9207)',
    );

    $tokens = demo_exchange_code($issuer, $ca, $clientId, $secret, (string) $callback['code'], DEMO_ATTESTED_REDIRECT_URI, $verifier);
    $claims = demo_claims_of((string) ($tokens['id_token'] ?? ''));
    demo_expect(
        is_string($claims['sub'] ?? null) && $claims['sub'] !== '',
        sprintf('the ID token names a subject (got "%s")', (string) ($claims['sub'] ?? '')),
    );
    demo_expect(($claims['aud'] ?? null) === $clientId, sprintf(
        'and is addressed to the client the statement registered and to no other (got "%s")',
        is_string($claims['aud'] ?? null) ? $claims['aud'] : '',
    ));
    $verified[] = [
        'Signed in',
        sprintf('"%s" is %s… to it, on a code spent with the secret the registration gave', DEV_USERNAME, substr((string) $claims['sub'], 0, 12)),
    ];

    // Given back before the table rather than by the shutdown function alone, so that what the next run of a
    // conformance plan finds is asserted here and not hoped for.
    demo_registration_mode($issuer, $ca, DEMO_ATTESTED_ENV_MARKER, null);

    io()->table(['Step', 'Verified'], $verified);
    io()->success(sprintf(
        'A client this provider authorises on nothing of its own registered on a statement of %s, was given the name its publisher signed, and signed "%s" in.',
        DEMO_ATTESTED_AUTHORITY,
        DEV_USERNAME,
    ));
    io()->note(sprintf(
        'The client is left registered: it was used, so the scheduled step deletes it after the period this tenant named (decision 0009, keep_a_client_unused_for). "beffroi:client:list" shows it until then, and "beffroi:client:delete %s" now.',
        $clientId,
    ));
}

/**
 * What each refused registration of the walk must answer, by the key the client program returns it under.
 * A statement this tenant does not accept, whatever is wrong with it, is one refusal and one message
 * (`invalid_software_statement`); a body carrying none at all presents nothing this mode acts on, which is
 * not a bad statement but an unauthorized request.
 */
const DEMO_ATTESTED_REFUSALS = [
    'replayed' => [
        'status' => 400,
        'error' => 'invalid_software_statement',
        'says' => 'the same statement again registers nothing: one statement registers one client (RFC 7591 §2.3)',
    ],
    'stranger' => [
        'status' => 400,
        'error' => 'invalid_software_statement',
        'says' => 'a statement signed by an authority this tenant pinned for assertions and not for statements is refused',
    ],
    'elsewhere' => [
        'status' => 400,
        'error' => 'invalid_software_statement',
        'says' => 'and one its authority addressed to another provider, refused the same way and with the same message',
    ],
    'without_statement' => [
        'status' => 401,
        'error' => 'invalid_token',
        'says' => 'a registration carrying no statement at all is unauthorized, this tenant being in no other mode',
    ],
];

/**
 * The attestation client of tests/demo/, which castor cannot run itself: it holds the key of the authority
 * and is the only thing here that signs.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function demo_attested_client(array $input): array
{
    $process = new Process(['php', DEMO_ATTESTED_CLIENT], input: (string) json_encode($input));
    $process->setTimeout(120.0);
    $process->run();
    demo_expect($process->isSuccessful(), sprintf(
        'the attestation client ran%s',
        $process->isSuccessful() ? '' : sprintf(' (exit %d): %s', $process->getExitCode() ?? -1, trim($process->getErrorOutput())),
    ));
    $run = json_decode($process->getOutput(), true);
    demo_expect(is_array($run), sprintf('and answered a JSON object%s', is_array($run) ? '' : ': ' . $process->getOutput()));

    return $run;
}
