<?php

declare(strict_types=1);

/*
 * The provisioning of the development stack: apps/op/.env.local, the tenant, the signing key, the user and
 * the client secrets, replayed on every run. What the CI runs after the stack is up.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Process\Process;

/**
 * The variables "castor provision" writes into apps/op/.env.local when they are missing: development
 * values, generated once per checkout, never committed (apps/op/.env explains each one).
 */
const DEV_ENV_LOCAL = 'apps/op/.env.local';

const DEV_USERNAME = 'alice';

/**
 * The slug of the one tenant of the development stack (apps/op/config/packages/beffroi.yaml names no other,
 * BEFFROI_TENANT_SLUG in compose.yaml is the same value for the KMS containers).
 */
const DEV_TENANT_SLUG = 'default';

/**
 * The description of the development user, every claim of OIDC Core §5.1 the "profile", "phone" and
 * "address" scopes stand for: the scope modules of the conformance plan check that UserInfo answers each
 * scope with its claims, and a user without them ends those modules in a warning (issue #45).
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
    // Not a URL of this provider: what the search of a dump looks for must collide with nothing a
    // readable column holds, and the base URL of the provider is the prefix of the logo of its tenant
    // (issue #505).
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

/**
 * Where the client certificate of the development stack lives, on the machine and not in a container:
 * the host is where "castor mtls" and anyone with a curl presents it from. Under var/, which the
 * repository ignores; a certificate of a development stack is not a secret worth a vault, and it is not
 * committed either.
 */
const DEV_MTLS_DIRECTORY = 'var/mtls';

const DEV_MTLS_CLIENT_NAME = 'beffroi-dev-mtls-client';

/**
 * The host of the listener that asks for a client certificate; MTLS_SERVER_NAME in compose.yaml is the
 * same value, and the ordinary host of the OP is not this one (architecture §6).
 */
const DEV_MTLS_SERVER_NAME = 'mtls.op.localhost';

/**
 * Long enough not to be reissued in the middle of a spike, short enough to say it is a development one.
 */
const DEV_MTLS_CLIENT_DAYS = 90;

/**
 * Where the key material of the four clients of the FAPI 2 plans lives, on the machine and not in a
 * container (tests/conformance/README.md): one JWK Set per client, private half included, plus the
 * certificate and its key for the two that authenticate with one. Under var/, which the repository
 * ignores, beside the client certificate above: what a development stack generates is not committed, and
 * the provider is given the public half through apps/op/.env.local.
 */
const DEV_CONFORMANCE_DIRECTORY = 'var/conformance';

/**
 * The clients the plans that prove a key run with, two per run: a handful of modules need a second client
 * to present an authorization code, a request URI or a request object that was issued to another one.
 * Each one holds one P-256 key, published to the provider in the environment variable named here
 * (apps/op/config/packages/beffroi.yaml reads it) and held whole by the suite; the ones that carry a
 * certificate have it issued on that very key, so what the handshake proves and what signs a request
 * object are the same key.
 *
 * What the certificate is for depends on the run. In the FAPI 2 runs that bind their tokens to one, it is
 * also what authenticates the client ("self_signed_tls_client_auth", RFC 8705 §2.2). In the FAPI-CIBA
 * runs it is only what the tokens are bound to: those clients authenticate with "private_key_jwt" and
 * present a certificate all the same, the profile asking for sender-constrained tokens whichever way the
 * client authenticated, and the suite refusing to configure a static client of that plan without one.
 *
 * The Security Profile and Message Signing runs do not share their clients. Message Signing holds a
 * client to signing every authorization request it starts (RFC 9101 §10.5,
 * require_signed_request_object), which is a registration and not a mode: the same client cannot both
 * require an object and start the unsigned requests the Security Profile plan sends. The FAPI-CIBA runs
 * do not share theirs either: a client registers one backchannel token delivery mode (CIBA Core §4), and
 * the two runs are that mode changed.
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

/**
 * The key the body of every message is sealed to (decision 0020, issue #539), and the first key a tenant is
 * given: a key of any other algorithm announces its own staging on a transport, and nothing leaves the
 * process before this one exists (issue #548). A stack without it writes no message at all, the provider
 * refusing to put in a queue what it cannot seal.
 */
const DEV_MESSAGE_KEY_ALGORITHM = 'MESSAGE-SEAL';

/**
 * The keys the tenant holds beside that one and beside the one the provider signs with by default: ES256,
 * because the four clients of the FAPI 2 plans register it for everything the provider signs for them and
 * the profile refuses RS256, the key a client encrypts a request object to, same custody, same four states,
 * published with "use": "enc" (issue #164), and the application server key of Web Push, same custody again
 * and the other key the tenant keeps rather than publishing (RFC 8292 §2, issue #265): a browser subscribes
 * under it, so it exists before anybody opens the page of their notifications; and the SAML signing key of
 * the identity provider of the tenant, same custody, published as a certificate in its metadata and never in
 * its JWK Set (beffroi/saml, issue #728), so that a service provider can be configured from that metadata
 * once the stack is up. A key that is there already is kept and rotated by hand; nothing here generates a
 * second one.
 */
const DEV_KEY_ALGORITHMS = ['ES256', 'ECDH-ES+A256KW', 'VAPID', 'SAML-SIGNING'];

/**
 * Where the key material of the lab that is nobody's client lives, beside the one of the conformance
 * clients and under the same rule: what a development stack generates is not committed, the provider is
 * given the public half through apps/op/.env.local, and the lab reads the private one from here. The
 * trusted issuer of the assertion grant and the attestation authority keep their keys there.
 *
 * No client of the demonstration has a key here any more: a client of the forge draws what it needs when
 * it is built and publishes the public half in its own registration (issue #582), so there is nothing to
 * provision for it and nothing of it to hand over.
 */
const DEV_DEMO_DIRECTORY = 'var/demo';

/**
 * The issuer of the development stack whose signature the tenant trusts (RFC 7523 §3, issue #299), which
 * "castor demo --assertion" signs with. Its key lives in var/demo/ under the same rule as the others:
 * what a development stack generates is not committed, the provider is given the public half through
 * apps/op/.env.local, and the lab reads the private one from var/demo/.
 *
 * It is not a client, and the name here is not a client identifier: it is the "iss" its assertions carry, the
 * source of the linked identities their subjects name (`identity_provider`), and the subject the development
 * user is known by over there, which this task links to that user because nothing else ever writes such a row.
 */
const DEV_DEMO_ISSUER = [
    'issuer' => 'https://issuer.demo.localhost',
    'env' => 'DEMO_ISSUER_JWKS',
    'file' => 'demo-issuer',
    'identity_provider' => 'demo-issuer',
    'subject' => 'alice@issuer.demo.localhost',
];

/**
 * The authority of the development stack whose software statements the tenant accepts (RFC 7591 §2.3, issue
 * #347), which "castor demo --attested" signs with. Its key lives beside the one of the trusted issuer above
 * and under the same rule: what a development stack generates is not committed, the provider is given the
 * public half through apps/op/.env.local, and the lab reads the private one from var/demo/.
 *
 * It is not the trusted issuer of RFC 7523 §3 and it is not a client: one signs about a user, the other
 * attests a piece of software, the tenant pins them apart, and a key that attests nothing about users is a
 * key an authority can hand to a store without handing it a way to name somebody.
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
 * The policy the credential of the OP is cut from, written by docker/vault/init.sh from
 * docker/vault/beffroi-op.hcl: data keys and decryption under the Transit keys of the tenants, the
 * configuration of those keys, nothing else. It is also what tells a request of the OP from a request of
 * the root token in the audit device of Vault, which is where the count of a measurement is read
 * (cost.php).
 */
const VAULT_OP_POLICY = 'beffroi-op';

#[AsTask(
    description: 'Provision the development OP after "castor start": the KMS that seals the signing keys and the secrets of the clients (apps/op/.env.local), then the tenant, a signing key (checked against the KMS when there is one already) and the user "alice" with a full profile and a password',
)]
function provision(
    #[AsOption(
        description: 'The KMS to seal the keys of the tenant with when apps/op/.env.local names none yet: sodium (default, a key generated in place), file (the same key in a file of the op container, mode 0600), vault (a token minted under the policy of the OP on the Vault of "castor start --kms vault") or aws (the LocalStack of "castor start --kms aws"); the backend already there is kept, switching is a change of KMS',
    )]
    ?string $kms = null,
): void {
    io()->title('Provisioning the development OP');

    io()->section('Development secrets');
    $env = provision_env_local($kms);

    // The schema first: nothing else of this task has a table to write to, and until this spike nothing of
    // the repository played the migrations at all, so a clean stack needed a command typed by hand before
    // anything worked. A run with nothing to apply says so and costs nothing.
    io()->section('Schema');
    op_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);

    io()->section('Tenant');
    op_console(['beffroi:tenant:synchronize']);

    io()->section('Keys');
    // What the tenant holds is read before anything is drawn, and the key the messages are sealed to is
    // drawn before the rest: every other key announces its own staging on a transport (issue #548).
    $keys = provision_published_keys();
    $fresh = str_contains($keys, 'no published key');
    provision_key(DEV_MESSAGE_KEY_ALGORITHM);
    if ($fresh) {
        op_console(['beffroi:keys:generate']);
    } else {
        // A key is published: before trusting it, ask the KMS to open it. Vault in dev mode and LocalStack
        // forget their master key when they restart, and the envelopes sealed under it are dead; the
        // command says which key and what to do, this task deletes nothing and stops here.
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
    // The whole profile of OIDC Core §5.1, so that every scope of the Basic OP plan gets its claims
    // (tests/conformance/README.md); replayed on every run, the command clears what it does not say.
    op_console(['beffroi:user:profile', DEV_USERNAME, ...DEV_USER_PROFILE]);
    // Never on the command line: the command reads it on its standard input.
    op_console(
        ['beffroi:user:set-password', DEV_USERNAME, '--password-stdin'],
        context()->withInput($env['BEFFROI_DEV_USER_PASSWORD'] . "\n"),
    );
    $env['BEFFROI_DEV_USER_SUBJECT'] = provision_dev_subject(getcwd() . '/' . DEV_ENV_LOCAL);
    // Decision 0002: the subject of an assertion of the trusted issuer above is this user through this row
    // and through nothing else, so it is written before that issuer can name anybody ("castor demo
    // --assertion"). Replayed on every run, the command refreshes the row rather than adding one.
    op_console(['beffroi:user:link', DEV_USERNAME, DEV_DEMO_ISSUER['identity_provider'], DEV_DEMO_ISSUER['subject']]);

    // What the tenant holds to seal its personal data, shown rather than assumed (decision 0018): a data
    // key per family of columns and the index key, each minted at the first write of its family, so the
    // user created just above is what put the first ones there. Read only, and it never opens a key.
    io()->section('Data keys');
    op_console(['beffroi:data-keys:list']);

    io()->section('Client certificate');
    provision_mtls_client();

    // The migrations above may have changed the type of a column, and what was serving while they ran holds
    // the mapping it booted with (compose_restart_after_migration).
    compose_restart_after_migration();

    // Last, once everything it reads is written: a provision that ends is a worker that consumes.
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

/**
 * Generates the key of one algorithm when the tenant holds none for it. The command is the one an operator
 * runs, and what it writes is what the section shows.
 */
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
 * What the tenant holds, on one line: the console wraps its blocks, and this is searched for a sentence and
 * for an algorithm.
 */
function provision_published_keys(): string
{
    return (string) preg_replace('/\s+/', ' ', op_console(['beffroi:keys:list'], context()->withQuiet())->getOutput());
}

/**
 * The subject the provider issued the development user, published into apps/op/.env.local: what a client
 * of the FAPI-CIBA plans names its user by ("login_hint", CIBA Core §7.1, §15) and the one value of that
 * configuration no secret and no client holds. It follows the user as the keys of the conformance clients
 * follow their files: a database emptied and provisioned again is another user with another subject, and
 * the variable says what the rows say, never what an earlier run wrote.
 *
 * @param string $path apps/op/.env.local
 */
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
 * Writes the development values apps/op/.env.local lacks and returns the environment of the application
 * once they are loaded: the DSN of the KMS and the key it seals under (a sodium key generated in place or
 * written in a file of the op container, a token minted on the Vault of the stack under the policy of the
 * OP and the Transit key of the tenant, the LocalStack of the stack and the alias of the tenant), one
 * secret per client, the password of the development user. An existing value is kept, whoever wrote it:
 * the sealed signing keys depend on the KMS key, and a KMS is not switched by accident. The one exception
 * is a Vault token that no longer works (the dev server forgets everything when it restarts): a new one is
 * minted in its place, and the check of the published key says what became of the key files.
 *
 * @return array<string, string>
 */
function provision_env_local(?string $kms): array
{
    $env = load_dot_env(getcwd() . '/apps/op/.env');
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
            // The master key a rewrap moves to, under the same key id, which is what makes two clients
            // configured at once possible on this stack ("castor rewrap-live"). Only this backend writes
            // one: a second client has to hold a key under the id the deployment names, and a Transit key
            // or a KMS alias is one a container creates and not one a task generates.
            'BEFFROI_KMS_DSN_SECOND' => static fn (): string => 'sodium://?keys[signing]=' . $generate(32),
        ],
        // The same sodium backend reading <directory>/<key id><ext> (FilesystemKeyLoader): one file per
        // tenant, written in the container by this task, never in the checkout nor in the environment.
        'file' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'sodium+dir://' . KMS_FILE_DIRECTORY . '?ext=.key',
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'beffroi-{tenant}',
        ],
        // The scheme and the options of the bridge (symfony/hashicorp-vault-key-management, README): the
        // token in the user component, the mount at its default, plain HTTP for the dev server.
        'vault' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'hashicorp-vault-transit://' . vault_mint_op_token() . '@vault:8200?scheme=http',
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'beffroi-{tenant}',
        ],
        // The scheme and the options of the bridge (symfony/aws-key-management, README): the credential
        // pair in the user information, any host but "default" is a custom endpoint, plain HTTP for
        // LocalStack; the alias of the tenant is what docker/localstack/init.sh creates.
        'aws' => [
            'BEFFROI_KMS_DSN' => static fn (): string => 'aws-kms://test:test@localstack:4566?region=eu-west-3&scheme=http',
            'BEFFROI_KMS_KEY_ID' => static fn (): string => 'alias/beffroi-{tenant}',
        ],
    };
    $values['BEFFROI_DEV_USER_PASSWORD'] = static fn (): string => $generate(24);
    foreach (DEV_CLIENT_SECRETS as $name) {
        $values[$name] = static fn (): string => $generate(32);
    }

    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    if ($kms === 'file') {
        // Every run: a volume recreated with the stack has no key any more, and the check below says what
        // that did to the sealed keys; an existing key is kept.
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
    // The keys of the FAPI clients are not a value generated once into the file: the file holds the
    // public half of what var/conformance/ holds whole, so the key material is the source and the
    // variable follows it. A key generated again there is published again here, and a variable edited
    // by hand is put back to what the suite will actually sign with.
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

/**
 * Restarts the consumers of a running stack, so that they hold the values just written.
 *
 * A container reads the dotenv of the application once, when it starts. The op container is restarted by
 * whoever needs it to, and the console commands read the file each time; a worker, which runs for an
 * hour, would go on signing a logout token for a client whose secret it does not have, which is what the
 * back-channel logout plan and "castor demo --logout-others" both need. The sidecar that shares its
 * network namespace goes with it, created again and after it (compose_recreate_redirectors).
 */
function provision_restart_consumers(): void
{
    if (in_array('worker', compose_running_services(), true)) {
        run(['docker', 'compose', ...compose_profiles(), 'restart', 'worker']);
    }

    compose_recreate_redirectors(['worker']);
}

/**
 * Starts the worker and waits until it consumes, then brings up the sidecar that joins its network namespace.
 *
 * "castor start" creates the worker without starting it on a stack that names no KMS yet, the worker refusing
 * to boot without one (issue #773), so a first provision is what starts it; a worker that runs already was
 * restarted by the steps above and is only waited for. It is never created here: it carries the environment
 * "castor start" gave it (the host of the suite whose certificate it trusts, the access token format of the
 * clients of the suite), which this task does not know, and an "up" would create it again without them.
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

/**
 * The backend a KMS DSN names, by its scheme, or null when there is no DSN.
 */
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
 * Writes the key of the file backend in the op container, where the volume kms_data of compose.yaml holds
 * it for the worker too: 32 bytes of the kernel's randomness, mode 0600 in a directory 0700, the exact
 * length the sodium backend wants and nothing else in the file (FilesystemKeyLoader reads it verbatim). A
 * key that exists is kept: the sealed keys depend on it.
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

/**
 * The token of a Vault DSN: its user component.
 */
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
 * Mints the credential of the OP on the Vault of the stack: a token under the policy above, with the root
 * token of the dev server, which never reaches the OP.
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

/**
 * Whether a token still opens a session on the Vault of the stack.
 */
function vault_token_works(string $token): bool
{
    return vault_cli(['token', 'lookup'], [
        'VAULT_TOKEN' => $token,
    ])->isSuccessful();
}

/**
 * Runs the Vault CLI inside the vault container, with the root token of the dev server unless another one
 * is given; the output is captured, never shown.
 *
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
 * The certificate a test client presents to the listener that asks for one (issue #157,
 * architecture §6): one self-signed certificate on a P-256 key, with its private key, written
 * on the machine under var/mtls/. Self-signed because that is what the listener of the development stack
 * asks for and accepts: it asks without requiring and validates no chain, and RFC 8705 §2.2
 * ("self_signed_tls_client_auth") binds a token to exactly such a certificate. A deployment doing
 * "tls_client_auth" (§2.1) trusts a certificate authority at the edge instead, which is configuration of
 * the edge and not of this task.
 *
 * Replayed on every run and idempotent: an existing certificate that is still valid is kept, so that a
 * client registered under its thumbprint survives a second "castor provision".
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

/**
 * The certificate already there, when it is there with its key and has not expired; null when anything
 * of that is missing, in which case a new one is issued over it.
 */
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

/**
 * One P-256 key, the curve the development stack signs and authenticates with: ES256 is what FAPI 2
 * allows beside PS256, and a key of that curve serves a client assertion, a request object and the
 * handshake of a certificate issued on it.
 */
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
 * A certificate signed on the key given by whoever holds it, written beside its private key: what the
 * listener of the development stack asks a client for and accepts, and what RFC 8705 §2.2 authenticates a
 * client against.
 *
 * A certificate a client presents needs no name anybody checks, the listener validating no chain. One a
 * server answers with does: whoever connects verifies the host against a subject alternative name, so
 * $serverName names it, and the certificate is then its own authority as well, because what makes it
 * verifiable at all is being installed as a trust anchor where the client runs and nothing signing above
 * it.
 *
 * @param string|null $serverName the host a client will verify this certificate against, when it is a
 *                                server that answers with it
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
    // The private key of a client, even a development one, is readable by its owner and by nobody else.
    file_put_contents($keyFile, $privateKey);
    chmod($keyFile, 0o600);
    file_put_contents($certificateFile, $certificate);

    return $certificate;
}

/**
 * The section of the OpenSSL configuration the extensions of a server certificate are read from.
 */
const DEV_SERVER_CERTIFICATE_EXTENSIONS = 'beffroi_server';

/**
 * What OpenSSL has to be handed a file to be told: the extensions of a server certificate cannot be given
 * as an array, so they are written next to the certificate they are for.
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
 * The key material of the four clients of the FAPI 2 plans, in var/conformance/ and published to the
 * provider as the public half of each set (apps/op/config/packages/beffroi.yaml reads the variables of
 * DEV_FAPI_CLIENTS). Replayed on every run and idempotent: a set that is there, with its certificate
 * still valid when it carries one, is kept, so that a client the provider knows by its key survives a
 * second "castor provision".
 *
 * @param string $path apps/op/.env.local
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
 * The signing key of the attestation authority of the development stack, published to the provider as its
 * public half (RFC 7591 §2.3): the tenant pins the authority and reads no key a statement names, so what
 * this writes is the pin, and var/demo/ keeps the half the lab signs statements with.
 *
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
 * The keys of one authority of the laboratory, in var/demo/ and private halves included: the directory is
 * made when it is missing, which is the one thing the two authorities need of the machine.
 *
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
 * The public half of a set the lab holds whole: what the provider is given of an authority, and never more
 * (RFC 7517 §5).
 *
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
 * The signing key of the trusted issuer of the development stack, published to the provider as its public
 * half (RFC 7523 §3): the tenant holds the keys of an issuer it trusts and reads no key an assertion names,
 * so the registration is what this writes, and var/demo/ keeps the half the lab signs with.
 *
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
 * The keys of one rung, private halves included, read back from var/demo/<client>.jwks.json or generated
 * there: the one it signs with, and the one the provider encrypts to when the rung asks for it.
 *
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
 * The JWK of a fresh RSA key, RFC 7518 §6.3: the modulus, the exponents and the factors of the private
 * half, each the big-endian integer padded to nothing, and the identifier of RFC 7638, the thumbprint of
 * the three members of the public key in lexicographic order.
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
 * The keys already there, when the file holds the expected number of private JWK; null when anything of
 * that is missing, in which case they are all generated over.
 *
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
 * The key of one client of the FAPI 2 plans, private half included, read back from
 * var/conformance/<client>.jwks.json or generated there. A client that authenticates with a certificate
 * carries it in the "x5c" of that key (RFC 7517 §4.7) and has its PEM beside, which is what the suite
 * presents at the handshake: one key for the handshake and for what the client signs.
 *
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
 * The key already there, when the file holds one private JWK and the certificate that goes with it, when
 * there is one, is there and has not expired; null when anything of that is missing, in which case a new
 * key is generated over it.
 *
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
 * The JWK of a P-256 key, RFC 7518 §6.2: the two coordinates and the private one, each the big-endian
 * integer of the field padded to its length, and the identifier of RFC 7638, the thumbprint of the four
 * members of the public key in lexicographic order. What the key is for is said on it (RFC 7517 §4.2,
 * §4.4), a signature unless the caller asks for the encryption side.
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
 * The DER of a certificate in base64, which is what an "x5c" entry is (RFC 7517 §4.7): the body of the
 * PEM on one line, padding included, and not the base64url of a thumbprint.
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
 * Writes one variable into apps/op/.env.local, replacing the line that names it when there is one: the
 * values of the block above are generated once and kept, this one follows a file and is put back to what
 * that file says.
 *
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
 * RFC 8705 §3.1: the SHA-256 thumbprint of the DER encoding of a certificate, base64url without padding,
 * computed here from its PEM the way Beffroi\Bundle\Http\Tls\ClientCertificate computes it from what the
 * edge hands over. Two computations of the same thing, on two sides of the stack, is what "castor mtls"
 * compares.
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
