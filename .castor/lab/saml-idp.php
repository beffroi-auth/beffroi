<?php

declare(strict_types=1);

/*
 * The service provider of the stack judged by an upstream identity provider that is not this project's (sub-spike 9d,
 * issue #788): SimpleSAMLphp 2.5.3.1, from the image of the judges of 9b (tests/saml2-bindings/Interop/simplesamlphp),
 * served on https://saml-idp.localhost by the "saml-idp" service of compose.yaml behind the Caddy of op and configured
 * by docker/saml-idp/: two people, alice and bob, a persistent NameID, its responses, assertions and metadata signed by
 * a key drawn here, and the metadata of the service provider of the stack read from the provider.
 *
 * What it serves is judged before anything signs in: its metadata, fetched over https under the root of the certificate
 * of the stack, are verified by xmlsec1, which is not the provider and not SimpleSAMLphp, under the certificate they
 * publish, and read by the model the provider reads an upstream identity provider with (tests/demo/saml-idp-model.php),
 * readTrusted() and then readSigned() under the certificate drawn here.
 *
 * Then the provider federates it the way an operator federates one: the declaration of apps/op/config/packages/
 * beffroi.yaml (beffroi.saml.identity_providers, under when@dev) names the file its metadata are written to, which
 * "beffroi:saml:identity-provider:refresh" reads, its key to encrypt for is drawn (spec/saml.md S-64) and the group of
 * the tenant its mapping names is created. And the walk signs people in as a browser and a client of OpenID Connect do,
 * one request at a time: the client is oidc-demo, whose code the walk spends itself, the demonstration not being needed
 * for it. alice twice, her request over HTTP-Redirect from the address she types and over HTTP-POST from the address
 * her client hints, the first sign-in creating her and the second creating nothing; then bob, his assertion encrypted
 * for the key of this provider, and his group; then carol, whom SimpleSAMLphp signs in and refuses, its Response saying
 * AuthnFailed, which the provider answers the client access_denied for. Then what the provider refuses: the response of
 * bob posted again, and a response SimpleSAMLphp sends unasked (decision 0029). Every request of the provider is verified by the OpenSSL command
 * line and Python (the detached signature of HTTP-Redirect) or by xmlsec1 (the XML signature of HTTP-POST), every
 * response by xmlsec1, under the certificates of the metadata of their signer. Every document of a run is in
 * var/saml-idp/captured/.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;

const SAML_IDP_URL = 'https://saml-idp.localhost';

/**
 * The entity ID of the identity provider, the URL of its metadata, as docker/saml-idp/metadata/saml20-idp-hosted.php
 * names it and as the declaration of the provider is keyed.
 */
const SAML_IDP_ENTITY_ID = SAML_IDP_URL . '/simplesaml/module.php/saml/idp/metadata';

/**
 * Under the ignored var/ of the repository, mounted into the saml-idp service: the key and the certificate of the
 * identity provider, the root of the certificate of the stack it verifies the provider with, the two files that say
 * which binding it publishes and whether it encrypts, and every document of a run.
 */
const SAML_IDP_DIRECTORY = 'var/saml-idp';

const SAML_IDP_CAPTURED = SAML_IDP_DIRECTORY . '/captured';

/**
 * The metadata the declaration of the provider names, mounted at /saml-idp-metadata/ in op and the worker.
 */
const SAML_IDP_METADATA_FILE = SAML_IDP_DIRECTORY . '/metadata/idp-metadata.xml';

/**
 * The people of the identity provider and their attributes, the file its authentication source reads.
 */
const SAML_IDP_PEOPLE = 'docker/saml-idp/config/users.php';

/**
 * The group of the tenant the declaration maps the value "beffroi-admins" to, created by the walk.
 */
const SAML_IDP_GROUP = 'Administrators';

const SAML_IDP_BINDINGS = [
    'redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'post' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
];

#[AsTask(
    name: 'saml-idp',
    description: 'The service provider of the stack judged by a SimpleSAMLphp 2.5.3.1 identity provider (issue #788): the identity provider is started on https://saml-idp.localhost with a key drawn under var/saml-idp/, its metadata verified by xmlsec1 and read by the model, then federated (its metadata refreshed, its key to encrypt for drawn, the group of its mapping created); then alice signs in twice through oidc-demo, over HTTP-Redirect from the address she types and over HTTP-POST from the address her client hints, created at the first and not at the second, and bob once, his assertion encrypted, in his group; carol, whom SimpleSAMLphp refuses with the status AuthnFailed, answered access_denied and created nowhere; then the response of bob posted again and a response SimpleSAMLphp sends unasked are refused. Every request and every response verified by OpenSSL and Python or by xmlsec1',
)]
function saml_idp(
    #[AsOption(description: 'Only start the identity provider, judge its metadata and federate it: no sign-in')]
    bool $up = false,
    #[AsOption(description: 'Stop the identity provider')]
    bool $stop = false,
): void {
    if ($stop) {
        run(['docker', 'compose', '--profile', 'saml-idp', 'rm', '--stop', '--force', 'saml-idp']);

        return;
    }

    io()->title('SimpleSAMLphp 2.5.3.1, an identity provider upstream of the stack');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['BEFFROI_ISSUER', 'OIDC_DEMO_SECRET'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
            exit(1);
        }
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');

    io()->section('The identity provider');
    $ca = saml_idp_start();

    io()->section('Its metadata');
    saml_idp_metadata($ca);

    io()->section('The provider federates it');
    $serviceProvider = saml_idp_federate($issuer, $ca);
    if ($up) {
        io()->success(sprintf(
            '%s serves SimpleSAMLphp as an identity provider, which the provider federates; its metadata: %s',
            SAML_IDP_URL,
            SAML_IDP_ENTITY_ID,
        ));

        return;
    }

    $client = [
        'issuer' => $issuer,
        'ca' => $ca,
        'secret' => $env['OIDC_DEMO_SECRET'],
        'serviceProvider' => $serviceProvider,
    ];

    saml_idp_nobody_yet();

    io()->section('alice, whom the provider has never seen, over HTTP-Redirect from the address she types');
    $first = saml_idp_sign_in($client, 'alice', 'redirect', encrypted: false, hinted: false, capture: 'alice-first');
    $alice = saml_idp_person_at_the_provider('alice@idp.example');
    demo_expect(
        $alice !== null && str_contains($alice['source'], SAML_IDP_ENTITY_ID),
        sprintf(
            'alice@idp.example, whom the provider did not hold before, is created at this sign-in, by the provider she came from (%s, created %s)',
            $alice['source'] ?? '?',
            $alice['created'] ?? '?',
        ),
    );
    demo_expect($first['claims']['sub'] === $alice['subject'], 'the subject of her ID token is hers');
    saml_idp_claims('What oidc-demo received for alice', $first);

    io()->section('alice again, in another browser, over HTTP-POST from the address her client hints');
    $second = saml_idp_sign_in($client, 'alice', 'post', encrypted: false, hinted: true, capture: 'alice-second');
    $again = saml_idp_person_at_the_provider('alice@idp.example');
    demo_expect(
        $again !== null && $again['subject'] === $alice['subject'] && $again['created'] === $alice['created'] && $second['claims']['sub'] === $alice['subject'],
        sprintf('nothing is created: the same person, the same subject, created %s', $alice['created']),
    );

    io()->section('bob, his assertion encrypted for the key of this provider, and his group');
    $third = saml_idp_sign_in($client, 'bob', 'redirect', encrypted: true, hinted: false, capture: 'bob');
    $bob = saml_idp_person_at_the_provider('bob@idp.example');
    demo_expect(
        $bob !== null && str_contains($bob['source'], SAML_IDP_ENTITY_ID) && $third['claims']['sub'] === $bob['subject'],
        'bob@idp.example, whom the provider did not hold before, is created at this sign-in, the subject of his ID token',
    );
    io()->text('The groups of bob at the provider (beffroi:user:show):');
    io()->table(['Group', 'Source', 'Added'], array_map(array_values(...), $bob['groups']));
    demo_expect(
        array_map(static fn (array $membership): array => [$membership['group'], $membership['source']], $bob['groups']) === [[
            SAML_IDP_GROUP,
            'upstream_claims',
        ]],
        sprintf(
            'he is in the group "%s" of the tenant and in no other, the value "beffroi-admins" his provider asserts mapped by its declaration, a membership the claims of that provider hold (upstream_claims)',
            SAML_IDP_GROUP,
        ),
    );
    $alice = saml_idp_person_at_the_provider('alice@idp.example');
    demo_expect($alice !== null && $alice['groups'] === [], 'alice, whose provider asserts no group of hers, is in none');
    saml_idp_claims('What oidc-demo received for bob', $third);

    io()->section('carol, whom the identity provider signs in and then refuses');
    saml_idp_failed_at_the_provider($client);

    io()->section('What the provider refuses');
    saml_idp_replayed($issuer, $ca, $third);
    saml_idp_unsolicited($issuer, $ca, $third, $serviceProvider);

    io()->section('Every signature, by judges that are none of the two parties');
    saml_idp_verify_requests();
    io()->text('xmlsec1, every signature of the requests posted and of the responses, under the metadata of their signer:');
    saml_idp_xmlsec1();

    file_put_contents(SAML_IDP_DIRECTORY . '/assertion-encryption', '');
    io()->success(sprintf(
        'SimpleSAMLphp signed alice and bob in at %s through oidc-demo, over HTTP-Redirect and HTTP-POST, alice created at her first sign-in and not at her second, bob created in his group, his assertion encrypted; carol, whom it refused, answered access_denied; a response replayed and a response nobody asked for refused; every signature verified.',
        $issuer,
    ));
}

/**
 * The identity provider up, behind Caddy, with a key and a certificate of its own, drawn here and not committed, as the
 * pair of the service provider of "castor saml-sp" is not: what a development stack generates stays under var/.
 *
 * @return string the root of the certificate of the stack, with which every request of the walk verifies it
 */
function saml_idp_start(): string
{
    foreach ([SAML_IDP_DIRECTORY, SAML_IDP_CAPTURED, dirname(SAML_IDP_METADATA_FILE)] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    foreach (glob(SAML_IDP_CAPTURED . '/*') ?: [] as $file) {
        unlink($file);
    }
    // first, so that a stack that is not up is said before anything starts; read by www-data in the container, a
    // certificate and no secret
    $ca = caddy_ca(getcwd() . '/' . SAML_IDP_DIRECTORY . '/caddy-root.crt');
    chmod($ca, 0o644);
    $drawn = ! is_file(SAML_IDP_DIRECTORY . '/idp.pem') || ! is_file(SAML_IDP_DIRECTORY . '/idp.crt');
    if ($drawn) {
        run([
            'openssl',
            'req',
            '-x509',
            '-newkey',
            'rsa:3072',
            '-nodes',
            '-sha256',
            '-days',
            '3650',
            '-subj',
            '/CN=saml-idp.localhost',
            '-keyout',
            SAML_IDP_DIRECTORY . '/idp.pem',
            '-out',
            SAML_IDP_DIRECTORY . '/idp.crt',
        ], context: context()->withQuiet());
    }
    // Its owner's alone: the container reads it as root and hands www-data a copy of its own (compose.yaml).
    chmod(SAML_IDP_DIRECTORY . '/idp.pem', 0o600);
    // both bindings published, nothing encrypted, until a journey says otherwise
    file_put_contents(SAML_IDP_DIRECTORY . '/sso-binding', '');
    file_put_contents(SAML_IDP_DIRECTORY . '/assertion-encryption', '');
    // A container that copied the key of an earlier pair holds it until it is created again.
    run(['docker', 'compose', '--profile', 'saml-idp', 'up', '-d', '--wait', '--build', ...($drawn ? ['--force-recreate'] : []), 'saml-idp']);

    $cookies = [];
    for ($attempt = 0; $attempt < 30; ++$attempt) {
        try {
            [$status] = demo_request($cookies, $ca, 'GET', SAML_IDP_ENTITY_ID);
        } catch (HttpClientException) {
            $status = 0;
        }
        if ($status === 200) {
            io()->text(sprintf(' <info>✓</info> %s answers through the Caddy of op', SAML_IDP_ENTITY_ID));

            return $ca;
        }
        sleep(1);
    }
    io()->error(sprintf('%s does not answer: "docker compose --profile saml-idp logs saml-idp" says why.', SAML_IDP_ENTITY_ID));
    exit(1);
}

/**
 * The metadata of the identity provider, over https under the certificate of the stack, captured, then judged by
 * xmlsec1 and by the model.
 */
function saml_idp_metadata(string $ca): void
{
    $cookies = [];
    [$status, , $document, $headers] = demo_request($cookies, $ca, 'GET', SAML_IDP_ENTITY_ID);
    demo_expect(
        $status === 200 && ($headers['content-type'][0] ?? '') === 'application/samlmetadata+xml',
        sprintf(
            '%s serves the metadata of the identity provider, application/samlmetadata+xml, over https under the certificate of the stack',
            SAML_IDP_ENTITY_ID,
        ),
    );
    file_put_contents(SAML_IDP_CAPTURED . '/idp-metadata.xml', $document);

    io()->text('xmlsec1, the signature of the metadata under the certificate they publish:');
    in_alpine(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh '
        . SAML_IDP_CAPTURED
        . ' "idp-metadata.xml"',
        ['tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh', SAML_IDP_CAPTURED],
    );

    io()->text('The model, as the provider reads an upstream identity provider:');
    saml_sp_in_phpqa('tests/demo/saml-idp-model.php', SAML_IDP_DIRECTORY);
}

/**
 * The identity provider federated the way an operator federates one: its key to encrypt for drawn when the tenant holds
 * none (spec/saml.md S-64), the group its mapping names created, its metadata written to the file the declaration names
 * and read by "beffroi:saml:identity-provider:refresh"; then the metadata of the service provider for it, which the
 * provider serves to it alone (S-65), read as SimpleSAMLphp reads them.
 *
 * @return array{entityId: string, acs: string} the service provider of the tenant, as its metadata name it
 */
function saml_idp_federate(string $issuer, string $ca): array
{
    provision_key('SAML-ENCRYPTION:' . SAML_IDP_ENTITY_ID);
    $group = op_console(['beffroi:group:create', SAML_IDP_GROUP, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect(
        $group->isSuccessful() || str_contains($group->getOutput() . $group->getErrorOutput(), 'already'),
        sprintf('the tenant holds the group "%s" (beffroi:group:create)', SAML_IDP_GROUP),
    );
    saml_idp_publish('', $ca);

    $cookies = [];
    $segment = rtrim(strtr(base64_encode(SAML_IDP_ENTITY_ID), '+/', '-_'), '=');
    $url = $issuer . '/saml/sp/metadata/' . $segment;
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $url);
    demo_expect($status === 200, sprintf('the provider serves the metadata of its service provider for this identity provider at %s (got %d)', $url, $status));
    file_put_contents(SAML_IDP_CAPTURED . '/sp-metadata.xml', $document);
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $acs = (string) $xpath->evaluate('string(/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location)');
    $encryption = (int) $xpath->evaluate('count(/md:EntityDescriptor/md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"])');
    demo_expect(
        $entityId === $issuer . '/saml/sp/metadata' && $acs === $issuer . '/saml/sp/acs' && $encryption >= 1,
        sprintf('the service provider %s, its assertion consumer service %s, a certificate to encrypt for (%d)', $entityId, $acs, $encryption),
    );
    $signing =
        preg_replace(
            '/\s+/',
            '',
            (string) $xpath->evaluate('string(/md:EntityDescriptor/md:SPSSODescriptor/md:KeyDescriptor[@use="signing"]//ds:X509Certificate)'),
        ) ?? '';
    file_put_contents(
        SAML_IDP_CAPTURED . '/sp-signing.crt',
        "-----BEGIN CERTIFICATE-----\n" . chunk_split($signing, 64, "\n") . "-----END CERTIFICATE-----\n",
    );

    return [
        'entityId' => $entityId,
        'acs' => $acs,
    ];
}

/**
 * The metadata of the identity provider as it serves them with one binding of its single sign-on service, or both,
 * written to the file the declaration names and read by the provider: it sends its request over HTTP-Redirect whenever
 * the metadata list it (spec/saml.md S-48), so HTTP-POST is played from metadata that list it alone, which the
 * identity provider itself publishes (docker/saml-idp/metadata/saml20-idp-hosted.php), and not from a document edited.
 *
 * @param ''|'redirect'|'post' $binding
 */
function saml_idp_publish(string $binding, string $ca): void
{
    file_put_contents(SAML_IDP_DIRECTORY . '/sso-binding', $binding);
    $cookies = [];
    [$status, , $document] = demo_request($cookies, $ca, 'GET', SAML_IDP_ENTITY_ID);
    demo_expect($status === 200, sprintf('the identity provider serves its metadata (got %d)', $status));
    file_put_contents(SAML_IDP_METADATA_FILE, $document);
    $refresh = op_console(['beffroi:saml:identity-provider:refresh', SAML_IDP_ENTITY_ID, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect(
        $refresh->isSuccessful(),
        sprintf(
            'the provider reads them (beffroi:saml:identity-provider:refresh), its single sign-on service on %s%s',
            $binding === '' ? 'both bindings' : SAML_IDP_BINDINGS[$binding],
            $refresh->isSuccessful() ? '' : ': ' . trim($refresh->getOutput() . $refresh->getErrorOutput()),
        ),
    );
}

/**
 * The walk proves that a first sign-in creates a person, and that the group of bob is the mapping's, which a database
 * that holds one of the three people already cannot show: no command deletes a person, so a run on such a database is
 * refused, with how to empty it, rather than taken for a proof.
 */
function saml_idp_nobody_yet(): void
{
    $held = array_values(array_filter(
        ['alice@idp.example', 'bob@idp.example', 'carol@idp.example'],
        static fn (string $address): bool => saml_idp_person_at_the_provider($address) !== null,
    ));
    if ($held === []) {
        io()->text(' <info>✓</info> the provider holds none of the people of the identity provider yet');

        return;
    }
    $project = preg_replace('/[^a-z0-9_-]/', '', strtolower(basename((string) getcwd())));
    io()->error([
        sprintf('The provider holds %s already, from an earlier run on this database: a sign-in cannot be shown to create a person there, nor a group to come from the mapping.', implode(
            ', ',
            $held,
        )),
        sprintf(
            'Empty the database first: castor stop, docker volume rm %s_database_data, castor start, castor provision; then run "castor saml-idp" again.',
            $project,
        ),
    ]);
    exit(1);
}

/**
 * What the provider holds of a person, from "beffroi:user:show", the username of a person an upstream provider created
 * being their address: null when it holds nobody of that name.
 *
 * @return array{subject: string, created: string, source: string, groups: list<array{group: string, source: string, added: string}>}|null
 */
function saml_idp_person_at_the_provider(string $username): ?array
{
    $shown = op_console(['beffroi:user:show', $username, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    if (! $shown->isSuccessful()) {
        return null;
    }
    $output = $shown->getOutput();
    $read = static fn (string $name): string => preg_match(sprintf('/^\s*%s\s{2,}(.+?)\s*$/m', preg_quote($name, '/')), $output, $matches) === 1
        ? $matches[1]
        : '';
    // the table of the section "Groups", one row per membership: the name of the group, the source of the membership
    // (local, upstream_claims or scim, the core's GroupSource) and when it was added; the section says "The user is in
    // no group." otherwise
    $groups = [];
    $section = (string) preg_replace('/\A.*?^\s*Groups\s*$/ms', '', $output, 1);
    preg_match_all('/^\s*(\S.*?)\s{2,}(local|upstream_claims|scim)\s{2,}(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*$/m', $section, $rows, \PREG_SET_ORDER);
    foreach ($rows as $row) {
        $groups[] = [
            'group' => $row[1],
            'source' => $row[2],
            'added' => $row[3],
        ];
    }

    return [
        'subject' => $read('Subject'),
        'created' => $read('Created'),
        'source' => $read('Source'),
        'groups' => $groups,
    ];
}

/**
 * A person of the identity provider, from the file its authentication source reads: their password, which goes into
 * the form of SimpleSAMLphp and nowhere else, and the attributes it asserts of them.
 *
 * @return array{password: string, attributes: array<string, list<string>>}
 */
function saml_idp_person(string $username): array
{
    /** @var array<string, array<string, list<string>>> $people */
    $people = require SAML_IDP_PEOPLE;
    foreach ($people as $credentials => $attributes) {
        [$name, $password] = explode(':', $credentials, 2) + [1 => ''];
        if ($name === $username) {
            return [
                'password' => $password,
                'attributes' => $attributes,
            ];
        }
    }
    io()->error(sprintf('%s holds no person "%s".', SAML_IDP_PEOPLE, $username));
    exit(1);
}

/**
 * One sign-in through the identity provider, in a browser of its own: oidc-demo asks for an authorization, the login
 * page of the provider asks for the address first (spec/saml.md S-61), or skips it for the address the client hints
 * (S-62), and sends the browser to the sign-on of this provider (S-51), whose AuthnRequest goes over the binding the
 * metadata the provider holds publish; SimpleSAMLphp signs the person in and posts its Response from its site to the
 * assertion consumer service, which posts it again from its own origin (S-52), takes it (S-53) and resumes the
 * authorization (S-59); the client gets its code, spends it, and reads UserInfo.
 *
 * @param array{issuer: string, ca: string, secret: string, serviceProvider: array{entityId: string, acs: string}} $client
 * @param 'redirect'|'post' $binding
 * @return array{claims: array<string, mixed>, userinfo: array<string, mixed>, cookies: array<string, array<string, string>>, acs: array{action: string, fields: array<string, string>}}
 */
function saml_idp_sign_in(array $client, string $username, string $binding, bool $encrypted, bool $hinted, string $capture): array
{
    ['issuer' => $issuer, 'ca' => $ca] = $client;
    $person = saml_idp_person($username);
    $address = $person['attributes']['mail'][0] ?? '';
    saml_idp_publish($binding, $ca);
    file_put_contents(SAML_IDP_DIRECTORY . '/assertion-encryption', $encrypted ? 'yes' : '');
    $cookies = [];
    $asked = saml_idp_ask($client, $cookies, $address, $binding, $hinted, $capture);
    ['login' => $login, 'state' => $state, 'nonce' => $nonce, 'verifier' => $verifier] = $asked;

    // SimpleSAMLphp signs the person in
    [$status, $location, $page] = saml_idp_log_in($cookies, $ca, $asked['status'], $asked['location'], $username, $person['password']);
    demo_expect($status === 200, sprintf(
        '%s signs in at SimpleSAMLphp, which answers with the page that posts its Response (got %d %s)',
        $username,
        $status,
        substr($location, 0, 120),
    ));
    $acs = saml_sp_page_form($page);
    demo_expect(
        $acs['action'] === $client['serviceProvider']['acs'] && isset($acs['fields']['SAMLResponse'], $acs['fields']['RelayState']),
        sprintf('which posts SAMLResponse and the RelayState to the assertion consumer service of the provider (it posts to %s)', $acs['action']),
    );
    $response = (string) base64_decode($acs['fields']['SAMLResponse'], true);
    file_put_contents(SAML_IDP_CAPTURED . '/' . $capture . '-response.xml', $response);
    saml_idp_response_on_the_wire($response, $encrypted);

    // the assertion consumer service, posted from the site of SimpleSAMLphp, then from the origin of the provider
    $again = saml_sp_posted_from_another_site($acs['action'], $acs['fields'], $ca);
    [$status, $location, $page] = demo_request($cookies, $ca, 'POST', $again['url'], $again['fields']);
    parse_str((string) parse_url($login, \PHP_URL_QUERY), $interaction);
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login?') && str_contains($location, 'interaction=' . ($interaction['interaction'] ?? '?')),
        sprintf(
            'the provider takes the response and sends the browser back to the login page of the interaction, which resumes it (got %d %s%s)',
            $status,
            substr($location, 0, 120),
            preg_match('/data-description><code>[^<]*<\/code>: ([^<]+)/', $page, $refusal) === 1 ? ': ' . html_entity_decode($refusal[1]) : '',
        ),
    );

    // the authorization answered, the code spent
    [$status, $location] = demo_resume($cookies, $ca, $issuer, $location);
    demo_expect(
        $status === 302 && str_starts_with($location, DEMO_URL . '/oidc/callback?'),
        sprintf('the provider sends the browser to the callback of oidc-demo (got %d %s)', $status, substr($location, 0, 120)),
    );
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(
        isset($callback['code']) && ($callback['state'] ?? null) === $state && ($callback['iss'] ?? null) === $issuer,
        'with a code, its state and iss',
    );
    $tokens = demo_exchange_code($issuer, $ca, DEMO_CLIENT_ID, $client['secret'], (string) $callback['code'], DEMO_URL . '/oidc/callback', $verifier);
    $claims = demo_jwt((string) ($tokens['id_token'] ?? ''))['claims'];
    demo_expect(($claims['nonce'] ?? null) === $nonce && ($claims['aud'] ?? null) === DEMO_CLIENT_ID, 'an ID token for oidc-demo, its nonce');
    $userinfo = http_request('GET', $issuer . '/userinfo', [
        'cafile' => $ca,
        'auth_bearer' => (string) ($tokens['access_token'] ?? ''),
    ]);
    demo_expect($userinfo->getStatusCode() === 200, sprintf('UserInfo answers its access token (got %d)', $userinfo->getStatusCode()));
    $described = (array) json_decode($userinfo->getContent(false), true, 8, \JSON_THROW_ON_ERROR);
    demo_expect(
        ($described['email'] ?? null) === $address
        && ($described['given_name'] ?? null) === ($person['attributes']['givenName'][0] ?? null)
        && ($described['family_name'] ?? null) === ($person['attributes']['sn'][0] ?? null),
        sprintf('UserInfo says the address, the given name and the family name the identity provider asserted, %s', $address),
    );

    return [
        'claims' => $claims,
        'userinfo' => $described,
        'cookies' => $cookies,
        'acs' => $acs,
    ];
}

/**
 * The half of a sign-in before the identity provider signs anybody in: oidc-demo asks for an authorization, the login
 * page of the provider asks for the address first (spec/saml.md S-61), or skips it for the address the client hints
 * (S-62), and sends the browser to the sign-on of this provider (S-51), whose AuthnRequest goes over the binding the
 * metadata the provider holds publish, captured. Returned is what the client holds and what SimpleSAMLphp answered.
 *
 * @param array{issuer: string, ca: string, secret: string, serviceProvider: array{entityId: string, acs: string}} $client
 * @param array<string, array<string, string>> $cookies host => name => value
 * @param 'redirect'|'post' $binding
 * @return array{login: string, state: string, nonce: string, verifier: string, status: int, location: string, page: string}
 */
function saml_idp_ask(array $client, array &$cookies, string $address, string $binding, bool $hinted, string $capture): array
{
    ['issuer' => $issuer, 'ca' => $ca] = $client;

    // the client
    $base64url = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    $verifier = $base64url(random_bytes(32));
    $state = $base64url(random_bytes(16));
    $nonce = $base64url(random_bytes(16));
    $authorization =
        $issuer
        . '/authorize?'
        . http_build_query([
            'response_type' => 'code',
            'client_id' => DEMO_CLIENT_ID,
            'redirect_uri' => DEMO_URL . '/oidc/callback',
            'scope' => 'openid profile email',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $base64url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            ...($hinted ? ['login_hint' => $address] : []),
        ]);
    [$status, $location] = demo_request($cookies, $ca, 'GET', $authorization);
    demo_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login?interaction='),
        sprintf('oidc-demo asks for an authorization, and the provider asks for a login (got %d %s)', $status, substr($location, 0, 120)),
    );
    $login = $location;
    $signOn = $issuer . '/saml/sp/sign-on?';

    // the login page, its address first
    if ($hinted) {
        [$status, $location] = demo_request($cookies, $ca, 'GET', $login);
        demo_expect(
            $status === 302 && str_starts_with($location, $signOn),
            sprintf(
                'the login page skips itself for the address the client hints, %s, and sends the browser to the sign-on of its provider (got %d %s)',
                $address,
                $status,
                substr($location, 0, 120),
            ),
        );
    } else {
        [$status, , $page] = demo_request($cookies, $ca, 'GET', $login);
        $form = $status === 200 ? demo_form_with($page, '_address', 'the login page asks for the address first') : '';
        demo_expect(
            ! str_contains($page, 'name="_password"')
            && preg_match('/name="_token" value="([^"]+)"/', $form, $token) === 1
            && preg_match('/action="([^"]+)"/', $form, $action) === 1,
            'and for nothing else, no password: one field, its token, where it posts',
        );
        [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
            '_address' => $address,
            '_token' => $token[1],
        ]);
        demo_expect(
            $status === 303 && str_starts_with($location, $signOn),
            sprintf('%s, of a federated domain, is sent to the sign-on of its provider (got %d %s)', $address, $status, substr($location, 0, 120)),
        );
    }
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $query);
    demo_expect(($query['identity_provider'] ?? null) === SAML_IDP_ENTITY_ID, sprintf('of %s', SAML_IDP_ENTITY_ID));
    // spec/saml.md S-51: the one-time reference the login page drew, without which the sign-on starts nothing
    demo_expect(
        is_string($query['reference'] ?? null) && preg_match('/^[A-Za-z0-9_-]{43}$/', $query['reference']) === 1,
        'under the one-time reference the login page drew for that sign-on',
    );

    // the AuthnRequest, over the binding the metadata publish
    [$status, $location, $page] = demo_request($cookies, $ca, 'GET', $location);
    $sso = SAML_IDP_URL . '/simplesaml/module.php/saml/idp/singleSignOnService';
    if ($binding === 'redirect') {
        demo_expect(
            $status === 302 && str_starts_with($location, $sso . '?'),
            sprintf(
                'the sign-on sends the browser to the single sign-on service of SimpleSAMLphp over HTTP-Redirect (got %d %s)',
                $status,
                substr($location, 0, 120),
            ),
        );
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $request);
        demo_expect(
            isset($request['SAMLRequest'], $request['RelayState'], $request['SigAlg'], $request['Signature']),
            'its request signed over the query string, with a RelayState',
        );
        file_put_contents(SAML_IDP_CAPTURED . '/' . $capture . '-authn-request.url', $location);
        file_put_contents(
            SAML_IDP_CAPTURED . '/' . $capture . '-authn-request.xml',
            (string) gzinflate((string) base64_decode((string) $request['SAMLRequest'], true)),
        );
        [$status, $location, $page] = demo_request($cookies, $ca, 'GET', $location);
    } else {
        demo_expect($status === 200, sprintf(
            'the sign-on answers with the page that posts the request over HTTP-POST (got %d %s)',
            $status,
            substr($location, 0, 120),
        ));
        $form = saml_sp_page_form(demo_form_with($page, 'SAMLRequest', 'a form carrying SAMLRequest'));
        demo_expect(
            $form['action'] === $sso && isset($form['fields']['SAMLRequest'], $form['fields']['RelayState']),
            sprintf('which posts it with a RelayState to the single sign-on service of SimpleSAMLphp (it posts to %s)', $form['action']),
        );
        $request = (string) base64_decode($form['fields']['SAMLRequest'], true);
        file_put_contents(SAML_IDP_CAPTURED . '/' . $capture . '-authn-request.xml', $request);
        $dom = new DOMDocument();
        demo_expect($dom->loadXML($request), 'the request is well-formed XML');
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        demo_expect((int) $xpath->evaluate('count(/samlp:AuthnRequest/ds:Signature)') === 1, 'its request signed in its XML');
        [$status, $location, $page] = demo_request($cookies, $ca, 'POST', $form['action'], $form['fields']);
    }

    return [
        'login' => $login,
        'state' => $state,
        'nonce' => $nonce,
        'verifier' => $verifier,
        'status' => $status,
        'location' => $location,
        'page' => $page,
    ];
}

/**
 * The login of SimpleSAMLphp, from its answer to a request: its form opened, the username and the password posted, its
 * redirections on its own site followed. Returned is where that leaves the browser.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @return array{int, string, string} status, Location, body
 */
function saml_idp_log_in(array &$cookies, string $ca, int $status, string $location, string $username, string $password): array
{
    demo_expect(
        in_array($status, [302, 303], true) && str_starts_with($location, SAML_IDP_URL . '/simplesaml/module.php/core/loginuserpass'),
        sprintf('SimpleSAMLphp accepts the request and asks for a login (got %d %s)', $status, substr($location, 0, 120)),
    );
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200 && preg_match('/<form\b[^>]*\baction="([^"]+)"/i', $page, $action) === 1, 'its login form opens');
    [$status, $location, $page] = demo_request($cookies, $ca, 'POST', html_entity_decode($action[1]), [
        'username' => $username,
        'password' => $password,
    ]);
    for ($hops = 0; in_array($status, [302, 303], true) && str_starts_with($location, SAML_IDP_URL) && $hops < 5; ++$hops) {
        [$status, $location, $page] = demo_request($cookies, $ca, 'GET', $location);
    }

    return [$status, $location, $page];
}

/**
 * The Response as SimpleSAMLphp sent it: signed, its assertion signed too and named by a persistent NameID when it is in
 * clear; encrypted for the key the provider gave this identity provider alone (spec/saml.md S-64, S-65), its session
 * key under rsa-oaep-mgf1p and its content under aes128-cbc, which the provider opens only because the signature of the
 * Response covers it (decision 0013), when it was asked to encrypt.
 */
function saml_idp_response_on_the_wire(string $response, bool $encrypted): void
{
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($response), 'the Response is well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    demo_expect((int) $xpath->evaluate('count(/samlp:Response/ds:Signature)') === 1, 'the Response is signed');
    if (! $encrypted) {
        demo_expect(
            (int) $xpath->evaluate('count(/samlp:Response/saml:Assertion/ds:Signature)') === 1
            && (string) $xpath->evaluate('string(/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@Format)')
                === 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'its assertion, in clear, is signed and names the person by a persistent NameID',
        );

        return;
    }
    demo_expect(
        (int) $xpath->evaluate('count(/samlp:Response/saml:EncryptedAssertion)') === 1 && (int) $xpath->evaluate('count(//saml:Assertion)') === 0,
        'its assertion is encrypted: one saml:EncryptedAssertion, no saml:Assertion in clear',
    );
    $content = (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)');
    $key =
        (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)');
    demo_expect(
        $content === 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' && $key === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
        sprintf('under %s, its key under %s', $content, $key),
    );
}

/**
 * The ID token and UserInfo of a sign-in, as the client received them.
 *
 * @param array{claims: array<string, mixed>, userinfo: array<string, mixed>} $signedIn
 */
function saml_idp_claims(string $title, array $signedIn): void
{
    $rows = [];
    foreach (['sub', 'auth_time', 'amr', 'acr'] as $claim) {
        if (isset($signedIn['claims'][$claim])) {
            $rows[] = [
                'ID token',
                $claim,
                is_array($signedIn['claims'][$claim]) ? implode(' ', $signedIn['claims'][$claim]) : (string) $signedIn['claims'][$claim],
            ];
        }
    }
    foreach ($signedIn['userinfo'] as $claim => $value) {
        $rows[] = ['UserInfo', $claim, is_scalar($value) ? var_export($value, true) : (string) json_encode($value)];
    }
    io()->text($title . ':');
    io()->table(['', 'Claim', 'Value'], $rows);
}

/**
 * carol signs in at SimpleSAMLphp, which then refuses her (docker/saml-idp/metadata/saml20-idp-hosted.php): at her login
 * it shows its own error page and posts nothing; the next request the provider sends in the same browser finds her
 * signed in there and is answered with a Response whose status is Responder and AuthnFailed, with no assertion. The
 * assertion consumer service reads that status as the person authenticated by nobody and answers the client
 * access_denied at its redirection URI with its state (spec/saml.md S-58), creating nobody.
 *
 * @param array{issuer: string, ca: string, secret: string, serviceProvider: array{entityId: string, acs: string}} $client
 */
function saml_idp_failed_at_the_provider(array $client): void
{
    ['issuer' => $issuer, 'ca' => $ca] = $client;
    $person = saml_idp_person('carol');
    $address = $person['attributes']['mail'][0] ?? '';
    saml_idp_publish('redirect', $ca);
    file_put_contents(SAML_IDP_DIRECTORY . '/assertion-encryption', '');
    $cookies = [];

    $asked = saml_idp_ask($client, $cookies, $address, 'redirect', false, 'carol-first');
    [$status, , $page] = saml_idp_log_in($cookies, $ca, $asked['status'], $asked['location'], 'carol', $person['password']);
    demo_expect(
        $status >= 400 && str_contains($page, 'The laboratory identity provider refuses carol.') && ! str_contains($page, 'SAMLResponse'),
        sprintf('carol signs in at SimpleSAMLphp, which refuses her on its error page, saying why, and posts nothing (got %d)', $status),
    );

    $asked = saml_idp_ask($client, $cookies, $address, 'redirect', false, 'carol');
    ['status' => $status, 'location' => $location, 'page' => $page] = $asked;
    for ($hops = 0; in_array($status, [302, 303], true) && str_starts_with($location, SAML_IDP_URL) && $hops < 5; ++$hops) {
        [$status, $location, $page] = demo_request($cookies, $ca, 'GET', $location);
    }
    demo_expect($status === 200, sprintf(
        'the next request finds her signed in at SimpleSAMLphp, which answers it without a login (got %d %s)',
        $status,
        substr($location, 0, 120),
    ));
    $acs = saml_sp_page_form($page);
    demo_expect(
        $acs['action'] === $client['serviceProvider']['acs'] && isset($acs['fields']['SAMLResponse'], $acs['fields']['RelayState']),
        sprintf('with a page that posts SAMLResponse and the RelayState to the assertion consumer service of the provider (it posts to %s)', $acs['action']),
    );
    $response = (string) base64_decode($acs['fields']['SAMLResponse'], true);
    file_put_contents(SAML_IDP_CAPTURED . '/carol-response.xml', $response);
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($response), 'the Response is well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    demo_expect((int) $xpath->evaluate('count(/samlp:Response/ds:Signature)') === 1, 'the Response is signed');
    $status = (string) $xpath->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/@Value)');
    $second = (string) $xpath->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value)');
    demo_expect(
        $status === 'urn:oasis:names:tc:SAML:2.0:status:Responder'
        && $second === 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
        && (int) $xpath->evaluate('count(//saml:Assertion) + count(//saml:EncryptedAssertion)') === 0,
        sprintf('its status is not Success, %s and %s, and it carries no assertion', $status, $second),
    );

    $again = saml_sp_posted_from_another_site($acs['action'], $acs['fields'], $ca);
    [$status, $location, $page] = demo_request($cookies, $ca, 'POST', $again['url'], $again['fields']);
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(
        $status === 302
        && str_starts_with($location, DEMO_URL . '/oidc/callback?')
        && ($callback['error'] ?? null) === 'access_denied'
        && ($callback['state'] ?? null) === $asked['state']
        && ($callback['iss'] ?? null) === $issuer
        && ! isset($callback['code']),
        sprintf(
            'the provider answers the client access_denied at its redirection URI, with its state and no code (got %d %s%s)',
            $status,
            substr($location, 0, 160),
            preg_match('/data-description><code>[^<]*<\/code>: ([^<]+)/', $page, $refusal) === 1 ? ': ' . html_entity_decode($refusal[1]) : '',
        ),
    );
    demo_expect(saml_idp_person_at_the_provider($address) === null, sprintf('and holds nobody named %s', $address));
}

/**
 * The Response of a sign-in posted again by the browser that posted it, from the origin of the provider and with its
 * cookies: the entry its RelayState named was forgotten when it was read (spec/saml.md S-53), so the second post finds
 * nothing and is refused before the response is read.
 *
 * @param array{cookies: array<string, array<string, string>>, acs: array{action: string, fields: array<string, string>}} $signedIn
 */
function saml_idp_replayed(string $issuer, string $ca, array $signedIn): void
{
    $cookies = $signedIn['cookies'];
    [$status, , $page] = demo_request($cookies, $ca, 'POST', $signedIn['acs']['action'] . '?' . SAML_POSTED_AGAIN . '=1', $signedIn['acs']['fields']);
    saml_idp_refused($status, $page, 'the Response of bob posted again by his browser is refused, its RelayState naming nothing any more');
}

/**
 * A Response SimpleSAMLphp sends unasked, its sign-on started at the identity provider for the service provider of the
 * tenant (Profiles §4.1.5), in the browser of bob, who is signed in there: it answers no request, carries no
 * InResponseTo and no RelayState the provider remembers, and is refused (decision 0029, spec/saml.md S-53).
 *
 * @param array{cookies: array<string, array<string, string>>} $signedIn
 * @param array{entityId: string, acs: string} $serviceProvider
 */
function saml_idp_unsolicited(string $issuer, string $ca, array $signedIn, array $serviceProvider): void
{
    file_put_contents(SAML_IDP_DIRECTORY . '/assertion-encryption', '');
    $cookies = [
        parse_url(SAML_IDP_URL, \PHP_URL_HOST) => $signedIn['cookies'][parse_url(SAML_IDP_URL, \PHP_URL_HOST)] ?? [],
    ];
    $url = SAML_IDP_URL . '/simplesaml/module.php/saml/idp/singleSignOnService?' . http_build_query(['spentityid' => $serviceProvider['entityId']]);
    [$status, $location, $page] = demo_request($cookies, $ca, 'GET', $url);
    demo_expect(
        $status === 200,
        sprintf(
            'SimpleSAMLphp starts a sign-on of its own for the service provider of the tenant, from the session of bob (got %d %s)',
            $status,
            substr($location, 0, 120),
        ),
    );
    $acs = saml_sp_page_form($page);
    demo_expect(
        $acs['action'] === $serviceProvider['acs'] && isset($acs['fields']['SAMLResponse']),
        sprintf('and posts a Response nobody asked for to the assertion consumer service of the provider (it posts to %s)', $acs['action']),
    );
    $response = (string) base64_decode($acs['fields']['SAMLResponse'], true);
    file_put_contents(SAML_IDP_CAPTURED . '/unsolicited-response.xml', $response);
    demo_expect(! str_contains($response, 'InResponseTo='), 'which answers no request: no InResponseTo');
    saml_idp_response_on_the_wire($response, false);
    $again = saml_sp_posted_from_another_site($acs['action'], $acs['fields'], $ca);
    [$status, , $page] = demo_request($cookies, $ca, 'POST', $again['url'], $again['fields']);
    saml_idp_refused($status, $page, 'the provider refuses it, no request of this browser naming it (decision 0029)');
}

/**
 * The page of a refusal of the assertion consumer service, and the rule it gives, which names no value (M-16).
 */
function saml_idp_refused(int $status, string $page, string $what): void
{
    $description = preg_match('/data-description><code>[^<]*<\/code>: ([^<]+)/', $page, $matches) === 1 ? html_entity_decode($matches[1]) : '';
    demo_expect(
        $status === 400 && str_contains($page, 'data-error="saml_assertion_refused"'),
        sprintf('%s (got %d%s)', $what, $status, $description === '' ? '' : ': ' . $description),
    );
}

/**
 * The AuthnRequests the provider sent over HTTP-Redirect, by the OpenSSL command line and Python's zlib, the oracle of
 * saml2-bindings, under the signing certificate of the metadata of its service provider: the signature over the query
 * string and the document it carries.
 */
function saml_idp_verify_requests(): void
{
    $urls = glob(SAML_IDP_CAPTURED . '/*-authn-request.url') ?: [];
    if ($urls === []) {
        return;
    }
    io()->text('OpenSSL and Python, the signature of the requests over the query string and the document each carries:');
    in_alpine(
        'apk add -q openssl python3 >/dev/null 2>&1 && openssl version && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
            . SAML_IDP_CAPTURED
            . '/sp-signing.crt '
            . implode(' ', array_map(escapeshellarg(...), $urls)),
        [SAML_SP_ORACLE_REDIRECT, SAML_IDP_CAPTURED],
    );
}

/**
 * xmlsec1 on every XML signature of the documents captured, each under the certificate of the metadata of its signer,
 * both metadata among them (tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh): the request posted under the
 * service provider of the tenant, every Response and every assertion in clear under the identity provider; the signature
 * of an encrypted assertion is inside its ciphertext, which only the provider opens, so the signature of its Response,
 * over that ciphertext, is the one verified. The script lists and skips a document that carries no XML signature, which
 * two kinds of document may be and no other: a request redirected, whose signature is over its query string and which
 * OpenSSL verified (saml_idp_verify_requests()), and the metadata of the service provider, which the provider does not
 * sign. Any other document skipped lost its signature, and fails the walk.
 */
function saml_idp_xmlsec1(): void
{
    $run = run(alpine_command(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh '
        . SAML_IDP_CAPTURED
        . ' "*.xml"',
        ['tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh', SAML_IDP_CAPTURED],
    ), context: context()->withQuiet()->withAllowFailure());
    io()->write($run->getOutput());
    demo_expect($run->isSuccessful(), 'xmlsec1 verifies every signature it finds');
    preg_match_all('/^SKIP (\S+): no XML signature$/m', $run->getOutput(), $skipped);
    $unsigned = array_values(array_filter(
        $skipped[1],
        static fn (string $file): bool => (
            $file !== 'sp-metadata.xml'
            && ! (str_ends_with($file, '-authn-request.xml') && is_file(SAML_IDP_CAPTURED . '/' . substr($file, 0, -4) . '.url'))
        ),
    ));
    demo_expect(
        $unsigned === [],
        sprintf('and no document that has to be signed came without its signature%s', $unsigned === [] ? '' : ': ' . implode(', ', $unsigned)),
    );
}
