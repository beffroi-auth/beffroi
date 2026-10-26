<?php

declare(strict_types=1);

/*
 * The SAML identity provider of the stack judged by a service provider that is not this project's (sub-spike 9c, issue
 * #732): SimpleSAMLphp 2.5.3.1, the service provider of the judges of 9b (tests/saml2-bindings/Interop/simplesamlphp),
 * served on https://saml-sp.localhost by the "saml-sp" service of compose.yaml behind the Caddy of op, configured with
 * the metadata the stack serves and nothing else (docker/saml-sp/), and registered at the provider the way an
 * operator registers one: its metadata given as a file the development configuration declares
 * (apps/op/config/packages/beffroi.yaml, beffroi.saml.service_providers) and read by "beffroi:saml:service-provider:refresh".
 *
 * Three things judge what the walk captures, none of them the provider and none of them SimpleSAMLphp's reading of
 * itself: xmlsec1 on every XML signature (the AuthnRequest posted, the Response), the OpenSSL command line and Python's
 * zlib on the signature and the message of the AuthnRequest redirected, which carries a detached signature over the
 * query string and none in the XML (the oracles of 9b), and the model of the packages the provider is built on, which
 * receives and validates each AuthnRequest as the single sign-on service has to (tests/demo/saml-sp-model.php).
 *
 * The walk is the browser, as the walks of demo.php are: one request at a time, no redirect followed, a cookie jar per
 * host, the page of the provider read with the eyes of a person. Every document it captures goes to var/saml-sp/captured/.
 *
 * With --encrypted (issue #733, spec/saml.md S-19 to S-21), the walk plays the second service provider of the same
 * SimpleSAMLphp, "beffroi-encrypted": its configuration sets "assertion.encryption", so that it refuses an assertion in
 * clear, and its declaration in apps/op/config/packages/beffroi.yaml sets "encrypt_assertions". The Response captured is
 * checked to carry its assertion encrypted, under aes256-gcm and rsa-oaep-mgf1p and nothing in CBC; xmlsec1 decrypts it
 * under var/saml-sp/sp.pem, and the assertion it gives back joins the documents saml_sp_verify_responses() verifies, its
 * signature under the metadata of the provider, as the signature of the Response over the ciphertext is.
 *
 * Single Logout is played both ways. SimpleSAMLphp starts it on each journey (issue #734, saml_sp_log_out()); then a
 * third browser, signed in at SimpleSAMLphp over HTTP-Redirect, signs out at the end session endpoint of the provider
 * and confirms (issue #735, spec/saml.md S-29 to S-34, saml_sp_logged_out_by_the_provider()): the provider sends
 * SimpleSAMLphp a LogoutRequest, which SimpleSAMLphp verifies under the metadata of the provider (validate.logout) and
 * answers once it has ended its own session, and the provider ends the chain on the page that says the browser is
 * signed out. The LogoutRequest is verified by OpenSSL and Python under the certificate of the metadata of the
 * provider, and the LogoutResponse under the certificate of SimpleSAMLphp, by their oracle when it is redirected and by
 * xmlsec1 when it is posted.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;

const SAML_SP_URL = 'https://saml-sp.localhost';

/**
 * The entity ID of the service provider, as its own metadata carry it and as beffroi.saml.service_providers declares it.
 */
const SAML_SP_ENTITY_ID = SAML_SP_URL . '/simplesaml/module.php/saml/sp/metadata/beffroi';

/**
 * Under the ignored var/ of the repository: the key and the certificate of the service provider and the binding it is
 * asked to play (mounted into the saml-sp service), the metadata the provider reads (mounted into op and worker), and
 * every document of a run.
 */
const SAML_SP_DIRECTORY = 'var/saml-sp';

const SAML_SP_METADATA_FILE = SAML_SP_DIRECTORY . '/metadata/sp-metadata.xml';

/**
 * The two service providers of the one SimpleSAMLphp, by the name of their authentication source
 * (docker/saml-sp/config/authsources.php), and the file the metadata of each are written to, which the declaration of
 * each in apps/op/config/packages/beffroi.yaml names: "beffroi" takes its assertion in clear, "beffroi-encrypted"
 * demands it encrypted (issue #733).
 */
const SAML_SP_SOURCES = [
    'beffroi' => SAML_SP_METADATA_FILE,
    'beffroi-encrypted' => SAML_SP_DIRECTORY . '/metadata/sp-encrypted-metadata.xml',
];

/**
 * What the encrypted assertion is encrypted under (spec/saml.md S-20), as the EncryptionMethod elements name it.
 */
const SAML_SP_ENCRYPTION = [
    'content' => 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    'key' => 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
];

const SAML_SP_CAPTURED = SAML_SP_DIRECTORY . '/captured';

/**
 * The parameter the page that posts a form from another site again adds to the query of its action (S-28), the MARKER
 * of Beffroi\Bundle\Http\CrossSitePost, which the tasks do not load: the action of that page carries it, and a
 * profiled post that carries it is the one the provider read.
 */
const SAML_POSTED_AGAIN = '_beffroi_posted_again';

/**
 * The cookie that binds a chain of logout to the browser that began it (spec/saml.md S-32), the NAME of
 * Beffroi\Bundle\Saml\LogoutChainCookie, which the tasks do not load: it says "SameSite=None", and goes with the
 * answer a service provider posts from its site.
 */
const SAML_LOGOUT_CHAIN_COOKIE = '__Host-beffroi_saml_logout';

/**
 * The oracle of HTTP-Redirect of saml2-bindings, the script and the Python it runs, which is what the container that
 * verifies a redirected message reads of tests/ (alpine_command()), with the certificate of the signer and the
 * directory of what the walk captured, where each <name>.url has the document it carries beside it, <name>.xml.
 */
const SAML_SP_ORACLE_REDIRECT = 'tests/saml2-bindings/Fixture/oracle';

/**
 * The bindings the AuthnRequest travels over, by the name the walk and its files give them, and the value of
 * "Binding" in the metadata that name stands for.
 */
const SAML_SP_BINDINGS = [
    'redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'post' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
];

#[AsTask(
    name: 'saml-sp',
    description: 'The SAML identity provider of the stack judged by SimpleSAMLphp 2.5.3.1 (issue #732): the service provider is started on https://saml-sp.localhost, reads the metadata of the provider and is registered at it by a metadata file and "beffroi:saml:service-provider:refresh"; then single sign-on is played in HTTP-Redirect and in HTTP-POST as a browser plays it, as the development user, and the attributes SimpleSAMLphp received are printed. Every AuthnRequest is verified by xmlsec1 or by OpenSSL and Python (the detached signature of the redirect) and accepted by the model; every Response by xmlsec1. Each journey is a browser of its own, which signs in at the provider; the HTTP-POST one then signs in a second time, its request posted from the site of the service provider without the cookie of the provider and posted again by the provider from its own origin, answered without a login (spec/saml.md S-28); then SimpleSAMLphp signs it out (issue #734): its LogoutRequest, verified by OpenSSL and Python, ends the session of the provider, the LogoutResponse comes back signed to its single logout service and SimpleSAMLphp accepts it, the browser is sent to the login when it asks to sign in again, and the same LogoutRequest presented again is refused; then a third browser signed in at SimpleSAMLphp signs out at the end session endpoint of the provider (issue #735): the provider sends SimpleSAMLphp a LogoutRequest, verified by OpenSSL and Python under the certificate of its metadata, SimpleSAMLphp ends its session and answers with a LogoutResponse verified under its own certificate, which, posted from the site of SimpleSAMLphp without the cookie of the provider, the provider posts again from its own origin (spec/saml.md S-28), the provider ends the chain on the page that says the browser is signed out, and the same LogoutResponse presented again is refused',
)]
function saml_sp(
    #[AsOption(description: 'Only start the service provider, read the metadata of the provider and register it: no sign-on')]
    bool $up = false,
    #[AsOption(description: 'Play the HTTP-Redirect binding alone')]
    bool $redirect = false,
    #[AsOption(description: 'Play the HTTP-POST binding alone')]
    bool $post = false,
    #[AsOption(
        description: 'Play the service provider that demands its assertion encrypted, "beffroi-encrypted" (issue #733): the assertion on the wire checked to be encrypted, then decrypted by xmlsec1 before its signature is verified',
    )]
    bool $encrypted = false,
    #[AsOption(description: 'Stop the service provider')]
    bool $stop = false,
): void {
    if ($stop) {
        run(['docker', 'compose', '--profile', 'saml-sp', 'rm', '--stop', '--force', 'saml-sp']);

        return;
    }

    io()->title('SimpleSAMLphp 2.5.3.1 against the SAML identity provider of the stack');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['BEFFROI_ISSUER', 'BEFFROI_DEV_USER_PASSWORD'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
            exit(1);
        }
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');
    $bindings = $redirect || $post ? array_keys(array_filter(['redirect' => $redirect, 'post' => $post])) : array_keys(SAML_SP_BINDINGS);
    $source = $encrypted ? 'beffroi-encrypted' : 'beffroi';

    io()->section('The service provider');
    $ca = saml_sp_start();

    io()->section('It reads the metadata of the provider');
    $endpoint = saml_sp_reads_the_metadata($issuer, $ca);

    io()->section('The provider registers it');
    saml_sp_register($ca, $source);
    if ($up) {
        io()->success(sprintf('%s serves SimpleSAMLphp, which reads %s/saml/metadata; the provider holds its metadata.', SAML_SP_URL, $issuer));

        return;
    }

    io()->section('The AuthnRequests of the service provider');
    $journeys = [];
    foreach ($bindings as $binding) {
        $journeys[$binding] = saml_sp_requests_sign_on($binding, $ca, $endpoint, $source);
    }
    // the service provider goes back to playing whatever the metadata say, for whoever uses it by hand
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    saml_sp_verify_requests($journeys);

    io()->section('Single sign-on at the provider');
    foreach ($journeys as $binding => $journey) {
        $journeys[$binding] = saml_sp_sign_on_at_the_provider($journey, $issuer, $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if (isset($journeys['post'])) {
        io()->section('A second sign-on in the same browser, its request posted from the site of the service provider');
        saml_sp_sign_on_again($journeys['post'], $issuer, $ca, $endpoint);
    }
    saml_sp_verify_responses($journeys);

    io()->section('Single Logout started by the service provider');
    foreach ($journeys as $binding => $journey) {
        saml_sp_log_out($journey, $issuer, $ca);
    }
    saml_sp_verify_logout_requests($journeys);

    io()->section('Single Logout started by the provider');
    $journey = saml_sp_requests_sign_on('redirect', $ca, $endpoint, $source);
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    $journey['capture'] = 'provider-logout';
    $journey = saml_sp_sign_on_at_the_provider($journey, $issuer, $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    $answer = saml_sp_logged_out_by_the_provider($journey, $issuer, $ca);
    saml_sp_verify_provider_logout($answer);

    io()->success(sprintf(
        'SimpleSAMLphp signed %s in at %s over %s%s and out again, both ways, and every document that crossed was verified.',
        DEV_USERNAME,
        $issuer,
        implode(' and ', array_map(static fn (string $binding): string => SAML_SP_BINDINGS[$binding], array_keys($journeys))),
        $encrypted ? ', its assertion encrypted' : '',
    ));
}

/**
 * The service provider up, behind Caddy, with a key and a certificate of its own.
 *
 * The pair is drawn here and not committed, as the client certificate of the stack is not: what a development stack
 * generates stays under var/. It is the pair its metadata carry, and the one every signature of its requests is
 * verified under.
 *
 * @return string the CA of Caddy, with which every request of the walk verifies the certificates of the stack
 */
function saml_sp_start(): string
{
    foreach ([SAML_SP_DIRECTORY, SAML_SP_DIRECTORY . '/metadata', SAML_SP_CAPTURED] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    foreach (glob(SAML_SP_CAPTURED . '/*') ?: [] as $file) {
        unlink($file);
    }
    $drawn = ! is_file(SAML_SP_DIRECTORY . '/sp.pem') || ! is_file(SAML_SP_DIRECTORY . '/sp.crt');
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
            '/CN=saml-sp.localhost',
            '-keyout',
            SAML_SP_DIRECTORY . '/sp.pem',
            '-out',
            SAML_SP_DIRECTORY . '/sp.crt',
        ], context: context()->withQuiet());
    }
    // Its owner's alone: the container reads it as root, whatever uid owns it here, and hands www-data a copy of its
    // own (compose.yaml), so that no other account of the machine reads the key the judge signs with.
    chmod(SAML_SP_DIRECTORY . '/sp.pem', 0o600);
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    // A container that copied the key of an earlier pair holds it until it is created again.
    run(['docker', 'compose', '--profile', 'saml-sp', 'up', '-d', '--wait', '--build', ...($drawn ? ['--force-recreate'] : []), 'saml-sp']);

    $ca = caddy_ca(getcwd() . '/' . SAML_SP_DIRECTORY . '/caddy-root.crt');
    // read by www-data in the container, a certificate and no secret
    chmod($ca, 0o644);
    $cookies = [];
    for ($attempt = 0; $attempt < 30; ++$attempt) {
        try {
            [$status] = demo_request($cookies, $ca, 'GET', SAML_SP_ENTITY_ID);
        } catch (HttpClientException) {
            $status = 0;
        }
        if ($status === 200) {
            io()->text(sprintf(' <info>✓</info> %s answers through the Caddy of op', SAML_SP_ENTITY_ID));

            return $ca;
        }
        sleep(1);
    }
    io()->error(sprintf('%s does not answer: "castor start" first, then "docker compose --profile saml-sp logs saml-sp".', SAML_SP_ENTITY_ID));
    exit(1);
}

/**
 * What SimpleSAMLphp made of the metadata of the provider, compared with the document itself: the same entity, the same
 * two bindings at the same URL, the same keys. Kept for the verifications that follow, with the document.
 *
 * @return array{sso: string, entityId: string}
 */
function saml_sp_reads_the_metadata(string $issuer, string $ca): array
{
    $cookies = [];
    $url = $issuer . '/saml/metadata';
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $url);
    demo_expect($status === 200 && str_contains($document, 'IDPSSODescriptor'), sprintf('%s serves the metadata of the provider (got %d)', $url, $status));
    file_put_contents(SAML_SP_CAPTURED . '/idp-metadata.xml', $document);

    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $published = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService') ?: [] as $service) {
        $published[$service->getAttribute('Binding')] = $service->getAttribute('Location');
    }
    $certificates = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate')
        ?: [] as $certificate) {
        $certificates[] = hash('sha256', (string) base64_decode(preg_replace('/\s+/', '', $certificate->textContent) ?? '', true));
    }

    [$status, , $body] = demo_request($cookies, $ca, 'GET', SAML_SP_URL . '/simplesaml/status.php?idp');
    $read = json_decode($body, true);
    demo_expect(
        $status === 200 && is_array($read),
        sprintf('SimpleSAMLphp reads the metadata of the provider and tells what it holds of it (got %d; "docker compose logs saml-sp" says why not)', $status),
    );
    demo_expect($read['entityId'] === $entityId, sprintf('the entity it holds is %s', $entityId));
    $heldServices = [];
    foreach ($read['singleSignOnService'] as $service) {
        $heldServices[$service['Binding']] = $service['Location'];
    }
    demo_expect(
        $heldServices === $published && count($published) === 2,
        sprintf('its single sign-on service is the one published, for HTTP-Redirect and HTTP-POST: %s', implode(', ', array_unique($published))),
    );
    $heldKeys = array_column($read['keys'], 'sha256');
    demo_expect(
        $certificates !== [] && array_diff($certificates, $heldKeys) === [],
        sprintf('it holds the %d signing certificate(s) of the document, by their SHA-256', count($certificates)),
    );
    demo_expect($read['signAuthnRequest'] === true, 'it signs its requests, as WantAuthnRequestsSigned asks');

    return [
        'sso' => $published[SAML_SP_BINDINGS['redirect']],
        'entityId' => $entityId,
    ];
}

/**
 * The entity ID of a service provider of the SimpleSAMLphp, by its authentication source, as its own metadata carry it
 * and as beffroi.saml.service_providers declares it.
 */
function saml_sp_entity_id(string $source): string
{
    return SAML_SP_URL . '/simplesaml/module.php/saml/sp/metadata/' . $source;
}

/**
 * The metadata of the service provider written where the development configuration says the provider reads them, then
 * registered with the console command a deployment uses: the same object the schedule runs every hour.
 */
function saml_sp_register(string $ca, string $source = 'beffroi'): void
{
    $cookies = [];
    $entityId = saml_sp_entity_id($source);
    $file = SAML_SP_SOURCES[$source];
    [$status, , $metadata] = demo_request($cookies, $ca, 'GET', $entityId);
    demo_expect(
        $status === 200 && str_contains($metadata, 'entityID="' . $entityId . '"') && str_contains($metadata, 'SPSSODescriptor'),
        sprintf('%s serves the metadata of the service provider (got %d)', $entityId, $status),
    );
    file_put_contents($file . '.tmp', $metadata);
    rename($file . '.tmp', $file);
    file_put_contents(SAML_SP_CAPTURED . '/sp-metadata.xml', $metadata);
    io()->text(sprintf(' <info>✓</info> written to %s, which op reads at /saml-sp/%s', $file, basename($file)));

    $refresh = op_console(['beffroi:saml:service-provider:refresh', $entityId], context()->withAllowFailure());
    demo_expect($refresh->isSuccessful(), 'beffroi:saml:service-provider:refresh registers it (its output above says why not)');
}

/**
 * The first half of a journey: the browser asks the service provider to sign it in, and keeps the AuthnRequest the
 * service provider gives it for the provider, in the binding the metadata the service provider reads were narrowed
 * to. Nothing is sent to the provider: that is the next section's, and what is captured here is verified first.
 *
 * @param array{sso: string, entityId: string} $endpoint
 * @return array{binding: string, source: string, cookies: array<string, array<string, string>>, request: array{method: string, url: string, fields: array<string, string>}, ssoUrl: string}
 */
function saml_sp_requests_sign_on(string $binding, string $ca, array $endpoint, string $source = 'beffroi'): array
{
    // SimpleSAMLphp sends the request to the HTTP-Redirect service whenever the metadata list one: the file narrows the
    // single sign-on service it sees to the binding being played (docker/saml-sp/metadata/saml20-idp-remote.php)
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', $binding);
    $cookies = [];
    $returnTo = SAML_SP_URL . '/simplesaml/status.php?as=' . $source;
    [$status, $location, $page] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/saml/sp/login/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    $journey = [
        'binding' => $binding,
        'source' => $source,
        'cookies' => $cookies,
        'ssoUrl' => $endpoint['sso'],
    ];
    if ($binding === 'redirect') {
        demo_expect(
            in_array($status, [302, 303], true) && str_starts_with($location, $endpoint['sso'] . '?'),
            sprintf('SimpleSAMLphp redirects the browser to %s (got %d %s)', $endpoint['sso'], $status, substr($location, 0, 120)),
        );
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $query);
        demo_expect(isset($query['SAMLRequest'], $query['SigAlg'], $query['Signature']), 'with a signed query string: SAMLRequest, SigAlg, Signature');
        $inflated = gzinflate((string) base64_decode((string) $query['SAMLRequest'], true));
        demo_expect($inflated !== false, 'whose SAMLRequest is base64 over raw DEFLATE');
        // no newline: the oracle of 9b reads the file whole, and one would end the Signature parameter
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-redirect.url', $location);
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-redirect.xml', $inflated);
        $journey['request'] = [
            'method' => 'GET',
            'url' => $location,
            'fields' => [],
        ];
    } else {
        demo_expect($status === 200, sprintf('SimpleSAMLphp answers with the page that posts the request (got %d)', $status));
        $form = saml_sp_page_form($page);
        demo_expect(
            $form['action'] === $endpoint['sso'] && isset($form['fields']['SAMLRequest']),
            sprintf('which posts SAMLRequest to %s (the form posts to %s)', $endpoint['sso'], $form['action']),
        );
        $document = base64_decode($form['fields']['SAMLRequest'], true);
        demo_expect(
            $document !== false && str_contains($document, 'AuthnRequest') && str_contains($document, 'Signature'),
            'a base64 AuthnRequest carrying its own XML signature',
        );
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-post.xml', $document);
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-post.fields.json', json_encode($form['fields'], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
        $journey['request'] = [
            'method' => 'POST',
            'url' => $form['action'],
            'fields' => $form['fields'],
        ];
    }
    $journey['cookies'] = $cookies;

    return $journey;
}

/**
 * The form of a page that posts a document, as a browser reads it: where it posts and the hidden fields it carries.
 *
 * @return array{action: string, fields: array<string, string>}
 */
function saml_sp_page_form(string $page): array
{
    demo_expect(preg_match('/<form\b[^>]*\baction="([^"]*)"/i', $page, $action) === 1, 'the page carries a form');

    return [
        'action' => html_entity_decode($action[1]),
        'fields' => demo_form_fields($page),
    ];
}

/**
 * Every AuthnRequest of the journeys, by the three judges that are not the provider's: the OpenSSL command line and
 * Python's zlib on the detached signature and the message of the redirect, xmlsec1 on the XML signature of the post,
 * the model on both, received by the receiver of their binding.
 *
 * @param array<string, array{binding: string}> $journeys
 */
function saml_sp_verify_requests(array $journeys): void
{
    if (isset($journeys['redirect'])) {
        io()->text('OpenSSL and Python, the signature over the query string and the message it carries:');
        in_alpine(
            'apk add -q openssl python3 >/dev/null 2>&1 && openssl version && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
            . SAML_SP_DIRECTORY
            . '/sp.crt '
            . SAML_SP_CAPTURED
            . '/authn-request-redirect.url',
            [SAML_SP_ORACLE_REDIRECT, SAML_SP_DIRECTORY . '/sp.crt', SAML_SP_CAPTURED],
        );
    }
    if (isset($journeys['post'])) {
        io()->text('xmlsec1, the signature of the document:');
        saml_sp_xmlsec1();
    }
    io()->text('The model, receiving each request and validating it as the single sign-on service has to:');
    saml_sp_in_phpqa('tests/demo/saml-sp-model.php', SAML_SP_CAPTURED);
}

/**
 * xmlsec1 on every XML signature of the documents captured, each under the certificate of the metadata of its signer,
 * both metadata documents being among them (tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh): a document
 * with no XML signature, the redirected request, is listed and skipped.
 */
function saml_sp_xmlsec1(): void
{
    in_alpine(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh '
        . SAML_SP_CAPTURED
        . ' "*.xml"',
        ['tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh', SAML_SP_CAPTURED],
    );
}

/**
 * A script of the repository in the phpqa image, which has the dependencies of the monorepo the script loads.
 */
function saml_sp_in_phpqa(string $script, string $argument): void
{
    if (! is_file('vendor/autoload.php')) {
        io()->error('The repository is not installed: run "composer install" first.');
        exit(1);
    }
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'XDEBUG_MODE=off',
        '-v',
        getcwd() . ':/project:ro',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', saml2_interop_php_version()),
        'php',
        $script,
        $argument,
    ]);
}

/**
 * The second half of a journey, at the provider: the AuthnRequest the browser holds sent to the single sign-on service,
 * the login of the development user, the Response the provider posts back, carried to the assertion consumer service of
 * the service provider, and what SimpleSAMLphp holds of its session afterwards.
 *
 * Each journey is a browser of its own and signs in: the request waits for the login in the session of that browser
 * (spec/saml.md S-18) and is resumed into the page that posts the Response, in the binding the metadata name for it
 * (HTTP-POST, SAML Bindings §3.5).
 *
 * A browser already signed in at the provider ($signedIn) is answered from its session, and the login is then a
 * failure of the journey; the Response it is answered with is captured under the name of the journey ($journey['capture']).
 *
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, request: array{method: string, url: string, fields: array<string, string>}, ssoUrl: string, capture?: string} $journey
 * @return array{binding: string, source: string, cookies: array<string, array<string, string>>, response?: string}
 */
function saml_sp_sign_on_at_the_provider(array $journey, string $issuer, string $password, string $ca, bool $signedIn = false): array
{
    $source = $journey['source'] ?? 'beffroi';
    $cookies = $journey['cookies'];
    $request = $journey['request'];
    $binding = SAML_SP_BINDINGS[$journey['binding']];

    [$status, $location, $page] = demo_request($cookies, $ca, $request['method'], $request['url'], $request['fields']);
    if ($signedIn) {
        demo_expect(
            ! ($status === 302 && strtok($location, '?') === $issuer . '/login'),
            sprintf('the provider answers from the session of the browser, without a login (got %d %s)', $status, substr($location, 0, 120)),
        );
    }
    // the login every page of the provider that is not an authorization request sends the browser to, its path read
    // and not its query (spec/saml.md S-18)
    if ($status === 302 && strtok($location, '?') === $issuer . '/login') {
        [$status, , $login] = demo_request($cookies, $ca, 'GET', $location);
        demo_expect($status === 200, sprintf('the provider takes the browser to its login page (got %d)', $status));
        $login = demo_past_the_address($cookies, $ca, $issuer, $login);
        $form = demo_form_with($login, '_username', 'which carries the form of the password');
        demo_expect(
            preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
            'and its token',
        );
        [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
            '_username' => DEV_USERNAME,
            '_password' => $password,
            '_csrf_token' => $csrf[1],
        ]);
        demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));
        [$status, $location, $page] = demo_resume($cookies, $ca, $issuer, $location);
    }
    demo_expect($status === 200, sprintf('the provider answers with the page that posts the Response (got %d %s)', $status, substr($location, 0, 120)));
    $form = saml_sp_page_form($page);
    demo_expect(
        $form['action'] === SAML_SP_URL . '/simplesaml/module.php/saml/sp/saml2-acs.php/' . $source && isset($form['fields']['SAMLResponse']),
        sprintf('which posts SAMLResponse to the assertion consumer service of the service provider (it posts to %s)', $form['action']),
    );
    $response = base64_decode($form['fields']['SAMLResponse'], true);
    demo_expect($response !== false, 'a base64 Response');
    $name = sprintf('response-%s.xml', $journey['capture'] ?? $journey['binding']);
    file_put_contents(SAML_SP_CAPTURED . '/' . $name, $response);
    if ($source === 'beffroi-encrypted') {
        saml_sp_encrypted_on_the_wire($response);
    }

    [$status, $location] = demo_request($cookies, $ca, 'POST', $form['action'], $form['fields']);
    demo_expect(
        in_array($status, [302, 303], true) && str_starts_with($location, SAML_SP_URL . '/simplesaml/status.php'),
        sprintf('SimpleSAMLphp accepts it and sends the browser back to where it came from (got %d %s)', $status, substr($location, 0, 120)),
    );
    [$status, , $body] = demo_request($cookies, $ca, 'GET', SAML_SP_URL . '/simplesaml/status.php?as=' . $source);
    $session = json_decode($body, true);
    demo_expect($status === 200 && is_array($session) && ($session['authenticated'] ?? false) === true, 'its session is open');

    $rows = [
        ['NameID', sprintf('%s (%s)', $session['nameId']['value'] ?? '?', $session['nameId']['format'] ?? '?')],
        ['SessionIndex', (string) ($session['sessionIndex'] ?? '?')],
    ];
    foreach ($session['attributes'] as $attribute => $values) {
        $rows[] = [$attribute, implode(', ', $values)];
    }
    io()->text(sprintf('What SimpleSAMLphp received over %s from %s:', $binding, (string) ($session['idp'] ?? '?')));
    io()->table(['', 'Received'], $rows);
    demo_expect($session['attributes'] !== [], 'the assertion carried attributes');

    return [
        'binding' => $journey['binding'],
        'source' => $source,
        'cookies' => $cookies,
        'response' => $name,
    ];
}

/**
 * A second sign-on in the browser of the HTTP-POST journey, signed in at the provider by the first (spec/saml.md S-28,
 * issue #739): the service provider posts a new AuthnRequest from its own site, which a "SameSite=Lax" session cookie
 * does not accompany, and the provider answers with a page of its own origin that posts the same fields again, once,
 * from where the cookie comes with them (saml_sp_posted_from_another_site()); that post is answered from the session,
 * without a login.
 *
 * @param array{source?: string, cookies: array<string, array<string, string>>} $first
 * @param array{sso: string, entityId: string} $endpoint
 */
function saml_sp_sign_on_again(array $first, string $issuer, string $ca, array $endpoint): void
{
    $journey = saml_sp_requests_sign_on('post', $ca, $endpoint, $first['source'] ?? 'beffroi');
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    $provider = (string) parse_url($issuer, \PHP_URL_HOST);
    demo_expect(($first['cookies'][$provider] ?? []) !== [], 'the browser holds the session cookie of the provider since the first sign-on');
    $journey['cookies'][$provider] = $first['cookies'][$provider];
    $journey['request'] = [
        'method' => 'POST',
        ...saml_sp_posted_from_another_site($journey['request']['url'], $journey['request']['fields'], $ca),
    ];
    $journey['capture'] = 'post-again';
    saml_sp_sign_on_at_the_provider($journey, $issuer, '', $ca, signedIn: true);
}

/**
 * A form a page of the service provider posts to the provider, as a browser posts it from that other site (spec/saml.md
 * S-28): the provider answers with a page of its own origin that posts the same fields again, once, to the same URL
 * marked in its query, and sets no cookie, which would replace the session cookie of the provider the browser holds.
 * Returned is the post that page makes, which the walk then makes with every cookie of the browser, as a post from the
 * origin of the provider goes.
 *
 * The walk is a PHP client and not a browser: it sends no "Sec-Fetch-Site" and carries every cookie of its jar, whatever
 * "SameSite" says. So the cross-site post is written here as a browser writes it, "Sec-Fetch-Site: cross-site" and, of
 * the cookies of the provider, only those that say "SameSite=None", given here, and what the walk proves is the answer
 * of the provider to that post, the page and the post again; that a browser keeps the other cookies back is the
 * browser's, which the walk does not play.
 *
 * @param array<string, string> $fields
 * @param array<string, string> $sameSiteNone the cookies of the provider that go with a post from another site, by name
 * @return array{url: string, fields: array<string, string>}
 */
function saml_sp_posted_from_another_site(string $url, array $fields, string $ca, array $sameSiteNone = []): array
{
    $headers = [
        'Sec-Fetch-Site' => 'cross-site',
    ];
    if ($sameSiteNone !== []) {
        $headers['Cookie'] = implode('; ', array_map(
            static fn (string $name, string $value): string => $name . '=' . $value,
            array_keys($sameSiteNone),
            array_values($sameSiteNone),
        ));
    }
    $response = http_request('POST', $url, [
        'max_redirects' => 0,
        'cafile' => $ca,
        'headers' => $headers,
        'body' => $fields,
    ]);
    $status = $response->getStatusCode();
    // the cookies the page sets, less the two the profiler of a stack in debug sets on every answer of a firewall
    // that is not stateless, to link the profiles of a sign-in and a sign-out (SecurityDataCollector): they are the
    // instrumentation's, not the provider's, and no stack that collects no profile sets them
    $set = array_values(array_filter(
        array_map(
            static fn (string $cookie): string => trim(explode('=', $cookie, 2)[0]),
            $response->getHeaders(false)['set-cookie'] ?? [],
        ),
        static fn (string $name): bool => preg_match('/_(de)?auth_profile_token$/', $name) !== 1,
    ));
    demo_expect(
        $status === 200 && $set === [],
        sprintf(
            'the provider answers the post that came without its cookie with a page of its own, which sets no cookie (got %d%s)',
            $status,
            $set === [] ? '' : ', setting ' . implode(', ', $set),
        ),
    );
    $form = saml_sp_page_form($response->getContent(false));
    $path = (string) parse_url($url, \PHP_URL_PATH);
    demo_expect(
        $form['action'] === $path . '?' . SAML_POSTED_AGAIN . '=1' && $form['fields'] === $fields,
        sprintf('whose form posts the same fields again to %s, marked so that it is not posted a third time (it posts to %s)', $path, $form['action']),
    );

    return [
        'url' => sprintf(
            '%s://%s%s%s',
            (string) parse_url($url, \PHP_URL_SCHEME),
            (string) parse_url($url, \PHP_URL_HOST),
            parse_url($url, \PHP_URL_PORT) === null ? '' : ':' . parse_url($url, \PHP_URL_PORT),
            $form['action'],
        ),
        'fields' => $form['fields'],
    ];
}

/**
 * xmlsec1 on every signature of the Responses the provider posted, under the certificate its metadata publish, and the
 * requests again beside them.
 *
 * @param array<string, array{response?: string}> $journeys
 */
function saml_sp_verify_responses(array $journeys): void
{
    if (array_filter($journeys, static fn (array $journey): bool => isset($journey['response'])) === []) {
        return;
    }
    foreach (glob(SAML_SP_CAPTURED . '/response-*.xml') ?: [] as $file) {
        if (str_contains((string) file_get_contents($file), 'EncryptedAssertion')) {
            saml_sp_decrypt($file);
        }
    }
    io()->text('xmlsec1, the signatures of the Responses:');
    saml_sp_xmlsec1();
}

/**
 * The acceptance of issue #733 on the wire (spec/saml.md S-19, S-20): the Response carries one saml:EncryptedAssertion
 * and no assertion in clear, its content under aes256-gcm and its key under rsa-oaep-mgf1p, and no algorithm of it in
 * CBC. The algorithms are what is read, the Algorithm of every element that names one, and not the text of the
 * document: an ID, a digest or a ciphertext is hexadecimal or base64 drawn at random, and holds "cbc" in some runs.
 */
function saml_sp_encrypted_on_the_wire(string $response): void
{
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($response), 'the Response is well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    demo_expect(
        (int) $xpath->evaluate('count(/samlp:Response/saml:EncryptedAssertion)') === 1 && (int) $xpath->evaluate('count(//saml:Assertion)') === 0,
        'its assertion is encrypted: one saml:EncryptedAssertion, no saml:Assertion in clear',
    );
    demo_expect(
        (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)')
            === SAML_SP_ENCRYPTION['content']
        && (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)')
            === SAML_SP_ENCRYPTION['key'],
        sprintf('under %s, its key under %s', SAML_SP_ENCRYPTION['content'], SAML_SP_ENCRYPTION['key']),
    );
    $algorithms = array_map(static fn (DOMAttr $algorithm): string => $algorithm->value, iterator_to_array($xpath->query('//@Algorithm') ?: []));
    demo_expect(
        array_filter($algorithms, static fn (string $algorithm): bool => stripos($algorithm, 'cbc') !== false) === [],
        sprintf('no algorithm of it is in CBC (%s)', implode(', ', array_unique($algorithms))),
    );
}

/**
 * xmlsec1, which is not the provider and not SimpleSAMLphp, decrypts the assertion of a Response captured with the
 * private key of the service provider, and the assertion it gives back is written beside it, so that
 * saml_sp_xmlsec1() verifies its signature as a document of its own.
 */
function saml_sp_decrypt(string $file): void
{
    $assertion = capture(alpine_command(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1'
        . ' && xmlsec1 --decrypt --lax-key-search --privkey-pem '
        . SAML_SP_DIRECTORY
        . '/sp.pem --output /tmp/decrypted.xml '
        . escapeshellarg($file)
        . ' && xmllint --xpath \'/*/*[local-name()="EncryptedAssertion"]/*[local-name()="Assertion"]\' /tmp/decrypted.xml',
        [SAML_SP_DIRECTORY . '/sp.pem', $file],
    ));
    $name = basename($file, '.xml') . '.decrypted-assertion.xml';
    file_put_contents(SAML_SP_CAPTURED . '/' . $name, $assertion);
    demo_expect(
        str_contains($assertion, ':Assertion') && str_contains($assertion, 'Signature'),
        sprintf('xmlsec1 decrypts %s into a signed assertion, %s', basename($file), $name),
    );
}

/**
 * Single Logout started by the service provider (issue #734, spec/saml.md section 6.5), on a journey signed in: the
 * browser asks SimpleSAMLphp to sign it out, carries the LogoutRequest it is given to the single logout service of the
 * provider, and the LogoutResponse the provider answers with back to the single logout service of SimpleSAMLphp, which
 * verifies its signature under the metadata of the provider (validate.logout, docker/saml-sp/config/authsources.php).
 * Then what the provider kept of it: the same browser asking SimpleSAMLphp to sign it in again is sent to the login of
 * the provider, its session having ended (S-25); and the same LogoutRequest presented again is refused, with the page
 * of a refusal and no answer (S-23, issue #708).
 *
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, response?: string} $journey
 */
function saml_sp_log_out(array $journey, string $issuer, string $ca): void
{
    $cookies = $journey['cookies'];
    $source = $journey['source'] ?? 'beffroi';
    $returnTo = SAML_SP_URL . '/simplesaml/status.php?as=' . $source;
    [$status, $request] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/core/logout/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    demo_expect(
        in_array($status, [302, 303], true) && strtok($request, '?') === $issuer . '/saml/slo',
        sprintf('SimpleSAMLphp sends the browser to the single logout service of the provider (got %d %s)', $status, substr($request, 0, 120)),
    );
    parse_str((string) parse_url($request, \PHP_URL_QUERY), $query);
    demo_expect(isset($query['SAMLRequest'], $query['SigAlg'], $query['Signature']), 'with a LogoutRequest signed over the query string');
    $inflated = gzinflate((string) base64_decode((string) $query['SAMLRequest'], true));
    demo_expect($inflated !== false, 'whose SAMLRequest is base64 over raw DEFLATE');
    // no newline: the oracle of 9b reads the file whole, and one would end the Signature parameter
    file_put_contents(sprintf('%s/logout-request-%s.url', SAML_SP_CAPTURED, $journey['binding']), $request);
    file_put_contents(sprintf('%s/logout-request-%s.xml', SAML_SP_CAPTURED, $journey['binding']), $inflated);

    [$status, $answer, $page] = demo_request($cookies, $ca, 'GET', $request);
    demo_expect(
        $status === 302 && str_starts_with($answer, SAML_SP_URL . '/simplesaml/module.php/saml/sp/saml2-logout.php/' . $source . '?'),
        sprintf(
            'the provider answers at the single logout service of the metadata of SimpleSAMLphp (got %d %s %s)',
            $status,
            substr($answer, 0, 120),
            $status === 302 ? '' : substr(strip_tags($page), 0, 300),
        ),
    );
    parse_str((string) parse_url($answer, \PHP_URL_QUERY), $query);
    demo_expect(isset($query['SAMLResponse'], $query['SigAlg'], $query['Signature']), 'with a LogoutResponse signed over the query string');
    $response = gzinflate((string) base64_decode((string) $query['SAMLResponse'], true));
    demo_expect($response !== false && str_contains($response, 'urn:oasis:names:tc:SAML:2.0:status:Success'), 'which says Success');
    file_put_contents(sprintf('%s/logout-response-%s.url', SAML_SP_CAPTURED, $journey['binding']), $answer);
    file_put_contents(sprintf('%s/logout-response-%s.xml', SAML_SP_CAPTURED, $journey['binding']), $response);

    [$status, $back] = demo_request($cookies, $ca, 'GET', $answer);
    demo_expect(
        in_array($status, [302, 303], true) && str_starts_with($back, $returnTo),
        sprintf('SimpleSAMLphp accepts the LogoutResponse, its signature verified, and sends the browser back (got %d %s)', $status, substr($back, 0, 120)),
    );
    [$status] = demo_request($cookies, $ca, 'GET', $returnTo);
    demo_expect($status === 401, sprintf('its session is closed (got %d)', $status));

    [$status, $sso] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/saml/sp/login/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    demo_expect(in_array($status, [302, 303], true), sprintf('SimpleSAMLphp asks the provider to sign the browser in again (got %d)', $status));
    [$status, $login] = demo_request($cookies, $ca, 'GET', $sso);
    demo_expect(
        $status === 302 && strtok($login, '?') === $issuer . '/login',
        sprintf('the provider sends the browser to its login: its session has ended (got %d %s)', $status, substr($login, 0, 120)),
    );

    [$status, $replayed] = demo_request($cookies, $ca, 'GET', $request);
    demo_expect(
        $status === 400 && $replayed === '',
        sprintf('the same LogoutRequest presented again is refused, without an answer (got %d %s)', $status, substr($replayed, 0, 120)),
    );
}

/**
 * Every LogoutRequest SimpleSAMLphp sent, by OpenSSL and Python, which verify its detached signature under the
 * certificate of the service provider and inflate its message, as for the AuthnRequest of the redirect.
 *
 * @param array<string, array{binding: string}> $journeys
 */
function saml_sp_verify_logout_requests(array $journeys): void
{
    $urls = array_map(
        static fn (array $journey): string => sprintf('%s/logout-request-%s.url', SAML_SP_CAPTURED, $journey['binding']),
        array_values($journeys),
    );
    io()->text('OpenSSL and Python, the signature of each LogoutRequest over its query string and the message it carries:');
    in_alpine(
        'apk add -q openssl python3 >/dev/null 2>&1 && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh ' . SAML_SP_DIRECTORY . '/sp.crt '
            . implode(' ', $urls),
        [SAML_SP_ORACLE_REDIRECT, SAML_SP_DIRECTORY . '/sp.crt', SAML_SP_CAPTURED],
    );
}

/**
 * Single Logout started by the provider (issue #735, spec/saml.md S-29 to S-34), on a journey signed in at SimpleSAMLphp:
 * the browser signs out at the end session endpoint of the provider, which asks it to confirm, no client having named
 * the session; the confirmed logout ends the session of the provider and sends the browser to the single logout
 * service of SimpleSAMLphp with a signed LogoutRequest, captured; SimpleSAMLphp verifies it under the metadata of the
 * provider (validate.logout), ends its own session and answers with a LogoutResponse, captured, which the browser
 * carries back to the single logout service of the provider, over HTTP-POST from the site of SimpleSAMLphp as a browser
 * posts it, answered with the page that posts it again from the origin of the provider (S-28,
 * saml_sp_posted_from_another_site()); the chain ends there, on the page that says the browser is signed out, nobody
 * having named where to go back to (S-34). Then what each kept of it: SimpleSAMLphp holds no
 * session any more, the browser asking it to sign in again is sent to the login of the provider, whose session has
 * ended (S-29), and the same LogoutResponse presented again is refused, with the page of a refusal (S-33).
 *
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, response?: string} $journey
 * @return array{binding: string, url?: string} the binding SimpleSAMLphp answered over, and the URL of its answer when
 *                                              it redirected
 */
function saml_sp_logged_out_by_the_provider(array $journey, string $issuer, string $ca): array
{
    $cookies = $journey['cookies'];
    $source = $journey['source'] ?? 'beffroi';
    $returnTo = SAML_SP_URL . '/simplesaml/status.php?as=' . $source;
    $singleLogout = SAML_SP_URL . '/simplesaml/module.php/saml/sp/saml2-logout.php/' . $source;
    $origin = sprintf(
        '%s://%s%s',
        (string) parse_url($issuer, \PHP_URL_SCHEME),
        (string) parse_url($issuer, \PHP_URL_HOST),
        parse_url($issuer, \PHP_URL_PORT) === null ? '' : ':' . parse_url($issuer, \PHP_URL_PORT),
    );

    saml_sp_participation_recorded($cookies, $ca, $source);

    [$status, , $page] = demo_request($cookies, $ca, 'GET', $issuer . '/logout');
    demo_expect($status === 200, sprintf('the end session endpoint of the provider asks the browser to confirm (got %d)', $status));
    $form = demo_form_with($page, 'confirm', 'with the form of the confirmation');
    demo_expect(str_contains($form, 'name="_token"'), 'and its token');
    demo_expect(preg_match('/action="([^"]+)"/', $form, $action) === 1, 'which posts back to the end session endpoint');
    [$status, $request] = demo_request($cookies, $ca, 'POST', $origin . html_entity_decode($action[1]), [...demo_form_fields($form), 'confirm' => 'yes']);
    demo_expect(
        in_array($status, [302, 303], true) && strtok($request, '?') === $singleLogout,
        sprintf('the confirmed logout sends the browser to the single logout service of SimpleSAMLphp (got %d %s)', $status, substr($request, 0, 120)),
    );
    parse_str((string) parse_url($request, \PHP_URL_QUERY), $query);
    demo_expect(
        isset($query['SAMLRequest'], $query['SigAlg'], $query['Signature']) && ! isset($query['RelayState']),
        'with a LogoutRequest signed over the query string, and no RelayState (S-31)',
    );
    $inflated = gzinflate((string) base64_decode((string) $query['SAMLRequest'], true));
    demo_expect($inflated !== false && str_contains($inflated, 'LogoutRequest'), 'whose SAMLRequest is a LogoutRequest, base64 over raw DEFLATE');
    // no newline: the oracle of 9b reads the file whole, and one would end the Signature parameter
    file_put_contents(SAML_SP_CAPTURED . '/provider-logout-request.url', $request);
    file_put_contents(SAML_SP_CAPTURED . '/provider-logout-request.xml', $inflated);
    [$status, $answer, $page] = demo_request($cookies, $ca, 'GET', $request);
    if ($status === 200) {
        $form = saml_sp_page_form($page);
        demo_expect(
            $form['action'] === $issuer . '/saml/slo' && isset($form['fields']['SAMLResponse']),
            sprintf(
                'SimpleSAMLphp accepts the request and posts its LogoutResponse to the single logout service of the provider (it posts to %s)',
                $form['action'],
            ),
        );
        $response = base64_decode($form['fields']['SAMLResponse'], true);
        demo_expect($response !== false && str_contains($response, 'urn:oasis:names:tc:SAML:2.0:status:Success'), 'which says Success');
        file_put_contents(SAML_SP_CAPTURED . '/sp-logout-response.xml', $response);
        // posted from the site of SimpleSAMLphp, with the cookie of the chain and without the session cookie of the
        // provider, then posted again by the page of the provider (S-28), the post the chain is carried on by
        $provider = (string) parse_url($issuer, \PHP_URL_HOST);
        $chain = $cookies[$provider][SAML_LOGOUT_CHAIN_COOKIE] ?? '';
        demo_expect($chain !== '', 'the browser holds the cookie of the chain the provider gave it (S-32)');
        $again = saml_sp_posted_from_another_site($form['action'], $form['fields'], $ca, [SAML_LOGOUT_CHAIN_COOKIE => $chain]);
        $carried = ['POST', $again['url'], $again['fields']];
        $answered = ['binding' => 'post'];
    } else {
        demo_expect(
            in_array($status, [302, 303], true) && strtok($answer, '?') === $issuer . '/saml/slo',
            sprintf(
                'SimpleSAMLphp accepts the request and sends the browser back to the single logout service of the provider (got %d %s %s)',
                $status,
                substr($answer, 0, 120),
                substr(strip_tags($page), 0, 300),
            ),
        );
        parse_str((string) parse_url($answer, \PHP_URL_QUERY), $query);
        demo_expect(isset($query['SAMLResponse'], $query['SigAlg'], $query['Signature']), 'with a LogoutResponse signed over the query string');
        $response = gzinflate((string) base64_decode((string) $query['SAMLResponse'], true));
        demo_expect($response !== false && str_contains($response, 'urn:oasis:names:tc:SAML:2.0:status:Success'), 'which says Success');
        file_put_contents(SAML_SP_CAPTURED . '/sp-logout-response.url', $answer);
        file_put_contents(SAML_SP_CAPTURED . '/sp-logout-response.xml', $response);
        $carried = ['GET', $answer, []];
        $answered = ['binding' => 'redirect', 'url' => $answer];
    }
    [$status] = demo_request($cookies, $ca, 'GET', $returnTo);
    demo_expect($status === 401, sprintf('the session of SimpleSAMLphp is closed (got %d)', $status));

    [$status, $location, $page] = demo_request($cookies, $ca, ...$carried);
    demo_expect(
        $status === 200 && str_contains($page, 'data-logged-out="yes"'),
        sprintf('the provider ends the chain on the page that says the browser is signed out (S-34, got %d %s)', $status, substr($location, 0, 120)),
    );

    [$status, $sso] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/saml/sp/login/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    demo_expect(in_array($status, [302, 303], true), sprintf('SimpleSAMLphp asks the provider to sign the browser in again (got %d)', $status));
    [$status, $login] = demo_request($cookies, $ca, 'GET', $sso);
    demo_expect(
        $status === 302 && strtok($login, '?') === $issuer . '/login',
        sprintf('the provider sends the browser to its login: its session has ended (S-29, got %d %s)', $status, substr($login, 0, 120)),
    );

    [$status, $location] = demo_request($cookies, $ca, ...$carried);
    demo_expect(
        $status === 400 && $location === '',
        sprintf('the same LogoutResponse presented again is refused, without an answer (S-33, got %d %s)', $status, substr($location, 0, 120)),
    );

    return $answered;
}

/**
 * The part of SimpleSAMLphp in the session of the provider, which the provider records from the queue of its events
 * (spec/saml.md S-26) and which its logout reads to tell it (S-30): the walk signs out within a second of the sign-on,
 * faster than a worker may have written the row, so it waits for the row, by the session index SimpleSAMLphp holds, up to
 * thirty seconds, and says how long it waited. A row that never comes is a failure of the walk, named as such, and not a
 * chain that would end without telling anybody.
 *
 * @param array<string, array<string, string>> $cookies
 */
function saml_sp_participation_recorded(array $cookies, string $ca, string $source): void
{
    [$status, , $body] = demo_request($cookies, $ca, 'GET', SAML_SP_URL . '/simplesaml/status.php?as=' . $source);
    $session = json_decode($body, true);
    $sessionIndex = is_array($session) ? (string) ($session['sessionIndex'] ?? '') : '';
    demo_expect(
        $status === 200 && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $sessionIndex) === 1,
        sprintf('SimpleSAMLphp holds the session index of the assertion, the ID of the session of the provider (got %d %s)', $status, $sessionIndex),
    );
    for ($waited = 0; $waited < 30; ++$waited) {
        $count = op_console(
            ['dbal:run-sql', sprintf("SELECT COUNT(*) AS participants FROM beffroi_saml_session_participant WHERE session_id = '%s'", $sessionIndex)],
            context()->withQuiet()->withAllowFailure(),
        );
        if ($count->isSuccessful() && preg_match('/^\s*([0-9]+)\s*$/m', $count->getOutput(), $rows) === 1 && (int) $rows[1] > 0) {
            demo_expect(true, sprintf(
                'the provider recorded the part of SimpleSAMLphp in the session from the queue of its events, after %d s (S-26)',
                $waited,
            ));

            return;
        }
        sleep(1);
    }
    demo_expect(false, 'the provider recorded the part of SimpleSAMLphp in the session within 30 s (S-26): is the worker consuming the events?');
}

/**
 * The two messages of the logout the provider started, each by a judge that is neither the provider nor SimpleSAMLphp:
 * the LogoutRequest of the provider by OpenSSL and Python under a certificate of the metadata of the provider, the one
 * of its active key among them; the LogoutResponse of SimpleSAMLphp by the same oracle under its certificate when it
 * was redirected, by xmlsec1 when it was posted.
 *
 * @param array{binding: string, url?: string} $answer
 */
function saml_sp_verify_provider_logout(array $answer): void
{
    $dom = new DOMDocument();
    demo_expect($dom->loadXML((string) file_get_contents(SAML_SP_CAPTURED . '/idp-metadata.xml')), 'the metadata of the provider captured are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $certificates = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate')
        ?: [] as $index => $certificate) {
        $file = sprintf('%s/idp-signing-%d.crt', SAML_SP_CAPTURED, $index);
        file_put_contents(
            $file,
            "-----BEGIN CERTIFICATE-----\n"
            . chunk_split((string) preg_replace('/\s+/', '', $certificate->textContent), 64, "\n")
            . "-----END CERTIFICATE-----\n",
        );
        $certificates[] = $file;
    }
    demo_expect($certificates !== [], sprintf('the metadata of the provider publish %d signing certificate(s)', count($certificates)));

    io()->text('OpenSSL and Python, the signature of the LogoutRequest of the provider over its query string and the message it carries:');
    in_alpine(
        'apk add -q openssl python3 >/dev/null 2>&1 && verified=; for certificate in '
        . implode(' ', $certificates)
        . '; do if sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh "$certificate" '
        . SAML_SP_CAPTURED
        . '/provider-logout-request.url; then verified=1; break; fi; done; test -n "$verified"',
        [SAML_SP_ORACLE_REDIRECT, SAML_SP_CAPTURED],
    );
    if ($answer['binding'] === 'redirect') {
        io()->text('OpenSSL and Python, the signature of the LogoutResponse of SimpleSAMLphp over its query string and the message it carries:');
        in_alpine(
            'apk add -q openssl python3 >/dev/null 2>&1 && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
            . SAML_SP_DIRECTORY
            . '/sp.crt '
            . SAML_SP_CAPTURED
            . '/sp-logout-response.url',
            [SAML_SP_ORACLE_REDIRECT, SAML_SP_DIRECTORY . '/sp.crt', SAML_SP_CAPTURED],
        );
    }
    // the Response of this sign-on came after saml_sp_verify_responses() decrypted the others: its assertion, when
    // encrypted, is decrypted here, so that xmlsec1 verifies its signature as it does theirs
    $response = SAML_SP_CAPTURED . '/response-provider-logout.xml';
    if (str_contains((string) file_get_contents($response), 'EncryptedAssertion')) {
        saml_sp_decrypt($response);
    }
    io()->text('xmlsec1, every XML signature captured, the Response of this sign-on and a LogoutResponse that was posted among them:');
    saml_sp_xmlsec1();
}

/*
 * The Entra judge (issue #736, spec/saml.md sections 7 and 12): Entra's SAML federation of guests, set up without a
 * domain in the maintainer's test tenant, federating the identity provider of the stack. Entra is configured by hand in
 * its portal, by the maintainer and by nobody else; this task prints what the portal takes and the authorization request
 * through which the guest signs in, registers the service provider the development configuration declares for it, and
 * reads back, once the sign-in was played, what the provider received from Entra.
 *
 * What was received is read from the profiler of the development stack, which collects every request while
 * APP_PROFILER is 1, its default (apps/op/config/packages/web_profiler.yaml): the raw query string of HTTP-Redirect, the
 * fields and the raw body of HTTP-POST, before anything validated them, a request refused included, from whoever sent
 * it. What is kept of them is a message of the entity ID declared for Entra that the provider accepted, and what is
 * printed of it is text. Nothing is added to the provider for it, and a deployment, which collects no profile, has
 * nothing of it.
 *
 * With --upstream, the Entra judge of sub-spike 9d (issue #789, spec/saml.md sections 6.10 to 6.14): the roles the
 * other way round, Entra ID the upstream identity provider of the stack through an enterprise application of the same
 * tenant, configured by hand in its portal, by the maintainer and by nobody else, whose Identifier and Reply URL are the
 * entity ID and the assertion consumer service of the service provider of the tenant. The task checks that the stack
 * serves those two as the portal holds them, has the provider read the Federation Metadata XML of the application
 * (apps/op/config/saml/entra-enterprise-application-idp.xml, which apps/op/config/packages/beffroi.yaml declares),
 * creates the group of the tenant its mapping names, and plays the walk up to Entra and no further: an authorization
 * request of oidc-demo, the address of alice typed on the login page, and the AuthnRequest the provider sends the
 * browser to Entra with, which is decoded and checked, and never sent. The sign-in itself is the maintainer's, in a
 * browser, through oidc-demo; what the browser carried, the request and the response copied from its network panel,
 * is decoded by --captured into the corpus of saml2-model (issue #665).
 */

/**
 * The test tenant of the maintainer, Entra ID Free (beffroilaboutlook.onmicrosoft.com).
 */
const SAML_ENTRA_TENANT = '20a6e528-cf9e-4f79-8949-bbd59006eff5';

/**
 * The tenanted issuer of the AuthnRequest Entra sends for a new federation, the trailing slash included, as
 * apps/op/config/packages/beffroi.yaml declares it and apps/op/config/saml/entra-guest-federation-sp.xml names it.
 */
const SAML_ENTRA_ENTITY_ID = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/';

/**
 * Where the guest signs in (spec/saml.md section 7): an authorization request sent to the tenant itself, whose
 * domain_hint, the Issuer URI of the federation, sends the browser to the identity provider, where the invitation
 * redemption URL and My Apps fall back to a one-time passcode by email.
 */
const SAML_ENTRA_AUTHORIZE = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/oauth2/v2.0/authorize';

/**
 * The client of that request: Azure CLI, a public client of Microsoft that every tenant knows and whose redirection URI
 * http://localhost takes any port. Nothing listens on the port: the last redirection ends on an error page of the
 * browser, whose address carries the answer of Entra in its query.
 */
const SAML_ENTRA_SIGN_IN_CLIENT = '04b07795-8ddb-461a-bbee-02f9e1bf7b46';

const SAML_ENTRA_SIGN_IN_REDIRECT = 'http://localhost:65000';

/**
 * Under the ignored var/ of the repository: the metadata of the provider as Entra's portal can parse them, its signing
 * certificate as the portal takes it, and every document received from Entra.
 */
const SAML_ENTRA_DIRECTORY = 'var/saml-entra';

const SAML_ENTRA_RECEIVED = SAML_ENTRA_DIRECTORY . '/received';

/**
 * Entra ID as the upstream identity provider of the stack (--upstream): the entity ID of the Federation Metadata XML of
 * the enterprise application, the tenanted issuer of sts.windows.net, the trailing slash included, as
 * apps/op/config/packages/beffroi.yaml declares it, and the single sign-on service those metadata name.
 */
const SAML_ENTRA_IDP_ENTITY_ID = 'https://sts.windows.net/' . SAML_ENTRA_TENANT . '/';

const SAML_ENTRA_IDP_SINGLE_SIGN_ON = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/saml2';

/**
 * What the portal of Entra holds of the service provider of the tenant, written there by hand: the Identifier of the
 * enterprise application and its Reply URL. The stack serves them under its issuer; a stack under another issuer is a
 * service provider Entra does not know.
 */
const SAML_ENTRA_SP_IDENTIFIER = 'https://op.localhost/saml/sp/metadata';

const SAML_ENTRA_SP_REPLY_URL = 'https://op.localhost/saml/sp/acs';

/**
 * The people of the tenant that walk, by their address, under the domain the declaration federates: alice, in a group
 * the mapping does not name, and bob, in the group it maps to "finance" of the tenant.
 */
const SAML_ENTRA_PEOPLE = [
    'alice' => 'alice@beffroilaboutlook.onmicrosoft.com',
    'bob' => 'bob@beffroilaboutlook.onmicrosoft.com',
];

const SAML_ENTRA_GROUP = 'finance';

/**
 * The corpus of saml2-model (spec/model.md section 9.4, issue #665), where --captured writes what the browser carried,
 * each document named by its origin and the date it was issued.
 */
const SAML_ENTRA_CORPUS = 'tests/saml2-model/Fixture/real';

/**
 * Run by the PHP of the op container on the profiler storage of its kernel: the requests profiled at the paths given
 * since the instant given, oldest first, as JSON.
 */
const SAML_ENTRA_PROFILE_READER = <<<'PHP'
    <?php

    declare(strict_types=1);

    require '/app/vendor/autoload.php';

    $storage = new Symfony\Component\HttpKernel\Profiler\FileProfilerStorage('file:/app/var/cache/dev/profiler');
    $rows = [];
    foreach (array_slice($argv, 2) as $path) {
        foreach ($storage->find(null, $path, 500, null, (int) $argv[1]) as $row) {
            $rows['t' . $row['token']] = $row;
        }
    }
    $found = [];
    foreach ($rows as $row) {
        $profile = $storage->read((string) $row['token']);
        if ($profile === null || ! $profile->hasCollector('request')) {
            continue;
        }
        $request = $profile->getCollector('request');
        $server = $request->getRequestServer(true)->all();
        $found[] = [
            'token' => (string) $row['token'],
            'time' => $profile->getTime(),
            'method' => $request->getMethod(),
            'url' => $profile->getUrl(),
            'status' => $profile->getStatusCode(),
            'query' => is_string($server['QUERY_STRING'] ?? null) ? $server['QUERY_STRING'] : '',
            'fields' => array_map(
                static fn (mixed $value): mixed => $value instanceof Symfony\Component\VarDumper\Cloner\Data ? $value->getValue(true) : $value,
                $request->getRequestRequest()->all(),
            ),
            'body' => is_string($request->getContent()) ? $request->getContent() : '',
            'secFetchSite' => is_string($server['HTTP_SEC_FETCH_SITE'] ?? null) ? $server['HTTP_SEC_FETCH_SITE'] : null,
        ];
    }
    usort($found, static fn (array $a, array $b): int => $a['time'] <=> $b['time']);
    echo json_encode($found, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    PHP;

#[AsTask(
    name: 'saml-entra',
    description: 'The Entra judge (issue #736): registers the service provider declared for Entra\'s SAML federation of guests, then prints what the portal of Entra takes (Issuer URI, passive authentication endpoint, signing certificate), the invitation Microsoft Graph creates and the authorization request to the tenant, carrying the domain_hint, through which the guest signs in and redeems it; with --received, lists what the provider accepted from the entity ID declared for Entra, read from the profiler of the stack, and writes each document to var/saml-entra/received/ for the corpus. With --upstream (issue #789), Entra the upstream identity provider of the stack: checks the entity ID and the assertion consumer service of the service provider against what the portal holds, refreshes the metadata of the enterprise application, creates the group "finance", plays the walk up to the AuthnRequest sent to Entra, and prints the page to open; with --captured, decodes the request and the response the browser carried into the corpus of saml2-model',
)]
function saml_entra(
    #[AsOption(
        description: 'List what the provider accepted from the entity ID declared for Entra at its single sign-on and single logout services, and write each document to var/saml-entra/received/',
    )]
    bool $received = false,
    #[AsOption(description: 'With --received: how far back the profiles are read, in minutes')]
    int $minutes = 180,
    #[AsOption(description: 'The address the guest is invited with, the email of the user of the provider who signs in')]
    string $email = DEV_USERNAME . '@op.localhost',
    #[AsOption(
        description: 'Entra the upstream identity provider of the stack (issue #789): prepare the provider for a sign-in by hand through oidc-demo, and print the page to open',
    )]
    bool $upstream = false,
    #[AsOption(
        description: 'After a sign-in of --upstream: a file holding what the browser carried, the URL of the request to Entra or the SAMLRequest of its query, the form posted to the assertion consumer service or its SAMLResponse, decoded into tests/saml2-model/Fixture/real/ (repeatable)',
        mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
    )]
    array $captured = [],
): void {
    if ($captured !== []) {
        io()->title('What the browser carried between the stack and Entra, into the corpus');
        saml_entra_corpus(array_values(array_filter($captured, is_string(...))));

        return;
    }
    if ($upstream) {
        io()->title('Entra ID, an identity provider upstream of the stack');
        saml_entra_upstream();

        return;
    }
    io()->title('Entra federating the SAML identity provider of the stack');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    if (($env['BEFFROI_ISSUER'] ?? '') === '') {
        io()->error('BEFFROI_ISSUER is empty: run "castor provision" first.');
        exit(1);
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');
    foreach ([SAML_ENTRA_DIRECTORY, SAML_ENTRA_RECEIVED] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    if ($received) {
        saml_entra_received($issuer, $minutes);

        return;
    }

    io()->section('The metadata of the provider');
    $ca = caddy_ca(getcwd() . '/' . SAML_ENTRA_DIRECTORY . '/caddy-root.crt');
    $cookies = [];
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $issuer . '/saml/metadata');
    demo_expect($status === 200 && str_contains($document, 'IDPSSODescriptor'), sprintf('%s/saml/metadata serves them (got %d)', $issuer, $status));
    file_put_contents(SAML_ENTRA_DIRECTORY . '/op-idp-metadata.xml', $document);
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document, \LIBXML_NONET), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $singleSignOn = (string) $xpath->evaluate(sprintf(
        'string(/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding="%s"]/@Location)',
        SAML_SP_BINDINGS['post'],
    ));
    demo_expect(
        str_starts_with($singleSignOn, 'https://'),
        sprintf('its single sign-on service over HTTP-POST is %s, in https as Entra requires', $singleSignOn),
    );
    $certificates = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate')
        ?: [] as $certificate) {
        $certificates[] = (string) preg_replace('/\s+/', '', $certificate->textContent);
    }
    demo_expect($certificates !== [], sprintf('they hold %d signing certificate(s)', count($certificates)));

    io()->section('The provider registers Entra');
    $refresh = op_console(['beffroi:saml:service-provider:refresh', SAML_ENTRA_ENTITY_ID], context()->withAllowFailure());
    demo_expect($refresh->isSuccessful(), sprintf('beffroi:saml:service-provider:refresh registers %s (its output above says why not)', SAML_ENTRA_ENTITY_ID));

    io()->section('What the portal of Entra takes (External Identities, All identity providers, Custom, Add new, SAML/WS-Fed)');
    io()->writeln(sprintf('<comment>Issuer URI</comment> (also the domain_hint):%s%s%s', \PHP_EOL, $entityId, \PHP_EOL));
    io()->writeln(sprintf('<comment>Passive authentication endpoint:</comment>%s%s%s', \PHP_EOL, $singleSignOn, \PHP_EOL));
    foreach ($certificates as $index => $certificate) {
        $file = sprintf('%s/signing-certificate-%d.txt', SAML_ENTRA_DIRECTORY, $index + 1);
        file_put_contents($file, $certificate);
        io()->writeln(sprintf(
            '<comment>Certificate</comment> %d of %d, the base64 of its DER on one line, also in %s (pbcopy < %s):%s%s%s',
            $index + 1,
            count($certificates),
            $file,
            $file,
            \PHP_EOL,
            $certificate,
            \PHP_EOL,
        ));
    }
    if (count($certificates) > 1) {
        io()->warning('The metadata publish more than one signing certificate (a key staged or retiring beside the active one, S-2), and Entra holds one: give it the certificate of the active key, which "castor console beffroi:keys:list" names.');
    }
    io()->writeln(sprintf('<comment>Metadata URL:</comment> empty, Microsoft cannot reach %s.%s', $issuer, \PHP_EOL));
    io()->writeln(sprintf('<comment>Or "Parse metadata file":</comment> %s%s', SAML_ENTRA_DIRECTORY . '/op-idp-metadata.xml', \PHP_EOL));
    $redirect = sprintf('https://myapps.microsoft.com/?tenantid=%s&domain_hint=%s', SAML_ENTRA_TENANT, rawurlencode($entityId));
    io()->writeln(sprintf(
        '<comment>The invitation</comment>, POST https://graph.microsoft.com/v1.0/invitations in Graph Explorer, the portal taking no redirect URL; neither the "inviteRedeemUrl" it answers with nor its "inviteRedirectUrl" sends the browser to the provider, Entra falling back to a one-time passcode:%s%s%s',
        \PHP_EOL,
        json_encode(
            [
                'invitedUserEmailAddress' => $email,
                'inviteRedirectUrl' => $redirect,
                'sendInvitationMessage' => false,
            ],
            \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR,
        ),
        \PHP_EOL,
    ));
    $signIn =
        SAML_ENTRA_AUTHORIZE
        . '?'
        . http_build_query(
            [
                'client_id' => SAML_ENTRA_SIGN_IN_CLIENT,
                'response_type' => 'code',
                'redirect_uri' => SAML_ENTRA_SIGN_IN_REDIRECT,
                'scope' => 'openid',
                'domain_hint' => $entityId,
            ],
            '',
            '&',
            \PHP_QUERY_RFC3986,
        );
    io()->writeln(sprintf(
        '<comment>The sign-in</comment>, opened in the browser by the guest, who signs in at the provider as the user whose email is %s and so redeems the invitation: an authorization request to the tenant, its domain_hint the Issuer URI, for Azure CLI; it ends on an error page of the browser, %s answering nothing, whose address carries the result:%s%s%s',
        $email,
        SAML_ENTRA_SIGN_IN_REDIRECT,
        \PHP_EOL,
        $signIn,
        \PHP_EOL,
    ));
    io()->success(sprintf('%s is registered; once the sign-in is played, "castor saml-entra --received" lists what Entra sent.', SAML_ENTRA_ENTITY_ID));
}

/**
 * What the provider received from Entra since the minutes given, read from the profiles of the stack: each message
 * written to var/saml-entra/received/, the document decoded and the bytes as they came, and described as it arrived.
 * A message posted again by the provider from its own origin (S-28) is the one Entra posted, and is written once.
 *
 * What is written for the corpus is what saml_entra_received_messages() keeps, the messages of the entity ID declared
 * for Entra that the provider accepted, and what is printed of them is text (saml_entra_text()): the profiles hold
 * every request the services were sent, from any browser and any host that reaches them, and none of it is Entra's word
 * until the provider took it as such.
 */
function saml_entra_received(string $issuer, int $minutes): void
{
    io()->section(sprintf('What the provider received from Entra in the last %d minutes', $minutes));
    $read = run(
        ['docker', 'compose', 'exec', '-T', 'op', 'php', '--', (string) (time() - ($minutes * 60)), '/saml/sso', '/saml/slo'],
        context: context()->withInput(SAML_ENTRA_PROFILE_READER)->withQuiet()->withAllowFailure(),
    );
    if (! $read->isSuccessful()) {
        io()->error(sprintf('The profiles of the op container cannot be read: %s', trim($read->getErrorOutput()) ?: '"castor start" first.'));
        exit(1);
    }
    /** @var list<array{token: string, time: int, method: string, url: string, status: int, query: string, fields: array<string, mixed>, body: string, secFetchSite: ?string}> $profiled */
    $profiled = json_decode($read->getOutput(), true, 512, \JSON_THROW_ON_ERROR);
    $received = saml_entra_received_messages($profiled);
    foreach ($received as ['message' => $message, 'requests' => $requests]) {
        $first = $requests[0];
        $base = sprintf('%s/%s-%s-%s', SAML_ENTRA_RECEIVED, date('Ymd\THis', $first['time']), $message['binding'], $message['root']);
        file_put_contents($base . '.xml', $message['document']);
        file_put_contents($base . '.raw.txt', $message['raw']);
        io()->section(saml_entra_text(sprintf('%s, %s over %s', date('c', $first['time']), $message['root'], $message['binding'])));
        io()->listing([
            saml_entra_text(sprintf('Issuer: %s, the entity ID declared', $message['issuer'])),
            saml_entra_text(sprintf('Signed: %s', $message['signed'] ? 'yes' : 'no')),
            ...array_map(
                static fn (array $request): string => saml_entra_text(sprintf(
                    '%s, answered %d, from another site: %s, profile %s/_profiler/%s',
                    saml_entra_posted_again($request) ? 'Posted again from the origin of the provider (S-28)' : 'Received',
                    $request['status'],
                    $request['secFetchSite'] ?? 'not said',
                    $issuer,
                    $request['token'],
                )),
                $requests,
            ),
            ...array_map(
                static fn (string $name, string $value): string => saml_entra_text(sprintf('%s: %s', $name, $value)),
                array_keys($message['facts']),
                array_values($message['facts']),
            ),
            saml_entra_text(sprintf('Written to %s.xml and %s.raw.txt', $base, $base)),
        ]);
        io()->writeln(saml_entra_text($message['document']));
    }
    if ($received === []) {
        io()->warning(sprintf(
            'Nothing the provider accepted from %s was profiled in the last %d minutes: --minutes reads further back; a stack started with --conformance collects no profile.',
            SAML_ENTRA_ENTITY_ID,
            $minutes,
        ));

        return;
    }
    io()->success(sprintf('%d document(s) received from Entra written to %s/: they go to the corpus (issue #665).', count($received), SAML_ENTRA_RECEIVED));
}

/**
 * The messages of Entra among the requests profiled, each with the requests that carried it, in the order they came: a
 * message whose Issuer is the entity ID declared for Entra, the string itself and not a prefix of it, which at least one
 * of its requests had the provider accept (saml_entra_accepted()). Entra signs no request (spec/saml.md section 7), so
 * that its signature cannot tell its messages apart: what the provider answered can, a message it refused, or one it
 * never read, being no request of Entra's for the corpus, whatever its Issuer says.
 *
 * @param list<array{token: string, time: int, method: string, url: string, status: int, query: string, fields: array<string, mixed>, body: string, secFetchSite: ?string}> $profiled
 * @return list<array{message: array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}, requests: non-empty-list<array{token: string, time: int, method: string, url: string, status: int, query: string, fields: array<string, mixed>, body: string, secFetchSite: ?string}>}>
 */
function saml_entra_received_messages(array $profiled): array
{
    $messages = [];
    foreach ($profiled as $request) {
        $message = saml_entra_message($request);
        if ($message === null || $message['issuer'] !== SAML_ENTRA_ENTITY_ID) {
            continue;
        }
        $digest = hash('sha256', $message['document']);
        $messages[$digest] ??= ['message' => $message, 'requests' => []];
        $messages[$digest]['requests'][] = $request;
    }

    return array_values(array_filter(
        $messages,
        static fn (array $received): bool => array_filter($received['requests'], saml_entra_accepted(...)) !== [],
    ));
}

/**
 * Whether the provider accepted a profiled request at its single sign-on or single logout service: a request it read
 * and answered with the login the request waits for (302) or the page that posts its answer (200), where a refusal is
 * answered 400 and the page that says so. A form posted from another site without the marker of the page that posts it
 * again is answered by that page (S-28), 200 as well, before anything of the message is read: it is not an answer of the
 * provider to the message.
 *
 * @param array{method: string, url: string, status: int, secFetchSite: ?string} $request
 */
function saml_entra_accepted(array $request): bool
{
    $answeredByThePageThatPostsAgain = $request['method'] === 'POST' && $request['secFetchSite'] === 'cross-site' && ! saml_entra_posted_again($request);

    return ! $answeredByThePageThatPostsAgain && in_array($request['status'], [200, 302], true);
}

/**
 * Whether a profiled request is the post the page of S-28 sent again from the origin of the provider: its URL carries
 * the marker of that page in its query.
 *
 * @param array{url: string} $request
 */
function saml_entra_posted_again(array $request): bool
{
    parse_str((string) parse_url($request['url'], \PHP_URL_QUERY), $query);

    return array_key_exists(SAML_POSTED_AGAIN, $query);
}

/**
 * A value received from the network, as text for the console: its markup escaped, so that a "<href=...>" or a
 * "<fg=...>" it holds is printed and never made a link or a colour by the formatter of the output, and every control
 * character but the tab and the line feed written as its bytes in hexadecimal, a C1 control included, which XML 1.0
 * lets into a document, so that none reaches the terminal as one of its sequences.
 */
function saml_entra_text(string $value): string
{
    return OutputFormatter::escape((string) preg_replace_callback(
        '/[\x00-\x08\x0B-\x1F\x7F]|\xC2[\x80-\x9F]/',
        static fn (array $control): string => '\\x' . bin2hex($control[0]),
        $value,
    ));
}

/**
 * The SAML message a profiled request carried, decoded as its binding encodes it: the raw query string of
 * HTTP-Redirect, its message deflated (SAML Bindings §3.4.4.1), or the field of HTTP-POST (§3.5.4); null when it
 * carries none, or one that does not decode to XML.
 *
 * @param array{method: string, query: string, fields: array<string, mixed>, body: string} $request
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_message(array $request): ?array
{
    if ($request['method'] === 'GET') {
        parse_str($request['query'], $parameters);

        return saml_entra_message_of('redirect', $request['query'], $parameters);
    }

    return saml_entra_message_of('post', $request['body'], $request['fields']);
}

/**
 * The SAML message of the parameters of a binding, the raw query string or body they came in beside them: decoded as
 * that binding encodes it, its message deflated over HTTP-Redirect (SAML Bindings §3.4.4.1) and not over HTTP-POST
 * (§3.5.4), and described by what a request says of the sign-on it asks for, or by what a Response says of the person;
 * null when it carries none, or one that does not decode to XML.
 *
 * @param 'redirect'|'post' $binding
 * @param array<array-key, mixed> $parameters
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_message_of(string $binding, string $raw, array $parameters): ?array
{
    $encoded = $parameters['SAMLRequest'] ?? $parameters['SAMLResponse'] ?? null;
    if (! is_string($encoded)) {
        return null;
    }
    $bytes = base64_decode($encoded, true);
    $document = $bytes;
    if ($bytes !== false && $binding === 'redirect') {
        $document = @gzinflate($bytes);
    }
    $dom = new DOMDocument();
    if (! is_string($document) || ! @$dom->loadXML($document, \LIBXML_NONET) || ! $dom->documentElement instanceof DOMElement) {
        return null;
    }
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $root = $dom->documentElement;
    $facts = $root->localName === 'Response' ? saml_entra_response_facts($xpath, $root) : saml_entra_request_facts($xpath, $root);

    return [
        'binding' => $binding,
        'raw' => $raw,
        'document' => $document,
        'root' => $root->localName,
        'issuer' => trim((string) $xpath->evaluate('string(saml:Issuer)', $root)),
        'signed' => isset($parameters['Signature']) || $xpath->query('ds:Signature', $root)?->length > 0,
        'facts' => $facts,
    ];
}

/**
 * What a request says of the sign-on it asks for, attribute by attribute of its root, "absent" for what it leaves out.
 *
 * @return array<string, string>
 */
function saml_entra_request_facts(DOMXPath $xpath, DOMElement $root): array
{
    $facts = [];
    foreach (['Destination', 'AssertionConsumerServiceURL', 'AssertionConsumerServiceIndex', 'ProtocolBinding', 'ForceAuthn', 'IsPassive'] as $attribute) {
        $facts[$attribute] = $root->hasAttribute($attribute) ? $root->getAttribute($attribute) : 'absent';
    }
    $policy = $xpath->query('samlp:NameIDPolicy', $root)?->item(0);
    $facts['NameIDPolicy'] = $policy instanceof DOMElement
        ? sprintf('Format %s, AllowCreate %s', $policy->getAttribute('Format') ?: 'absent', $policy->getAttribute('AllowCreate') ?: 'absent')
        : 'absent';
    $contexts = array_map(
        static fn (DOMNode $reference): string => trim($reference->textContent),
        iterator_to_array($xpath->query('samlp:RequestedAuthnContext/saml:AuthnContextClassRef', $root) ?: []),
    );
    $facts['RequestedAuthnContext'] = $xpath->query('samlp:RequestedAuthnContext', $root)?->length
        ? sprintf(
            'Comparison %s, %s',
            $xpath->evaluate('string(samlp:RequestedAuthnContext/@Comparison)', $root) ?: 'absent',
            implode(', ', $contexts) ?: 'no class',
        )
        : 'absent';

    return $facts;
}

/**
 * What a Response says of the person and of itself: its envelope, which of it is signed, the format of the NameID, the
 * class of the authentication, the windows of the assertion (issue #722) and the name of each attribute with the
 * number of its values, never the values.
 *
 * @return array<string, string>
 */
function saml_entra_response_facts(DOMXPath $xpath, DOMElement $root): array
{
    $read = static fn (string $expression): string => trim((string) $xpath->evaluate(sprintf('string(%s)', $expression), $root)) ?: 'absent';
    $count = static fn (string $expression): int => (int) $xpath->evaluate(sprintf('count(%s)', $expression), $root);
    $attributes = [];
    foreach ($xpath->query('saml:Assertion/saml:AttributeStatement/saml:Attribute', $root) ?: [] as $attribute) {
        if ($attribute instanceof DOMElement) {
            $attributes[] = sprintf('%s (%d)', $attribute->getAttribute('Name'), $xpath->query('saml:AttributeValue', $attribute)->length ?? 0);
        }
    }

    return [
        'IssueInstant' => $read('@IssueInstant'),
        'Destination' => $read('@Destination'),
        'InResponseTo' => $read('@InResponseTo'),
        'Status' => $read('samlp:Status/samlp:StatusCode/@Value'),
        'Signature of the Response' => $count('ds:Signature') > 0 ? 'yes' : 'no',
        'Assertion' => match (true) {
            $count('saml:EncryptedAssertion') > 0 => 'encrypted',
            $count('saml:Assertion/ds:Signature') > 0 => 'in clear, signed',
            default => 'in clear, unsigned',
        },
        'NameID' => sprintf('Format %s', $read('saml:Assertion/saml:Subject/saml:NameID/@Format')),
        'AuthnContextClassRef' => $read('saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef'),
        'Conditions' => sprintf('from %s to %s', $read('saml:Assertion/saml:Conditions/@NotBefore'), $read('saml:Assertion/saml:Conditions/@NotOnOrAfter')),
        'Bearer NotOnOrAfter' => $read('saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter'),
        'Attributes, by name and number of values' => implode(', ', $attributes) ?: 'none',
    ];
}

/**
 * The provider made ready for a sign-in through Entra by hand (--upstream): the service provider of the tenant served
 * as the portal of Entra holds it, the metadata of the enterprise application read, the group of the mapping created,
 * and the walk played up to the AuthnRequest the browser would carry to Entra, which is decoded and checked, and never
 * sent; then the page the maintainer opens.
 */
function saml_entra_upstream(): void
{
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    if (($env['BEFFROI_ISSUER'] ?? '') === '') {
        io()->error('BEFFROI_ISSUER is empty: run "castor provision" first.');
        exit(1);
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');
    $ca = caddy_ca(getcwd() . '/' . SAML_ENTRA_DIRECTORY . '/caddy-root.crt');

    io()->section('The service provider of the tenant, as the portal of Entra holds it');
    $cookies = [];
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $issuer . '/saml/sp/metadata');
    demo_expect($status === 200, sprintf('%s/saml/sp/metadata serves the metadata of the service provider (got %d)', $issuer, $status));
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document, \LIBXML_NONET), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $acs = (string) $xpath->evaluate('string(/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location)');
    demo_expect(
        $entityId === SAML_ENTRA_SP_IDENTIFIER && $acs === SAML_ENTRA_SP_REPLY_URL,
        sprintf(
            'its entity ID %s and its assertion consumer service %s, the Identifier and the Reply URL of the enterprise application',
            $entityId,
            $acs,
        ),
    );

    io()->section('The provider federates Entra');
    $refresh = op_console(['beffroi:saml:identity-provider:refresh', SAML_ENTRA_IDP_ENTITY_ID, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect(
        $refresh->isSuccessful(),
        sprintf(
            'beffroi:saml:identity-provider:refresh reads the Federation Metadata XML of the enterprise application (apps/op/config/saml/entra-enterprise-application-idp.xml)%s',
            $refresh->isSuccessful() ? '' : ': ' . trim($refresh->getOutput() . $refresh->getErrorOutput()),
        ),
    );
    $group = op_console(['beffroi:group:create', SAML_ENTRA_GROUP, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect(
        $group->isSuccessful() || str_contains($group->getOutput() . $group->getErrorOutput(), 'already'),
        sprintf('the tenant holds the group "%s", which the object ID of "Lab Finance" maps to (beffroi:group:create)', SAML_ENTRA_GROUP),
    );

    io()->section('The walk up to Entra, and no further');
    $base64url = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    $verifier = $base64url(random_bytes(32));
    $cookies = [];
    [$status, $login] = demo_request(
        $cookies,
        $ca,
        'GET',
        $issuer . '/authorize?'
            . http_build_query([
                'response_type' => 'code',
                'client_id' => DEMO_CLIENT_ID,
                'redirect_uri' => DEMO_URL . '/oidc/callback',
                'scope' => 'openid profile email',
                'state' => $base64url(random_bytes(16)),
                'nonce' => $base64url(random_bytes(16)),
                'code_challenge' => $base64url(hash('sha256', $verifier, true)),
                'code_challenge_method' => 'S256',
            ]),
    );
    demo_expect(
        $status === 302 && str_starts_with($login, $issuer . '/login?interaction='),
        sprintf('oidc-demo asks for an authorization, and the provider asks for a login (got %d %s)', $status, substr($login, 0, 120)),
    );
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $login);
    $form = $status === 200 ? demo_form_with($page, '_address', 'the login page asks for the address first') : '';
    demo_expect(
        preg_match('/name="_token" value="([^"]+)"/', $form, $token) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'its form: one field, its token, where it posts',
    );
    [$status, $signOn] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_address' => SAML_ENTRA_PEOPLE['alice'],
        '_token' => $token[1],
    ]);
    parse_str((string) parse_url($signOn, \PHP_URL_QUERY), $query);
    demo_expect(
        $status === 303
        && str_starts_with($signOn, $issuer . '/saml/sp/sign-on?')
        && ($query['identity_provider'] ?? null) === SAML_ENTRA_IDP_ENTITY_ID
        && is_string($query['reference'] ?? null)
        && preg_match('/^[A-Za-z0-9_-]{43}$/', $query['reference']) === 1,
        sprintf(
            '%s is sent to the sign-on of Entra, under the one-time reference the login page drew for it, spec/saml.md S-51 (got %d %s)',
            SAML_ENTRA_PEOPLE['alice'],
            $status,
            substr($signOn, 0, 160),
        ),
    );
    [$status, $location] = demo_request($cookies, $ca, 'GET', $signOn);
    demo_expect(
        $status === 302 && str_starts_with($location, SAML_ENTRA_IDP_SINGLE_SIGN_ON . '?'),
        sprintf('the sign-on sends the browser to the single sign-on service of Entra over HTTP-Redirect (got %d %s)', $status, substr($location, 0, 120)),
    );
    $raw = (string) parse_url($location, \PHP_URL_QUERY);
    parse_str($raw, $parameters);
    $request = saml_entra_message_of('redirect', $raw, $parameters);
    demo_expect(
        $request !== null && $request['root'] === 'AuthnRequest' && isset($parameters['SigAlg'], $parameters['Signature'], $parameters['RelayState']),
        'an AuthnRequest, signed over the query string, with a RelayState',
    );
    demo_expect(
        ($parameters['login_hint'] ?? null) === SAML_ENTRA_PEOPLE['alice'] && str_ends_with($raw, '&login_hint=' . rawurlencode(SAML_ENTRA_PEOPLE['alice'])),
        sprintf(
            'the address typed, %s, in the login_hint Entra prefills its sign-in with, after the Signature (spec/saml.md S-68)',
            SAML_ENTRA_PEOPLE['alice'],
        ),
    );
    demo_expect(
        $request['issuer'] === SAML_ENTRA_SP_IDENTIFIER && $request['facts']['AssertionConsumerServiceURL'] === SAML_ENTRA_SP_REPLY_URL,
        sprintf(
            'its Issuer and its AssertionConsumerServiceURL are the Identifier and the Reply URL Entra holds (%s, %s)',
            $request['issuer'],
            $request['facts']['AssertionConsumerServiceURL'],
        ),
    );
    io()->listing(array_map(
        static fn (string $name, string $value): string => saml_entra_text(sprintf('%s: %s', $name, $value)),
        array_keys($request['facts']),
        array_values($request['facts']),
    ));
    io()->text('Not sent: the sign-in at Entra is played by hand.');

    io()->section('The sign-in, by hand');
    io()->listing([
        sprintf('"castor demo" serves oidc-demo on %s ("--dir" names its checkout when it is not next to this one).', DEMO_URL),
        sprintf('In a private window, open %s/profile: the login page of the provider asks for the address, %s.', DEMO_URL, SAML_ENTRA_PEOPLE['alice']),
        'Entra shows its sign-in with her address filled in (login_hint, spec/saml.md S-68), signs her in, then posts its response to the provider, which creates her and answers oidc-demo: /profile shows email, given_name and family_name under "Standard claims", and amr under "ID token".',
        sprintf('Then bob, in another private window, %s: Entra holds the session of alice in the first one.', SAML_ENTRA_PEOPLE['bob']),
        sprintf(
            '"castor console beffroi:user:show <address>" says what the provider holds of each, its source, and bob in the group "%s".',
            SAML_ENTRA_GROUP,
        ),
        'In the network panel, the URL of the request to login.microsoftonline.com and the SAMLResponse posted to /saml/sp/acs, each saved to a file, are decoded into the corpus by "castor saml-entra --captured <file> --captured <file>".',
    ]);
    io()->success(sprintf('%s federates Entra; open %s/profile.', $issuer, DEMO_URL));
}

/**
 * What the browser carried between the stack and Entra, decoded into the corpus of saml2-model (--captured), each
 * document named by its origin, as the corpus names them, and by the date of its IssueInstant: the AuthnRequest of the
 * provider, the XML the query string carries and the query string itself, which its signature covers; the Response of
 * Entra, by what it signs, and its assertion, the bytes of the response from its first tag to its last when they stand
 * as a document of their own. Anything else is refused, and a file of the corpus is never written over with other bytes.
 *
 * @param list<string> $files
 */
function saml_entra_corpus(array $files): void
{
    $written = [];
    foreach ($files as $file) {
        io()->section(saml_entra_text($file));
        $contents = is_file($file) ? file_get_contents($file) : false;
        if (! is_string($contents)) {
            io()->error(sprintf('%s cannot be read.', $file));
            exit(1);
        }
        $message = saml_entra_captured_message($contents);
        if ($message === null) {
            io()->error('It carries no SAMLRequest or SAMLResponse that decodes to XML: the URL of the request, its query, the form posted, or the value of the field alone.');
            exit(1);
        }
        $date = preg_match('/\bIssueInstant="(\d{4}-\d{2}-\d{2})T/', $message['document'], $issued) === 1 ? $issued[1] : null;
        if ($date === null) {
            io()->error(sprintf('Its %s carries no IssueInstant to date it by.', $message['root']));
            exit(1);
        }
        $documents = match (true) {
            $message['root'] === 'AuthnRequest' && $message['issuer'] === SAML_ENTRA_SP_IDENTIFIER => array_filter(
                [
                    sprintf('beffroi-sp-authnrequest-to-entra-%s.xml', $date) => $message['document'],
                    sprintf('beffroi-sp-authnrequest-to-entra-query-%s.txt', $date) =>
                        $message['binding'] === 'redirect' && $message['raw'] !== '' ? $message['raw'] : null,
                ],
                is_string(...),
            ),
            $message['root'] === 'Response' && $message['issuer'] === SAML_ENTRA_IDP_ENTITY_ID => array_filter(
                [
                    sprintf('entra-idp-response-%s-%s.xml', saml_entra_coverage($message['facts']), $date) => $message['document'],
                    sprintf('entra-idp-assertion-%s.xml', $date) => saml_entra_assertion_of($message['document']),
                ],
                is_string(...),
            ),
            default => null,
        };
        if ($documents === null) {
            io()->error(saml_entra_text(sprintf(
                'A %s from %s is neither the AuthnRequest of %s nor the Response of %s.',
                $message['root'],
                $message['issuer'],
                SAML_ENTRA_SP_IDENTIFIER,
                SAML_ENTRA_IDP_ENTITY_ID,
            )));
            exit(1);
        }
        io()->listing([
            saml_entra_text(sprintf('%s from %s, over %s', $message['root'], $message['issuer'], $message['binding'])),
            ...array_map(
                static fn (string $name, string $value): string => saml_entra_text(sprintf('%s: %s', $name, $value)),
                array_keys($message['facts']),
                array_values($message['facts']),
            ),
        ]);
        foreach ($documents as $name => $bytes) {
            $path = SAML_ENTRA_CORPUS . '/' . $name;
            if (is_file($path) && file_get_contents($path) !== $bytes) {
                io()->error(sprintf('%s holds another capture of that day: a document enters the corpus once; remove it first to replace it.', $path));
                exit(1);
            }
            file_put_contents($path, $bytes);
            $written[] = $path;
        }
        if ($message['root'] === 'Response' && ! array_key_exists(sprintf('entra-idp-assertion-%s.xml', $date), $documents)) {
            io()->warning('Its assertion does not stand as a document of its own (encrypted, or a prefix the response declares): only the response is written.');
        }
    }
    io()->listing($written);
    io()->success('Written to the corpus, not committed: each enters it with its row in tests/saml2-model/Unit/RealDocumentsTest.php and its line in spec/model.md section 9.4 (issue #665).');
}

/**
 * The SAML message a file captured from the browser holds: a URL or a query string carrying SAMLRequest, a form body
 * carrying SAMLResponse, or the value of either alone, as the network panel shows it, decoded or not. The binding is
 * read from the bytes, a message that is XML once its base64 is decoded being posted and one that is not being
 * deflated (SAML Bindings §3.4.4.1, §3.5.4).
 *
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_captured_message(string $contents): ?array
{
    $contents = trim($contents);
    if (preg_match('/(?:^|[?&])SAML(?:Request|Response)=/', $contents) === 1) {
        $raw = str_contains($contents, '?') ? substr($contents, strpos($contents, '?') + 1) : $contents;
        $raw = explode('#', $raw, 2)[0];
        parse_str($raw, $parameters);
    } else {
        // the value alone: no query string to keep, the signature of a redirect being over the query
        $raw = '';
        $parameters = ['SAMLResponse' => str_contains($contents, '%') ? rawurldecode($contents) : $contents];
    }
    foreach (['SAMLRequest', 'SAMLResponse'] as $name) {
        if (is_string($parameters[$name] ?? null)) {
            // base64 holds no space: one is a "+" a form decoding took for one
            $parameters[$name] = (string) preg_replace('/[\r\n\t]/', '', strtr($parameters[$name], ' ', '+'));
        }
    }
    $encoded = $parameters['SAMLRequest'] ?? $parameters['SAMLResponse'] ?? null;
    $bytes = is_string($encoded) ? base64_decode($encoded, true) : false;
    if ($bytes === false) {
        return null;
    }
    $posted = str_starts_with(ltrim(str_starts_with($bytes, "\u{FEFF}") ? substr($bytes, 3) : $bytes), '<');

    return saml_entra_message_of($posted ? 'post' : 'redirect', $raw, $parameters);
}

/**
 * What a Response of Entra signs, as the corpus names it: "signed-both" for Entra's "Sign SAML response and
 * assertion", "signed-response" or "signed-assertion" for one of them, "unsigned" otherwise.
 *
 * @param array<string, string> $facts
 */
function saml_entra_coverage(array $facts): string
{
    $response = ($facts['Signature of the Response'] ?? '') === 'yes';
    $assertion = ($facts['Assertion'] ?? '') === 'in clear, signed';

    return match (true) {
        $response && $assertion => 'signed-both',
        $response => 'signed-response',
        $assertion => 'signed-assertion',
        default => 'unsigned',
    };
}

/**
 * The assertion of a Response, its bytes from its first tag to its last as the response carries them, when they stand
 * as a document of their own, an assertion of SAML 2.0 at their root: Entra declares the namespace of the assertion on
 * it. Null otherwise: an encrypted assertion, or one using a prefix its response declares.
 */
function saml_entra_assertion_of(string $response): ?string
{
    if (preg_match('~<((?:[A-Za-z_][\w.-]*:)?)Assertion\b.*</\1Assertion>~s', $response, $matches) !== 1) {
        return null;
    }
    $dom = new DOMDocument();
    if (! @$dom->loadXML($matches[0], \LIBXML_NONET) || ! $dom->documentElement instanceof DOMElement) {
        return null;
    }

    return $dom->documentElement->namespaceURI === 'urn:oasis:names:tc:SAML:2.0:assertion' && $dom->documentElement->localName === 'Assertion'
        ? $matches[0]
        : null;
}
