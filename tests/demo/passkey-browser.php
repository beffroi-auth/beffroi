<?php

declare(strict_types=1);

/*
 * The passkey side of "castor demo --passkey" (castor.php, demo_passkey_check): a browser holding a
 * software authenticator, the SoftwareAuthenticator of the functional tests, driven over HTTP against
 * the running OP the way the script of the bundle drives the two ceremonies. The task is what runs
 * under castor, which loads no code of the monorepo; this script runs under the autoloader of the
 * monorepo, in one process, so that the key pair generated at the enrolment signs the assertion.
 *
 * Reads one JSON object on stdin: "issuer", "cafile", "cookies" (name to value, the cookies the task
 * holds on the OP), "interaction" (the interaction the login page is asked for), "name" (the name
 * of the passkey) and "username" (what the step of the address is answered with, when the tenant
 * federates a domain and the login page asks for an address first, beffroi/saml S-61). Enrols a hardware key without a PIN on the account of the session the cookies bind
 * (WebAuthn Level 3 §7.1), then signs in with it on the login page of the interaction (§7.2). Writes
 * one JSON object on stdout: "cookies" as the OP left them, "location" the login page sent the browser
 * to, "credential_id" of the passkey (base64url) and "sign_count" after the assertion.
 */

use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * The HTTP side: cookies kept as the task keeps them, no redirect followed, the CA of the OP verified.
 */
final class PasskeyBrowser
{
    private readonly HttpClientInterface $http;

    /**
     * @param array<string, string> $cookies name => value
     */
    public function __construct(
        private readonly string $issuer,
        string $cafile,
        public array $cookies,
    ) {
        $this->http = HttpClient::create([
            'max_redirects' => 0,
            'cafile' => $cafile,
        ]);
    }

    /**
     * §7.1 through the account page: the token of the form, the creation options, the attestation posted.
     */
    public function enrol(SoftwareAuthenticator $device, string $name): void
    {
        [$status, , $page] = $this->request('GET', '/account/passkeys');
        self::expect($status === 200, sprintf('the account page opens for the session of the browser (got %d)', $status));
        $token = self::capture('/data-passkey="enrol".*?name="_token" value="([^"]+)"/s', $page, 'the account page carries the enrolment form');
        [$status, , $options] = $this->request('POST', '/account/passkeys/options');
        self::expect($status === 200, sprintf('the creation options are given (got %d)', $status));
        [$status, $location, $page] = $this->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => $name,
            '_passkey' => $device->create($options),
        ]);
        self::expect(
            $status === 302 && str_ends_with($location, '/account/passkeys'),
            sprintf('the passkey is enrolled (got %d %s)', $status, $status === 302 ? $location : self::reason($page)),
        );
    }

    /**
     * §7.2 through the login page of the interaction: the step of the address when the page asks for one
     * first (beffroi/saml S-61), a username being of no domain and sent on to the usual page; then the
     * token of the form, the request options, the assertion posted. Returns where the login page sends the
     * browser.
     */
    public function login(SoftwareAuthenticator $device, string $interaction, string $username): string
    {
        [$status, , $page] = $this->request('GET', '/login?interaction=' . rawurlencode($interaction));
        self::expect($status === 200, sprintf('the login page opens (got %d)', $status));
        if (str_contains($page, 'data-step="address"')) {
            $action = self::capture('/<form method="post" action="([^"]+)" data-step="address"/', $page, 'the login page asks for the address first');
            $token = self::capture('/data-step="address".*?name="_token" value="([^"]+)"/s', $page, 'and carries the token of its form');
            [$status] = $this->request('POST', $action, [
                '_address' => $username,
                '_token' => $token,
            ]);
            self::expect(in_array($status, [302, 303], true), sprintf('a username goes on to the usual login page (got %d)', $status));
            [$status, , $page] = $this->request('GET', '/login?interaction=' . rawurlencode($interaction));
            self::expect($status === 200, sprintf('which opens (got %d)', $status));
        }
        $token = self::capture('/data-passkey="login".*?name="_csrf_token" value="([^"]+)"/s', $page, 'the login page offers the passkey');
        [$status, , $options] = $this->request('POST', '/login/passkey/options?interaction=' . rawurlencode($interaction));
        self::expect($status === 200, sprintf('the request options are given (got %d)', $status));
        [$status, $location, $page] = $this->request('POST', '/login/passkey?interaction=' . rawurlencode($interaction), [
            '_csrf_token' => $token,
            '_passkey' => $device->get($options),
        ]);
        self::expect($status === 302, sprintf(
            'the assertion is accepted, back to the login page (got %d %s)',
            $status,
            $status === 302 ? $location : self::reason($page),
        ));

        return $location;
    }

    /**
     * @param array<string, string> $form
     * @return array{int, string, string} status, Location, body
     */
    private function request(string $method, string $path, array $form = []): array
    {
        $options = [
            'headers' => [
                'Cookie' => implode('; ', array_map(
                    static fn (string $name, string $value): string => $name . '=' . $value,
                    array_keys($this->cookies),
                    array_values($this->cookies),
                )),
            ],
        ];
        if ($form !== []) {
            $options['body'] = $form;
        }
        $response = $this->http->request($method, $this->issuer . $path, $options);
        $headers = $response->getHeaders(false);
        foreach ($headers['set-cookie'] ?? [] as $cookie) {
            [$pair] = explode(';', $cookie, 2);
            [$name, $value] = explode('=', $pair, 2)
            + [
                1 => '',
            ];
            $this->cookies[trim($name)] = trim($value);
        }
        $location = $headers['location'][0] ?? '';
        if (str_starts_with($location, '/')) {
            $location = $this->issuer . $location;
        }

        return [$response->getStatusCode(), $location, $response->getContent(false)];
    }

    /**
     * What an error page of the OP says, for the message of a failed expectation.
     */
    private static function reason(string $page): string
    {
        return preg_match('/<h1[^>]*>([^<]+)<\/h1>|<p[^>]*data-error[^>]*>([^<]+)<\/p>/', $page, $found) === 1 ? trim($found[2] ?? $found[1]) : '';
    }

    /**
     * The first group of the pattern in the page, an expectation of its own.
     */
    private static function capture(string $pattern, string $page, string $what): string
    {
        $found = preg_match($pattern, $page, $groups) === 1 ? $groups[1] : null;
        self::expect($found !== null, $what);

        return html_entity_decode((string) $found);
    }

    /**
     * Each step told on stderr, the way the task tells its own; a failed one ends the script, whose exit
     * code the task reads (an uncaught exception, PHP exits with 255).
     */
    private static function expect(bool $condition, string $what): void
    {
        if (! $condition) {
            throw new RuntimeException('Not verified: ' . $what);
        }
        fwrite(\STDERR, ' ✓ ' . $what . "\n");
    }
}

/** @var array{issuer?: mixed, cafile?: mixed, cookies?: mixed, interaction?: mixed, name?: mixed, username?: mixed} $input */
$input = (array) json_decode((string) stream_get_contents(\STDIN), true, 8, \JSON_THROW_ON_ERROR);
$issuer = $input['issuer'] ?? null;
$cafile = $input['cafile'] ?? null;
$interaction = $input['interaction'] ?? null;
$name = $input['name'] ?? null;
$username = $input['username'] ?? null;
if (! is_string($issuer) || ! is_string($cafile) || ! is_string($interaction) || ! is_string($name) || ! is_string($username)) {
    throw new RuntimeException('The input names no issuer, cafile, interaction, name or username.');
}
$cookies = [];
foreach ((array) ($input['cookies'] ?? []) as $cookieName => $value) {
    if (is_string($value)) {
        $cookies[(string) $cookieName] = $value;
    }
}

// a hardware key without a PIN (userVerified false), bound to its authenticator (not synced): "hwk" and
// "user", the "phr" class of the default policy of the tenant; the origin is the issuer itself
$device = new SoftwareAuthenticator($issuer);
$browser = new PasskeyBrowser($issuer, $cafile, $cookies);
$browser->enrol($device, $name);
$location = $browser->login($device, $interaction, $username);

fwrite(
    \STDOUT,
    json_encode(
        [
            'cookies' => $browser->cookies,
            'location' => $location,
            'credential_id' => Base64UrlSafe::encodeUnpadded($device->credentialId),
            'sign_count' => $device->signCount,
        ],
        \JSON_THROW_ON_ERROR,
    )
        . "\n",
);
