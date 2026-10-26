<?php

declare(strict_types=1);

/*
 * The third success criterion of spike 8 (issue #399): what a login costs on the development stack, and how
 * many times the KMS was asked for something while it was being served. The baseline is taken before the
 * first column is encrypted and the same run is taken again after the last one, by hand, twice, on one
 * machine, and read against the threshold decision 0018 fixes on the first day of the spike.
 *
 * Two numbers per run and no more: the p95 of the whole journey, and the count of what the KMS was asked.
 * The count is read in the log of the KMS itself and never in ours, because what our own code reports of
 * its own calls is what our own code decides to report, and the criterion is about what left the process.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;

/**
 * Where the internal CA of Caddy is copied for the PHP of the host, as the walks of the laboratory copy it
 * for themselves: the OP serves a certificate of an authority that exists only inside the stack.
 */
const COST_CA_FILE = 'var/caddy-root.crt';

/**
 * How many complete logins a run plays by default. The p95 is the smallest journey that ninety-five percent
 * of them are at or under, so fifty samples name the 48th: many fewer and the p95 is the slowest journey
 * under another name, many more and a measurement taken by hand stops being taken twice.
 */
const COST_JOURNEYS = 50;

/**
 * The fewest journeys a run accepts, below which what it printed would not be a p95 of anything.
 */
const COST_JOURNEYS_MINIMUM = 20;

/**
 * How many journeys are played and thrown away before the ones that count. What they take out of the figure
 * is the first journeys of a cold process, which are not what a stack that is serving costs: production is
 * warm, and the ceiling of decision 0018 is written in the server time of a stack that serves. What they do
 * not do, measured rather than assumed, is narrow the dispersion between two runs: that dispersion is the
 * machine's, it is of the same order as the threshold, and the journal of the spike states it.
 */
const COST_WARM_UP = 5;

/**
 * What decision 0018 allows the p95 of the journey to grow by over the baseline taken before the first
 * column was encrypted: twenty percent, which on a journey dominated by an argon2id verification at PHP's
 * defaults is of the order of a few tens of milliseconds, an order of magnitude above what an AES-256-GCM
 * on a key already in memory asks for.
 */
const COST_MARGIN = 1.20;

/**
 * The absolute ceiling of decision 0018, in seconds: no request of the journey above 800 ms at the p95, the
 * "good" line of the TTFB metric of the Core Web Vitals (web.dev, "Time to First Byte (TTFB)", read on
 * 2026-09-30). It does not decide the spike; it is the line under which the relative threshold is read, so
 * that a baseline which is already slow does not make +20 % acceptable.
 */
const COST_CEILING = 0.800;

/**
 * The requests of the step of the address, which a tenant that federates an e-mail domain to an upstream identity
 * provider asks for before the login page (beffroi/saml S-61), as the development tenant does since issue #788: the
 * address posted, and the usual login page opened again. They are measured apart and left out of the sum of the
 * journey, whose p95 stays the one of the eight requests the baselines of decision 0018 were taken on; each of them is
 * still held to the ceiling, as every request is.
 */
const COST_ADDRESS_STEPS = ['address', 'login page after the address'];

/**
 * The KMS the count is read from, which is the value "--kms" takes for it, the compose profile that runs it
 * and the name of its service, all three being the same word (KMS_BACKENDS, compose.yaml).
 *
 * Vault is the KMS of the spike, and its audit device is the one log of the stack that says what the OP
 * asked for without the OP being asked. A local backend has none: the master key lives in the process, so
 * there is nothing on a network to log and no count to read. LocalStack writes an access log of its own,
 * one line per call it serves, which nothing of this repository reads yet; what would read it goes beside
 * cost_kms_calls(), the day a run is taken on the aws backend.
 */
const COST_KMS = 'vault';

#[AsTask(
    description: 'Measure the cost of a login (issue #399): play complete logins against the running stack, one after another, and print the p95 of the journey and the number of times the KMS was asked for something while they were served, read in the audit device of Vault and not in the application. Two numbers, to be written in the journal of the spike with the commit they were taken at: the baseline before the first column is encrypted, the same run after the last one, and --baseline reads the second against the first at the +20 % decision 0018 allows',
)]
function login_cost(
    #[AsOption(
        description: 'How many complete logins to play; the run this one is compared with plays the same number, the p95 of a hundred journeys being another figure than the p95 of fifty',
    )]
    int $journeys = COST_JOURNEYS,
    #[AsOption(
        description: 'The p95 of an earlier run, in milliseconds, to read this one against: decision 0018 allows at most +20 % on the baseline taken before the first column was encrypted',
    )]
    ?float $baseline = null,
): void {
    io()->title('The cost of a login');

    if ($journeys < COST_JOURNEYS_MINIMUM) {
        io()->error(sprintf(
            'A p95 of %d journeys is the slowest of them under another name: %d is the fewest this task takes.',
            $journeys,
            COST_JOURNEYS_MINIMUM,
        ));
        exit(1);
    }

    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['BEFFROI_ISSUER', 'BEFFROI_DEV_USER_PASSWORD', 'OIDC_DEMO_SECRET'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
            exit(1);
        }
    }

    // Before a single journey is played: fifty logins take a minute, and a stack whose master key lives in
    // the process cannot answer half of what is being measured whatever they cost.
    $backend = kms_backend_of((string) ($env['BEFFROI_KMS_DSN'] ?? ''));
    if ($backend === null) {
        io()->error(sprintf('%s names no KMS: run "castor provision --kms %s" first.', DEV_ENV_LOCAL, COST_KMS));
        exit(1);
    }
    if ($backend !== COST_KMS) {
        io()->error([
            sprintf('The keys of this stack are sealed by the %s backend, which keeps the master key in the process and logs nothing.', $backend),
            sprintf(
                'The count of the third success criterion is read in the log of the KMS (decision 0018), so this run needs the %s backend: remove BEFFROI_KMS_DSN and BEFFROI_KMS_KEY_ID from %s, then run "castor start --kms %s", "castor provision --kms %s", and "castor console beffroi:keys:rotate --now --algorithm=X" once for every algorithm the provider is wired with, the envelopes of the previous backend opening under none of them.',
                COST_KMS,
                DEV_ENV_LOCAL,
                COST_KMS,
                COST_KMS,
            ),
        ]);
        exit(1);
    }
    if (! in_array(COST_KMS, compose_running_services(), true)) {
        io()->error(sprintf('The %s container is not running, so there is no KMS log to read: run "castor start --kms %s".', COST_KMS, COST_KMS));
        exit(1);
    }

    $issuer = $env['BEFFROI_ISSUER'];
    $instrumented = cost_instrumented($issuer);
    if ($instrumented !== []) {
        io()->error([
            sprintf('This stack is instrumented: %s.', implode(' and ', $instrumented)),
            sprintf(
                'A p95 taken then is the instrumentation as much as the provider, and the two do not grow alike: the profiler collects what the decorators the bundle wires under kernel.debug record, which is one entry per value opened, seventeen for one read of a user. Measured, the same commit gave 1234 ms instrumented and 871 ms not. Write APP_DEBUG=0 and APP_PROFILER=0 in %s, restart the op container, and run this again.',
                DEV_ENV_LOCAL,
            ),
        ]);
        exit(1);
    }
    $ca = caddy_ca(getcwd() . '/' . COST_CA_FILE);

    io()->section('What is played');
    io()->text([
        sprintf(' The eight requests a browser makes of the OP to sign %s in as the client %s, with nothing in front of', DEV_USERNAME, DEMO_CLIENT_ID),
        ' it: the authorization request the OP parks, its login page, the password argon2id verifies at the',
        ' defaults of PHP (RFC 9106 §4), the interaction resumed, the consent page and the consent answered',
        ' (OIDC Core §3.1.2.4), the code exchanged for a token (RFC 6749 §4.1.3, RFC 7636 §4.5) and UserInfo',
        ' read with it (OIDC Core §5.3). The Symfony application of the demonstration is left out: what is',
        ' measured is what the provider spends.',
        '',
        ' A tenant that federates an e-mail domain to an upstream identity provider, as the development tenant',
        ' does since issue #788, asks for the address first (beffroi/saml S-61): two requests more, the address',
        ' posted and the login page opened again. They are measured apart and left out of the journey, so that',
        ' its p95 is still the one of the eight requests the baselines of decision 0018 were taken on; each of',
        ' them is held to the ceiling all the same.',
        '',
        ' Every journey carries a cookie jar of its own, so every one of them is a login and not a session',
        ' already open, and every one of them asks for a consent, so that the last journey is the same journey',
        ' as the first. The seconds are taken on this machine over the loopback interface, so they are the',
        sprintf(' server time and a round trip on it, which is the conservative way round to read a %d ms ceiling.', (int) (COST_CEILING * 1000)),
    ]);

    io()->section(sprintf('%d journeys, after %d thrown away', $journeys, COST_WARM_UP));
    io()->text(sprintf(' Warming up: %d journeys played and thrown away.', COST_WARM_UP));
    for ($journey = 0; $journey < COST_WARM_UP; ++$journey) {
        cost_journey($issuer, $env['BEFFROI_DEV_USER_PASSWORD'], $env['OIDC_DEMO_SECRET'], $ca);
    }
    // The window the count is read over, as an instant and not as a duration: a duration is resolved
    // against the moment the log is read, which is after the last journey, and would reach back before the
    // first one. What the stack asked of the KMS a second before the run is not what the run cost, and the
    // warm-up above is not part of the run either.
    $since = cost_now();
    /** @var array<string, list<float>> $steps */
    $steps = [];
    io()->progressStart($journeys);
    for ($journey = 0; $journey < $journeys; ++$journey) {
        foreach (cost_journey($issuer, $env['BEFFROI_DEV_USER_PASSWORD'], $env['OIDC_DEMO_SECRET'], $ca) as $step => $seconds) {
            $steps[$step][] = $seconds;
        }
        io()->progressAdvance();
    }
    io()->progressFinish();
    $asked = cost_kms_calls($since);

    $addressSteps = array_intersect_key($steps, array_flip(COST_ADDRESS_STEPS));
    $p95 = cost_p95(cost_journey_times(array_diff_key($steps, $addressSteps)));
    [$slowestStep, $slowestP95] = cost_slowest_request($steps);

    io()->section('Result');
    io()->table(['Measured', 'Result'], [
        [sprintf('p95 of the login journey, %d requests', count($steps) - count($addressSteps)), sprintf('%d ms', cost_milliseconds($p95))],
        ...(
            $addressSteps === []
                ? []
                : [[
                    sprintf('p95 of the step of the address, %d requests, left out of the journey', count($addressSteps)),
                    sprintf('%d ms', cost_milliseconds(cost_p95(cost_journey_times($addressSteps)))),
                ]]
        ),
        [sprintf('Calls to the KMS while the %d journeys were served', $journeys), (string) $asked],
    ]);
    io()->text([
        sprintf(' Commit <info>%s</info>, %d journeys, KMS %s, the stack neither in debug nor collecting profiles.', cost_commit(), $journeys, $backend),
        sprintf(' The count is read in %s.', cost_kms_log()),
    ]);
    io()->newLine();

    $unmet = [];
    if ($slowestP95 > COST_CEILING) {
        $unmet[] = sprintf(
            'the "%s" request is at %d ms at the p95, above the %d ms ceiling',
            $slowestStep,
            cost_milliseconds($slowestP95),
            (int) (COST_CEILING * 1000),
        );
    }
    if ($baseline !== null && cost_milliseconds($p95) > ($baseline * COST_MARGIN)) {
        $unmet[] = sprintf(
            'the p95 is %d ms against a baseline of %d ms, which is %+d %% where +%d %% is allowed at the same number of journeys, which this run played %d of',
            cost_milliseconds($p95),
            (int) round($baseline),
            cost_growth($p95, $baseline),
            (int) round((COST_MARGIN - 1) * 100),
            $journeys,
        );
    }
    if ($unmet !== []) {
        io()->error('The threshold of decision 0018 is not met: ' . implode('; ', $unmet) . '.');
        exit(1);
    }

    io()->success(sprintf(
        'The p95 of the journey is %d ms, and the KMS was asked %d time%s for %d logins. No request of the journey is above the %d ms ceiling, the slowest being "%s" at %d ms.%s',
        cost_milliseconds($p95),
        $asked,
        $asked === 1 ? '' : 's',
        $journeys,
        (int) (COST_CEILING * 1000),
        $slowestStep,
        cost_milliseconds($slowestP95),
        $baseline === null
            ? ' Nothing is compared: --baseline takes the p95 of the run this one is to be read against.'
            : sprintf(
                ' Against a baseline of %d ms that is %+d %%, where decision 0018 allows +%d %% for the same task, the same stack and the same number of journeys, which this run played %d of.',
                (int) round($baseline),
                cost_growth($p95, $baseline),
                (int) round((COST_MARGIN - 1) * 100),
                $journeys,
            ),
    ));
    io()->note('Take several runs on the same commit and write all of them in the journal of the spike, with the commit above, the lowest being the one the next measurement is read against and the band they span being the dispersion of the machine. That dispersion is of the same order as the threshold, so one figure says nothing about the next and the comparison is the lowest of several against the lowest of several: a baseline that is too high is what makes +20 % permissive, which is the failure decision 0018 names, and a single run compared with it is what fails for no reason. A run taken minutes after a provisioning or a key rotation is not one to keep. The count is the one that decision reads as one opening per data key and per thread, so what to look for is a small number that does not grow with the number of journeys, not a zero.');
}

/**
 * One complete login, end to end, with a cookie jar of its own, and the seconds each of its requests took.
 *
 * This is the journey every walk of demo.php drives through demo_login() and demo_resume(), played against
 * the OP alone. It asserts the same steps and narrates none of them, fifty journeys having no use for four
 * hundred ✓ lines, and it shares the one part worth sharing, demo_request(), so that a change of cookie or
 * of redirect handling is made in one place.
 *
 * @return array<string, float> the seconds of each request, in the order they were played
 */
function cost_journey(string $issuer, string $password, string $secret, string $ca): array
{
    $cookies = [];
    $steps = [];
    $verifier = bin2hex(random_bytes(32));
    $redirectUri = DEMO_URL . '/oidc/callback';

    [$status, $location] = cost_request($steps, $cookies, 'authorize', $ca, 'GET', cost_authorization($issuer, $verifier, $redirectUri));
    cost_expect(
        $status === 302 && str_starts_with($location, $issuer . '/login?interaction='),
        sprintf('the OP did not ask for a login (got %d %s)', $status, $location),
    );

    [$status, , $page] = cost_request($steps, $cookies, 'login page', $ca, 'GET', $location);
    // A tenant that federates an e-mail domain to an upstream identity provider, as the development tenant does
    // (beffroi.saml.identity_providers), asks for the address first (beffroi/saml S-61): the username, of no domain, is
    // sent on to the usual page, two requests more of the journey of every login of such a tenant.
    if (str_contains($page, 'data-step="address"')) {
        cost_expect(
            preg_match('/data-step="address".*?name="_token" value="([^"]+)"/s', $page, $token) === 1
            && preg_match('/<form method="post" action="([^"]+)" data-step="address"/', $page, $addressForm) === 1,
            'the login page asked for the address without carrying its form',
        );
        [$status, $location] = cost_request($steps, $cookies, 'address', $ca, 'POST', $issuer . html_entity_decode($addressForm[1]), [
            '_address' => DEV_USERNAME,
            '_token' => $token[1],
        ]);
        cost_expect(in_array($status, [302, 303], true), sprintf('the address was not taken (got %d)', $status));
        [$status, , $page] = cost_request($steps, $cookies, 'login page after the address', $ca, 'GET', $location);
    }
    // The form of the password, named by its field: the layout of the page puts the forms of the locale and of the
    // theme before it, each with a token of its own (demo_form_with()).
    cost_expect(
        $status === 200
        && preg_match('/<form\b(?:(?!<\/form>).)*?name="_username"(?:(?!<\/form>).)*<\/form>/s', $page, $form) === 1
        && preg_match('/name="_csrf_token" value="([^"]+)"/', $form[0], $csrf) === 1
        && preg_match('/action="([^"]+)"/', $form[0], $loginForm) === 1,
        sprintf('the login page did not carry the form of the password (got %d)', $status),
    );

    [$status, $location] = cost_request($steps, $cookies, 'password', $ca, 'POST', $issuer . html_entity_decode($loginForm[1]), [
        '_username' => DEV_USERNAME,
        '_password' => $password,
        '_csrf_token' => $csrf[1],
    ]);
    cost_expect($status === 302, sprintf('the form was not accepted (got %d)', $status));

    // A sign-in that was refused comes back to the form, which says so, and one that was taken resumes into
    // the consent this request asked for: the two are the same redirection, so a password the provider does
    // not take is named here rather than three requests later (demo_resume, LoginController).
    [$status, $location] = cost_request($steps, $cookies, 'resume', $ca, 'GET', $location);
    cost_expect(
        $status === 302 && str_starts_with($location, $issuer . '/consent?'),
        sprintf(
            'the interaction did not resume into a consent, which a refused sign-in does not either (got %d %s; "beffroi:user:show %s" says which credentials that user holds)',
            $status,
            $location,
            DEV_USERNAME,
        ),
    );

    [$status, , $page] = cost_request($steps, $cookies, 'consent page', $ca, 'GET', $location);
    // the form of the answer, named by its field, after the forms of the layout as on the login page
    cost_expect(
        $status === 200
        && preg_match('/<form\b(?:(?!<\/form>).)*?name="answer"(?:(?!<\/form>).)*<\/form>/s', $page, $form) === 1
        && preg_match('/name="_token" value="([^"]+)"/', $form[0], $consentToken) === 1
        && preg_match('/name="interaction" value="([^"]+)"/', $form[0], $interaction) === 1
        && preg_match('/action="([^"]+)"/', $form[0], $consentForm) === 1,
        sprintf('the consent page did not carry the form of the answer (got %d)', $status),
    );

    [$status, $location] = cost_request($steps, $cookies, 'consent', $ca, 'POST', $issuer . html_entity_decode($consentForm[1]), [
        'interaction' => $interaction[1],
        '_token' => $consentToken[1],
        'answer' => 'allow',
    ]);
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    $code = $callback['code'] ?? null;
    cost_expect(
        $status === 302 && is_string($code) && ($callback['iss'] ?? null) === $issuer,
        sprintf('the OP did not answer with a code on the redirect URI of the client (got %d %s)', $status, $location),
    );

    $tokens = cost_step($steps, 'token', static fn (): array => cost_token($issuer, $ca, $secret, (string) $code, $redirectUri, $verifier));
    $accessToken = $tokens['access_token'] ?? null;
    cost_expect(
        is_string($accessToken) && is_string($tokens['id_token'] ?? null),
        'the token response carried no access token and no ID token: ' . json_encode($tokens),
    );

    $status = cost_step($steps, 'userinfo', static fn (): int => http_request('GET', $issuer . '/userinfo', [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_bearer' => (string) $accessToken,
    ])->getStatusCode());
    cost_expect($status === 200, sprintf('UserInfo refused the access token (got %d)', $status));

    return $steps;
}

/**
 * The authorization request of the run: the parameters `oidc_login` sends, PKCE included (decision 0006),
 * and a consent asked for rather than hoped for. A consent already in force answers the request without
 * showing a page (OIDC Core §3.1.2.4), and the second journey of a run would then be a shorter journey than
 * the first; what is measured is the whole of a login, so every journey pays for the page.
 */
function cost_authorization(string $issuer, string $verifier, string $redirectUri): string
{
    return $issuer
    . '/authorize?'
    . http_build_query([
        'response_type' => 'code',
        'client_id' => DEMO_CLIENT_ID,
        'redirect_uri' => $redirectUri,
        'scope' => 'openid profile email',
        'state' => bin2hex(random_bytes(16)),
        'nonce' => bin2hex(random_bytes(16)),
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
        'code_challenge_method' => 'S256',
        'prompt' => 'consent',
    ]);
}

/**
 * The code spent by the client it was issued to, with the verifier of its challenge (RFC 6749 §4.1.3,
 * RFC 7636 §4.5). What the endpoint answered comes back whatever its status: the journey reads it, in the
 * one place where every other step of it is read too.
 *
 * @return array<string, mixed>
 */
function cost_token(string $issuer, string $ca, string $secret, string $code, string $redirectUri, string $verifier): array
{
    $response = http_request('POST', $issuer . '/token', [
        'cafile' => $ca,
        'max_redirects' => 0,
        'auth_basic' => DEMO_CLIENT_ID . ':' . $secret,
        'body' => [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $verifier,
        ],
    ]);

    return (array) json_decode($response->getContent(false), true);
}

/**
 * One request of the browser, timed, its seconds kept under the name of its step. The cookie jar crosses
 * every step of one journey and no other, which is what makes each journey a login.
 *
 * @param array<string, float> $steps
 * @param array<string, array<string, string>> $cookies
 * @param array<string, string> $form
 * @return array{int, string, string, array<string, list<string>>} status, Location, body, headers
 */
function cost_request(array &$steps, array &$cookies, string $step, string $ca, string $method, string $url, array $form = []): array
{
    $started = hrtime(true);
    $answer = demo_request($cookies, $ca, $method, $url, $form);
    $steps[$step] = cost_seconds($started);

    return $answer;
}

/**
 * What of the stack is instrumented, each read where it is true and not in a file.
 *
 * The profiler marks a response it collected with an X-Debug-Token, and the JWK Set is what is asked
 * because the well-known paths are the ones its configuration excludes from collection. The kernel in
 * debug is what wires the decorators the bundle puts on the encrypter and on the store (beffroi#427), which
 * record every opening whether a profile is kept or not, and the application answers for it itself.
 *
 * @return list<string> what is instrumented, empty when nothing is
 */
function cost_instrumented(string $issuer): array
{
    $instrumented = [];

    // The development OP is served by the internal CA of Caddy, which nothing on the host trusts.
    $headers = http_request('GET', $issuer . '/jwks', [
        'verify_peer' => false,
        'verify_host' => false,
    ])->getHeaders(false);
    if (($headers['x-debug-token'] ?? []) !== []) {
        $instrumented[] = 'the profiler collects, the JWK Set coming back with an X-Debug-Token';
    }

    if (preg_match('/Debug\s+true/', op_console(['about'], context()->withQuiet())->getOutput()) === 1) {
        $instrumented[] = 'the kernel runs in debug, which its own "about" says';
    }

    return $instrumented;
}

/**
 * One request the client makes of the provider server to server, timed the same way: it carries no cookie,
 * a token endpoint and a UserInfo endpoint being reached by whoever holds the credential and never by a
 * session.
 *
 * @template T
 * @param array<string, float> $steps
 * @param callable(): T $request
 * @return T
 */
function cost_step(array &$steps, string $step, callable $request): mixed
{
    $started = hrtime(true);
    $answer = $request();
    $steps[$step] = cost_seconds($started);

    return $answer;
}

/**
 * Now, as the log of a container dates its lines: RFC 3339 in UTC with its microseconds, which is what
 * "docker compose logs --since" reads and what makes the window of a run an instant rather than a duration.
 */
function cost_now(): string
{
    return new DateTimeImmutable('now', new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');
}

/**
 * The seconds since a reading of the monotonic clock, which is the one clock a duration may be taken on.
 */
function cost_seconds(float|int $started): float
{
    return (hrtime(true) - $started) / 1_000_000_000;
}

function cost_milliseconds(float $seconds): int
{
    return (int) round($seconds * 1000);
}

/**
 * By how much a p95 grew over a baseline, in percent, which is the figure the threshold of decision 0018 is
 * a ceiling on.
 */
function cost_growth(float $p95, float $baseline): int
{
    return (int) round(((cost_milliseconds($p95) / $baseline) - 1) * 100);
}

/**
 * A step of the journey that did not answer what a login answers stops the run: a p95 taken off journeys
 * that are not logins is worse than no figure at all, and it would be written in a journal.
 */
function cost_expect(bool $condition, string $what): void
{
    if ($condition) {
        return;
    }
    io()->newLine(2);
    io()->error('The journey is not a login: ' . $what . '. "castor demo --check" walks the same journey and says what it verified at each step.');
    exit(1);
}

/**
 * The seconds each journey took, which is the sum of its requests: what the p95 of the run is read off.
 *
 * @param array<string, list<float>> $steps
 * @return list<float>
 */
function cost_journey_times(array $steps): array
{
    $journeys = [];
    foreach ($steps as $samples) {
        foreach ($samples as $journey => $seconds) {
            $journeys[$journey] = ($journeys[$journey] ?? 0.0) + $seconds;
        }
    }

    return array_values($journeys);
}

/**
 * The p95 by nearest rank: the smallest sample that ninety-five percent of them are at or under, which is
 * what a latency budget means by a p95 and what two runs of the same task can be compared on. Nothing is
 * interpolated, an interpolated p95 being a figure no journey took.
 *
 * @param list<float> $samples
 */
function cost_p95(array $samples): float
{
    if ($samples === []) {
        io()->error('No journey was played, so there is no p95 to take.');
        exit(1);
    }
    sort($samples);

    return $samples[(int) ceil(0.95 * count($samples)) - 1];
}

/**
 * The request of the journey whose own p95 is the highest, and that p95: the ceiling of decision 0018 is
 * read per request and not on the journey, so what it is read against is the worst request of it.
 *
 * @param array<string, list<float>> $steps
 * @return array{0: string, 1: float}
 */
function cost_slowest_request(array $steps): array
{
    $slowest = ['', 0.0];
    foreach ($steps as $step => $samples) {
        $p95 = cost_p95($samples);
        if ($p95 > $slowest[1]) {
            $slowest = [$step, $p95];
        }
    }

    return $slowest;
}

/**
 * What the OP asked the KMS since the instant the journeys started, counted in the audit device of Vault.
 *
 * An entry is counted when it is the request half of the pair, a response entry being the same call
 * answered; when its path is one of the Transit engine, which is the whole of what the OP can reach there
 * (the data key it mints, the one it unwraps, and the configuration of the master key it reads once per
 * process: symfony/hashicorp-vault-key-management, TransitKms); and when the token that made it is the one
 * of the OP rather than the root token, which the healthcheck of compose.yaml and docker/vault/init.sh
 * hold. The policy of a token is what tells the two apart (docker/vault/beffroi-op.hcl).
 */
function cost_kms_calls(string $since): int
{
    $logs = run(
        ['docker', 'compose', ...compose_profiles(), 'logs', '--no-log-prefix', '--since', $since, COST_KMS],
        context: context()->withQuiet()->withAllowFailure(),
    );
    if (! $logs->isSuccessful()) {
        io()->error(sprintf(
            'Cannot read the log of the %s container, which is running: %s',
            COST_KMS,
            trim($logs->getErrorOutput()),
        ));
        exit(1);
    }
    $asked = 0;
    foreach (explode("\n", $logs->getOutput()) as $line) {
        $entry = json_decode(trim($line), true);
        if (! is_array($entry) || ($entry['type'] ?? null) !== 'request') {
            continue;
        }
        $path = $entry['request']['path'] ?? null;
        $policies = $entry['auth']['policies'] ?? null;
        if (! is_string($path) || ! str_starts_with($path, 'transit/')) {
            continue;
        }
        if (is_array($policies) && in_array(VAULT_OP_POLICY, $policies, true)) {
            ++$asked;
        }
    }

    return $asked;
}

/**
 * Which log the count was read in, said in the result so that a figure written in a journal names its
 * source.
 */
function cost_kms_log(): string
{
    return sprintf(
        'the audit device of the %s container (file, file_path=stdout, docker/vault/init.sh), counting the requests that the token under the "%s" policy made of the Transit engine',
        COST_KMS,
        VAULT_OP_POLICY,
    );
}

/**
 * The commit the stack serves, which the journal row of a measurement names: a figure without one cannot be
 * taken again.
 */
function cost_commit(): string
{
    $commit = run(['git', 'rev-parse', '--short', 'HEAD'], context: context()->withQuiet()->withAllowFailure());

    return $commit->isSuccessful() ? trim($commit->getOutput()) : 'unknown';
}
