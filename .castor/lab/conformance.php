<?php

declare(strict_types=1);

/*
 * The OpenID conformance suite run against the stack (tests/conformance/README.md): a test of the OP, driven
 * through the API of the suite.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Console\Input\InputOption;

/**
 * The certification plans the OP answers (tests/conformance/README.md), by the short name "--plan" takes:
 * the name of each in the suite and the variants it is created with (the modules carry their own). A plan
 * the suite has to be created twice with, once per set of variants, is two entries here and two runs:
 * the alias of the configuration is exclusive, so a run is a plan with its variants and nothing else.
 * One configuration serves them all: the file whose {PLACEHOLDERS} the task fills from
 * apps/op/.env.local, and the values that must be there for the plans to make sense. An entry with "module" is not a plan
 * of the suite but one module run on its own, the suite having no plan for a single module; "before_start"
 * names, per module, what the task does between its creation and its start, in place of a human;
 * "registers_its_own_clients" says the clients of a run register themselves, which replaces the client
 * sections of the configuration with a name apiece and needs the tenant to have a registration policy.
 * "known" names the modules a run does not get past, whether the gap is the provider's or a check of the
 * suite behind the specifications the provider follows. A gap is written down whole: the result the module is known to end
 * in, the findings that result is made of, and the reason with the issue that closes it. Its result is
 * reported as KNOWN and accepted only when the run is exactly that gap, so that a gap we decided to leave
 * open does not keep the CI red for weeks; a failure where a warning was written down, a finding beside
 * the ones written down, or the module passing, is not that gap: the run fails on it, so that a
 * regression stays visible and the line is deleted rather than carried. A module is listed there once the
 * gap is written down, never to quiet a surprise.
 *
 * "waiting_on" is the other thing entirely: a run of a plan the provider does not pass yet, with the
 * issues that will make it, which are open and worked on rather than decided and left. Its modules run
 * and every result and finding is printed, and they do not fail the task while the line is there, so that
 * the runs the provider does pass keep gating. It is one line per run and not one per module because what
 * is missing is the provider's and not the module's: naming every red under "known" would write the one
 * blocker of the day thirty times over, and every line of it would be wrong the day it is lifted. A run
 * that passes whole with the line still there fails the task, which is what deletes the line.
 */
/**
 * A client per logout channel, in place of the "client" of the configuration: the suite certifies one
 * channel at a time and a module fails on a request to the endpoint of the other one, so the client of a
 * plan registers the URI of its channel and of no other (apps/op/config/packages/beffroi.yaml).
 */
const CONFORMANCE_FRONT_CHANNEL_CLIENT = [
    'client_id' => 'conformance-front-channel-logout',
    'client_secret' => '{CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET}',
];

const CONFORMANCE_BACK_CHANNEL_CLIENT = [
    'client_id' => 'conformance-back-channel-logout',
    'client_secret' => '{CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET}',
];

/**
 * The clients of the FAPI 2 plans, in the order the suite names them: "client" and "client2", the second
 * one being what a module that presents an authorization code or a request URI issued to another client
 * uses. Two per pair, because a client authenticates with the one method it registered (RFC 6749 §2.3.1)
 * and the two pairs do not authenticate the same way. "castor provision" generates their keys into
 * var/conformance/ and publishes the public half to the provider
 * (apps/op/config/packages/beffroi.yaml).
 */
const CONFORMANCE_FAPI_PRIVATE_KEY_JWT_CLIENTS = ['conformance-fapi-private-key-jwt', 'conformance-fapi-private-key-jwt-second'];

const CONFORMANCE_FAPI_MTLS_CLIENTS = ['conformance-fapi-mtls', 'conformance-fapi-mtls-second'];

/**
 * Message Signing runs with clients of its own: a client of those runs is registered to start every
 * authorization request with a request object it signed (RFC 9101 §10.5,
 * require_signed_request_object), which the unsigned requests of the Security Profile plan could not be.
 */
const CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_CLIENTS = ['conformance-fapi-signing-private-key-jwt', 'conformance-fapi-signing-private-key-jwt-second'];

const CONFORMANCE_FAPI_SIGNING_MTLS_CLIENTS = ['conformance-fapi-signing-mtls', 'conformance-fapi-signing-mtls-second'];

/**
 * The clients of the two FAPI-CIBA runs, read as "client" and "client2" like every other pair. One pair
 * per run and not one for both: a client registers one backchannel token delivery mode (CIBA Core §4),
 * and the two runs are that mode changed (apps/op/config/packages/beffroi.yaml).
 */
const CONFORMANCE_CIBA_POLL_CLIENTS = ['conformance-ciba-poll', 'conformance-ciba-poll-second'];

const CONFORMANCE_CIBA_PING_CLIENTS = ['conformance-ciba-ping', 'conformance-ciba-ping-second'];

/**
 * What a client of the FAPI-CIBA runs names its user with (CIBA Core §7.1, the "hint_type" and
 * "hint_value" of the suite): the subject this provider issued them, which is what the tenant of the
 * development stack reads a login hint as and what §15 asks for in place of an identifier that says who
 * somebody is everywhere. "castor provision" publishes the value with the other ones it draws.
 */
const CONFORMANCE_CIBA_HINT_TYPE = 'login_hint';

const CONFORMANCE_CIBA_HINT_VALUE = '{BEFFROI_DEV_USER_SUBJECT}';

/**
 * The authentication context class a client of the FAPI-CIBA runs asks for (CIBA Core §7.1, the
 * "acr_value" of the suite): one name, sent as the whole "acr_values" of a backchannel authentication
 * request, which the suite refuses to send unless the discovery document announces it under
 * "acr_values_supported".
 *
 * "1" is the single factor of the default policy (decision 0010) and the one of the four classes this
 * tenant announces that these runs can be answered with. The user they name signs in with a password and
 * holds nothing else, and the class a token names is what the session proved and never what the request
 * asked for (OIDC Core §2): a class asking for more is approved all the same, a voluntary demand being
 * refused to nobody (§5.5.1.1), and the module then reads an "acr" that is not the one it asked for. A
 * user holding a credential that could reach it would be asked for one more proof instead, which the
 * endpoint answering in place of a human refuses by design (AutomatedApprovalController).
 */
const CONFORMANCE_CIBA_ACR_VALUE = '1';

/**
 * Where the suite posts the answer of the user when there is nobody to give one (its
 * "automated_ciba_approval_url"): the endpoint of the bundle an application imports in development only
 * (src/symfony/config/routes/ciba-conformance.php), which signs the user in with their password and
 * answers the request the suite names. "{auth_req_id}" and "{action}" are what the suite substitutes,
 * itself, in the URL it was given; everything else is filled here.
 *
 * Without it every module of the plan waits for a human: there is no browser in this flow for the
 * scripted browser of the suite to drive, and the modules that need an answer would each wait out
 * CONFORMANCE_MODULE_TIMEOUT.
 */
const CONFORMANCE_CIBA_APPROVAL_PATH = '/ciba/conformance/approval';

/**
 * The modules that need the user to have consented to nothing. A consent is remembered, which is what
 * makes the provider ask once and not at every authorization; a module that has to see the user refuse
 * needs the page where refusing happens, and an earlier module of the same plan has already granted it.
 * The consent is taken back before those modules and before no other, because taking it back before
 * every one of them would add a console call per module for nothing.
 */
const CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT = ['fapi2-security-profile-final-user-rejects-authentication'];

/**
 * Where "castor provision" left the key material of those clients, relative to the checkout.
 */
const CONFORMANCE_FAPI_DIRECTORY = 'var/conformance';

/**
 * What the FAPI clients ask for, in the order a module that reorders them will read it back: more than
 * one scope, so that the order can be changed, and the claims of the development user behind them.
 */
const CONFORMANCE_FAPI_SCOPE = 'openid profile email offline_access';

/**
 * The JWS algorithm the FAPI clients sign a DPoP proof with. ES256 is what their keys are
 * (var/conformance/), and RS256 is what the profile refuses.
 */
const CONFORMANCE_FAPI_DPOP_ALGORITHM = 'ES256';

/**
 * The resource a FAPI module calls with the access token it obtained: the UserInfo endpoint of the
 * provider, which is the protected resource an OpenID Provider serves (OIDC Core §5.3). Under the
 * ordinary origin for a token bound to a key, under the mTLS origin for one bound to a certificate
 * (RFC 8705 §5), since a bound token is presented on the connection it was bound on.
 */
const CONFORMANCE_FAPI_RESOURCE_PATH = '/userinfo';

/**
 * The one module the four FAPI 2 runs do not pass, the same one each time (issue #210). It reads the ID
 * token of a request carrying a "claims" parameter and warns on every claim it does not know; the one it
 * does not know is "sid", which names the session the token was issued in. An OP that announces
 * frontchannel_logout_session_supported or backchannel_logout_session_supported puts "sid" in the ID
 * tokens it issues (Front-Channel Logout 1.0 §3, Back-Channel Logout 1.0 §2.1), and this one announces
 * both as soon as it serves the channel; the claim is registered in the IANA "JSON Web Token Claims"
 * registry by Front-Channel Logout 1.0 §6.1.1. The list of the suite (ValidateIdTokenStandardClaims)
 * does not carry it, so the module is a check behind its own specifications and not a gap of the
 * provider: dropping the claim would contradict the metadata the provider publishes and would take from
 * the logout endpoint what tells it the hint describes the session in front of it (architecture §4.9).
 */
const CONFORMANCE_FAPI_KNOWN_MODULES = [
    'fapi2-security-profile-final-test-claims-parameter-identity-claims' => [
        'result' => 'WARNING',
        // The condition that warns, by the name the log gives it. The sentence it writes after the name is
        // the suite's own wording and is not matched: what is known is which check warns, not how it words
        // it. A second condition warning on the same module is a finding beside this one and fails the run.
        'findings' => ['WARNING CheckForUnexpectedClaimsInIdToken:'],
        'reason' => 'the ID token carries "sid", a claim Front-Channel Logout 1.0 §3 defines and the suite does not know; beffroi#210',
    ],
];

/**
 * What the task does between the creation of a module and its start, in place of a human, by the module
 * it is done for: the key rotation module reads the JWK Set, waits for the operator to rotate the keys
 * and reads it again, and the suite has no other way of asking. It is named per module and not per run,
 * a plan that carries that module carrying twenty-two others the operator is asked nothing for.
 */
/**
 * OIDC Core §3.1, decision 0006: the Dynamic OP profile asks the discovery document for the two flows this
 * provider refuses, and the module that reads it is the one module of the plan no amount of building
 * closes. "OIDCCCheckDiscEndpointGrantTypesSupportedDynamic" wants "grant_types_supported" to carry
 * "implicit" beside "authorization_code", and "OIDCCCheckDiscEndpointResponseTypesSupportedDynamic" wants
 * "response_types_supported" to carry "id_token" and "token id_token" beside "code" (OIDCD-3), which it
 * checks unconditionally. Both were read in the source of the suite at the tag compose.yaml pins.
 *
 * The first of the two passes on a document that does not carry "grant_types_supported" at all, the suite
 * reading its absence as both being served. This provider carries it, what it announces being derived from
 * what is wired, and dropping the member to buy half a module would say the opposite of what it serves and
 * would leave the other check failing.
 *
 * It is therefore a check of the suite behind a decision this provider keeps, like the "sid" of the FAPI
 * runs above, and the profile stays out of certification (../../docs/07-certifications.md).
 */
/**
 * The audience every client assertion of this plan carries, and why no building makes it acceptable
 * (issue #379). "CreateClientAuthenticationAssertionClaims" signs the URL of the token endpoint, read in
 * the source of the suite at the tag compose.yaml pins, and "OIDCCDynamicTestPlan" fixes
 * "private_key_jwt" for every module but the discovery one and the key rotation: so every module that
 * reaches a token sends an assertion this provider refuses, and reads the refusal as a token endpoint that
 * did not answer 200.
 *
 * Decision 0016 is what refuses it, and "draft-ietf-oauth-rfc7523bis" §4 is why: it updates RFC 7523 so
 * that the "aud" of a client assertion must be the issuer identifier as a single value, must not be the URL
 * of the token endpoint, and must be rejected when it is anything else. FAPI 2.0 Security Profile §5.3.2.1
 * clause 8 asked for the same rule first, and the module
 * "fapi2-security-profile-final-ensure-invalid-client-assertions-fail" of the four green FAPI 2 runs
 * requires that exact refusal: accepting the URL here would turn four passing runs red to buy these.
 *
 * The one module of this plan that names the issuer, "oidcc-ensure-client-assertion-with-iss-aud-succeeds",
 * passes. So what is written down is a check of the suite behind a specification this provider follows, as
 * the two above are, and the profile stays out of certification (../../docs/07-certifications.md).
 */
const CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE = 'the plan signs the URL of the token endpoint as the "aud" of its client assertions, which draft-ietf-oauth-rfc7523bis section 4 forbids and decision 0016 refuses; beffroi#379';

/**
 * What such a module ends on: the status the exchange did not answer, and its own interruption, which
 * quotes that failure. A module interrupted for any other reason carries that reason as a finding of its
 * own, so the run still fails on it.
 */
const CONFORMANCE_TOKEN_ENDPOINT_STATUS = 'FAILURE CheckTokenEndpointHttpStatus200:';

/**
 * The two modules of the plan that play a request object published behind a "request_uri", and why no
 * building closes either (issue #385). Both must complete the authorization, and both are refused before
 * the request is read: an object that is refused is an object that was not read, so the answer is a page
 * and never a redirection (RequestObjectResolver::resolve()), the browser of the suite waits for a
 * callback that never comes, and the provider's own answer is in no artefact of a run. What each one is
 * answered is read in a functional test of the bundle and nowhere else
 * (RegisteredClientRequestObjectTest).
 *
 * "oidcc-request-uri-signed-rs256" signs the parameters of the authorization request plus "aud" and "iss"
 * and nothing more (ConvertAuthorizationEndpointRequestToRequestObject, AddAudToRequestObject,
 * AddIssToRequestObject, read in the source of the suite at the tag compose.yaml pins), so its object
 * carries neither "exp" nor "nbf", which RFC 9101 §4 asks of none: it makes "iss" and "aud" a SHOULD and
 * names neither of the other two. Decision 0012 asks for the four of an object that carries a signature,
 * FAPI 2.0 Message Signing being what bounds them, and opens an exemption on them to no client; the
 * modules "fapi2-security-profile-final-ensure-request-object-without-exp-fails" and
 * "-without-nbf-fails" of the four green FAPI 2 runs require that exact refusal, so accepting the object
 * here would turn passing runs red to buy this one.
 *
 * "oidcc-request-uri-unsigned" registers a client that says nothing about "request_object_signing_alg"
 * and publishes an object with "alg": "none" (SerializeRequestObjectWithNullAlgorithm). A client that
 * registered nothing is read under any algorithm the provider is wired with and never unsigned
 * (AnyRegisteredAlgorithm): decision 0012 has an unsigned object registered per client, never fallen
 * into, and by the tenant or by a global setting never at all. The module skips itself where "none" is
 * not announced, and this tenant announces it because one client of it registered it
 * (AnnouncedRequestObjects, and the comment that member carries in apps/op/config/packages/beffroi.yaml):
 * dropping that registration to buy the skip would cost the module of the Basic and Form Post plans
 * decision 0012 exists for.
 *
 * "oidcc-ensure-request-object-with-redirect-uri" sends that same unsigned object by value, with an
 * invalid "redirect_uri" beside the valid one the object carries, and is refused on the object before the
 * query is looked at (AbstractOIDCCRequestObjectServerTest, which serializes with a null algorithm and
 * skips itself where "none" is not announced, read in the same source). It ends on the error page the
 * module accepts, and it is written down here rather than captured from the browser: what the page says
 * is the algorithm the client registered, not the redirect URI the module is about, and the same module of
 * the Basic and Form Post plans completes the authorization, the client of those plans having registered
 * "none". A "browser" block is named by module and shared by every plan, so one written for this module
 * would answer for a run where the provider redirects.
 *
 * So both are checks of the suite behind a decision this provider keeps, like the "sid" of the FAPI runs
 * and the assertion audience above, and the profile stays out of certification
 * (../../docs/07-certifications.md).
 */
const CONFORMANCE_DYNAMIC_SIGNED_REQUEST_OBJECT_CLAIMS = 'the plan signs a request object carrying neither exp nor nbf, which decision 0012 asks of every signed object and which two modules of the FAPI 2 security runs require to be refused; beffroi#385';

const CONFORMANCE_DYNAMIC_UNSIGNED_REQUEST_OBJECT = 'the plan sends an unsigned request object from a client that registered no request_object_signing_alg, which decision 0012 reads from the client that registered "none" and from no other; beffroi#385';

/**
 * The first of the three findings a module whose browser never reached the callback ends on: the runner
 * says the wait ran out, the module says it again as an exception of its own, and the module is interrupted.
 * The wording is matched here, where the two entries above name a condition of the suite instead: the
 * condition that fails is the module itself, so the wait is all that tells this gap from any other of the
 * same module, and one that fails for another reason must fail the run.
 */
const CONFORMANCE_BROWSER_TIMEOUT = 'FAILURE WebRunner: Timed out waiting:';

const CONFORMANCE_DYNAMIC_KNOWN_MODULES = [
    'oidcc-discovery-endpoint-verification' => [
        'result' => 'FAILED',
        // The two conditions that fail, by the names the log gives them. The sentences they write after
        // the name are the suite's own wording and are not matched: what is known is which checks fail.
        'findings' => [
            'FAILURE OIDCCCheckDiscEndpointResponseTypesSupportedDynamic:',
            'FAILURE OIDCCCheckDiscEndpointGrantTypesSupportedDynamic:',
        ],
        'reason' => 'the Dynamic OP profile requires the implicit grant and the hybrid response types, which decision 0006 refuses; beffroi#371',
    ],
    'oidcc-server' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-server:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-idtoken-rs256' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-idtoken-rs256:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-userinfo-rs256' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-userinfo-rs256:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-redirect-uri-query-OK' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-redirect-uri-query-OK:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-registration-jwks-uri' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-registration-jwks-uri:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-refresh-token' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-refresh-token:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-refresh-token-rp-key-rotation' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-refresh-token-rp-key-rotation:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-request-uri-signed-rs256' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_BROWSER_TIMEOUT,
            'FAILURE oidcc-request-uri-signed-rs256: Web Runner Exception: Timed out waiting:',
            'INTERRUPTED oidcc-request-uri-signed-rs256:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_SIGNED_REQUEST_OBJECT_CLAIMS,
    ],
    'oidcc-request-uri-unsigned' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_BROWSER_TIMEOUT,
            'FAILURE oidcc-request-uri-unsigned: Web Runner Exception: Timed out waiting:',
            'INTERRUPTED oidcc-request-uri-unsigned:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_UNSIGNED_REQUEST_OBJECT,
    ],
    'oidcc-ensure-request-object-with-redirect-uri' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_BROWSER_TIMEOUT,
            'FAILURE oidcc-ensure-request-object-with-redirect-uri: Web Runner Exception: Timed out waiting:',
            'INTERRUPTED oidcc-ensure-request-object-with-redirect-uri:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_UNSIGNED_REQUEST_OBJECT,
    ],
];

const CONFORMANCE_ROTATE_KEYS_BEFORE_START = [
    'oidcc-server-rotate-keys' => 'rotate',
];

/**
 * What a client the suite registers calls itself (RFC 7591 §2, "client_name"): with an initial access
 * token, the one thing the "dynamic_client" variant reads of a client section of the configuration, and
 * the open mode of a tenant asks for no token (decision 0009). It is what the consent page prints of a
 * client nobody declared, which is what the three modules that register a logo and two policy URIs read
 * back.
 */
const CONFORMANCE_DYNAMIC_CLIENT_NAME = 'OpenID conformance suite';

const CONFORMANCE_DYNAMIC_SECOND_CLIENT_NAME = 'OpenID conformance suite, second client';

const CONFORMANCE_PLANS = [
    'basic' => [
        'name' => 'oidcc-basic-certification-test-plan',
        'variant' => [
            'server_metadata' => 'discovery',
            'client_registration' => 'static_client',
        ],
    ],
    'config' => [
        'name' => 'oidcc-config-certification-test-plan',
        'variant' => [],
    ],
    'form-post' => [
        'name' => 'oidcc-formpost-basic-certification-test-plan',
        'variant' => [
            'server_metadata' => 'discovery',
            'client_registration' => 'static_client',
        ],
    ],
    'rp-initiated-logout' => [
        'name' => 'oidcc-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
    ],
    // Each logout channel is certified with a client of its own, and neither with the client the other
    // plans use: a client that registers a logout URI is told at every logout of its sessions, and a
    // module of another plan fails on a request it did not expect ("Got an HTTP request to
    // 'frontchannel_logout' that wasn't expected"). That is the metadata working as written, per client,
    // and it is why certifying the three logout profiles takes three clients.
    'front-channel-logout' => [
        'name' => 'oidcc-frontchannel-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
        'client' => CONFORMANCE_FRONT_CHANNEL_CLIENT,
    ],
    // The one plan whose modules the OP answers from outside the browser: the worker posts the logout
    // token to the URI the suite gives its clients, which names localhost:8443 and is the suite itself
    // from the host. Inside the worker that address is the worker, so the conformance-worker-redirector
    // sidecar of compose.yaml brings the port there, and the entrypoint of the worker trusts the
    // certificate nginx answers with (docker/worker/entrypoint.sh). The module waits for the token while
    // it runs, which makes the latency of the worker a matter of conformance and not of operations.
    'back-channel-logout' => [
        'name' => 'oidcc-backchannel-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
        'client' => CONFORMANCE_BACK_CHANNEL_CLIENT,
    ],
    // The four runs of FAPI 2 (issue #166), the judge of spike 5: two profiles, and each of them once
    // per pair the profile lets an authorization server choose between, because a plan created with
    // variants is a run of its own and the alias of the configuration makes runs exclusive. The pair is
    // always read the same way round: "private_key_jwt" proves a key and DPoP binds the token to a key,
    // "mtls" proves a certificate and the same certificate binds the token, and nothing here mixes the
    // two. The clients are named per pair, and the sender constraining of the variant is what says
    // whether the suite presents a certificate and on which host it calls the resource.
    'fapi2-security-dpop' => [
        'name' => 'fapi2-security-profile-final-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'sender_constrain' => 'dpop',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_PRIVATE_KEY_JWT_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    'fapi2-security-mtls' => [
        'name' => 'fapi2-security-profile-final-test-plan',
        'variant' => [
            'client_auth_type' => 'mtls',
            'sender_constrain' => 'mtls',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_MTLS_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    // The same two pairs, with the request signed and the answer signed: what Message Signing adds to
    // the Security Profile (FAPI 2.0 Message Signing §5.3.1, JARM).
    'fapi2-signing-dpop' => [
        'name' => 'fapi2-message-signing-final-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'sender_constrain' => 'dpop',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
            'fapi_request_method' => 'signed_non_repudiation',
            'fapi_response_mode' => 'jarm',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    'fapi2-signing-mtls' => [
        'name' => 'fapi2-message-signing-final-test-plan',
        'variant' => [
            'client_auth_type' => 'mtls',
            'sender_constrain' => 'mtls',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
            'fapi_request_method' => 'signed_non_repudiation',
            'fapi_response_mode' => 'jarm',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_SIGNING_MTLS_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    // The two runs of FAPI-CIBA (issue #227), the judge of spike 6: the same plan created once per
    // delivery mode, "ciba_mode" being the variant that changes what the suite does between two
    // requests. In poll mode it asks the token endpoint again until it is answered; in ping mode it
    // waits for the provider to post the identifier of the request to the endpoint it serves, which the
    // worker reaches through the conformance-worker-redirector sidecar of compose.yaml as it reaches it
    // for a logout token. Both authenticate with "private_key_jwt" and present a certificate all the
    // same: the profile asks for sender-constrained tokens whichever way the client authenticated, so
    // the suite calls the token endpoint on the mTLS alias (RFC 8705 §5) and refuses to configure a
    // static client of this plan without a certificate.
    'fapi-ciba-poll' => [
        'name' => 'fapi-ciba-id1-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'ciba_mode' => 'poll',
            'fapi_ciba_profile' => 'plain_fapi',
            'client_registration' => 'static_client',
        ],
        'ciba' => [
            'clients' => CONFORMANCE_CIBA_POLL_CLIENTS,
        ],
    ],
    'fapi-ciba-ping' => [
        'name' => 'fapi-ciba-id1-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'ciba_mode' => 'ping',
            'fapi_ciba_profile' => 'plain_fapi',
            'client_registration' => 'static_client',
        ],
        'ciba' => [
            'clients' => CONFORMANCE_CIBA_PING_CLIENTS,
        ],
    ],
    // The two runs of spike 7 (issue #79), whose clients this provider has never seen: each module
    // registers its own with a POST that carries no credential at all, which is what the "dynamic_client"
    // variant sends (RFC 7591 §1.3) and what the open mode of a tenant answers (decision 0009). Both
    // plans fix "discovery", "dynamic_client", the client authentication and the default response mode
    // themselves and leave the response type to whoever creates them, which is the one variant written
    // here; both hide the secret and the key of a client section, the suite drawing the key of every
    // client it registers and sending it in the registration request, so there is no client of
    // beffroi.yaml behind either run and nothing for "castor provision" to draw. What they need of the
    // deployment is the registration policy of the tenant in its open mode, which the task reads in the
    // document before it creates a plan: without it every module of both fails on the same line.
    'dynamic' => [
        'name' => 'oidcc-dynamic-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
        ],
        'registers_its_own_clients' => true,
        // The plan carries the key rotation module, which waits for the operator where the twenty-two
        // others wait for nobody, so the rotation is named against that module and against no other.
        'before_start' => CONFORMANCE_ROTATE_KEYS_BEFORE_START,
        'known' => CONFORMANCE_DYNAMIC_KNOWN_MODULES,
    ],
    // The second profile of the same spike, two modules: a client registers an "initiate_login_uri" and
    // the provider begins a login at it (OIDC Core §4), the second module registering one that is not
    // "https", on the loopback host the suite runs on, and expecting the registration to be refused. It
    // passes whole, so it gates like the plans of the spikes before it and carries no "waiting_on" line.
    'third-party-init' => [
        'name' => 'oidcc-3rdparty-init-login-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
        ],
        'registers_its_own_clients' => true,
    ],
    // The key rotation module of the Dynamic OP plan, run on its own and created without a plan since the
    // suite has none for a single module (architecture §3.3): it reads the JWK Set, waits for the
    // operator to rotate the keys, reads it again and wants a new key with the old one still there. It is
    // here as well as inside the "dynamic" run because it is the outside judge of spike 2 and the run an
    // operator replays after a rotation, without the twenty-two other modules of the plan; both gate, and a
    // module that fails in either fails the task. The plans of the suite nothing here runs are those of the
    // response types and the features this provider does not have: implicit and hybrid, and session
    // management.
    'rotate-keys' => [
        'name' => 'oidcc-server-rotate-keys',
        'module' => true,
        'variant' => [
            'server_metadata' => 'discovery',
        ],
        'before_start' => CONFORMANCE_ROTATE_KEYS_BEFORE_START,
    ],
];

/**
 * The results no run of a plan can avoid and that a submission may be in (tests/conformance/README.md):
 * a module in one of them is never a gap of the OP, so it is never reported as known.
 */
const CONFORMANCE_UNCONDITIONALLY_ACCEPTED = ['PASSED', 'REVIEW', 'SKIPPED'];

const CONFORMANCE_CONFIGURATION = 'tests/conformance/configuration.json';

const CONFORMANCE_REQUIRED_VALUES = [
    'BEFFROI_ISSUER',
    // The host whose listener asks for a client certificate, where the FAPI runs that bind their tokens
    // to one call the token, the PAR and the resource endpoints (RFC 8705 §5).
    'BEFFROI_MTLS_ORIGIN',
    'BEFFROI_DEV_USER_PASSWORD',
    'CONFORMANCE_BASIC_SECRET',
    'CONFORMANCE_BASIC_SECOND_SECRET',
    'CONFORMANCE_POST_SECRET',
    'CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET',
    'CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET',
    // The subject the provider issued the development user: what a client of the FAPI-CIBA runs names
    // its user with, and the one value of those runs that follows the rows rather than the file.
    'BEFFROI_DEV_USER_SUBJECT',
];

/**
 * How long a module may run before the task gives up on it, in seconds: the longest one waits thirty
 * seconds before reusing a code, and a module the scripted browser cannot finish waits for a human.
 */
const CONFORMANCE_MODULE_TIMEOUT = 300;

/**
 * How long a module is given to leave CONFIGURED before the start is asked for a second time, seconds.
 */
const CONFORMANCE_START_CONFIRMATION = 15;

/**
 * How long the suite may take to serve its API after its container reports healthy.
 */
const CONFORMANCE_SUITE_TIMEOUT = 180;

/**
 * How long the OP may take to serve its discovery document again after "--reset" restarted it.
 */
const CONFORMANCE_OP_TIMEOUT = 180;

/**
 * @param array<string> $plan
 * @param array<string> $module
 */
#[AsTask(
    description: 'Run the certification plans the OP answers (Basic OP, Config OP, Form Post OP, the three logout profiles, the four runs of FAPI 2, the two runs of FAPI-CIBA, the Dynamic OP and 3rd Party-Init OP plans whose clients register themselves, and the key rotation module run on its own) against it through the API of the suite started by "castor start --conformance", the scripted browser of the suite signing in as the development user and the task rotating the signing key when the suite asks for it, and print the result of every module',
)]
function conformance(
    #[AsOption(
        description: 'Run only this plan: basic, config, form-post, rp-initiated-logout, front-channel-logout, back-channel-logout, fapi2-security-dpop, fapi2-security-mtls, fapi2-signing-dpop, fapi2-signing-mtls, fapi-ciba-poll, fapi-ciba-ping, dynamic, third-party-init or rotate-keys (repeatable); every plan by default',
        mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
    )]
    array $plan = [],
    #[AsOption(description: 'Run only the modules whose name contains this text (repeatable)', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $module = [],
    #[AsOption(description: 'Base URL of the suite; CONFORMANCE_TOKEN in the environment authenticates on a hosted one')]
    string $suite = 'https://localhost:8443',
    #[AsOption(description: 'Fail on WARNING as well as on FAILED, which is what the CI asks of the plans')]
    bool $strict = false,
    #[AsOption(
        description: 'Empty the database of the OP and provision it again before the plans run, which is the state they were written against: a development user with a password and nothing else',
    )]
    bool $reset = false,
): void {
    $unknown = array_diff($plan, array_keys(CONFORMANCE_PLANS));
    if ($unknown !== []) {
        io()->error(sprintf('Unknown plan %s; the plans are %s.', implode(', ', $unknown), implode(', ', array_keys(CONFORMANCE_PLANS))));
        exit(1);
    }
    $plans = $plan === [] ? CONFORMANCE_PLANS : array_intersect_key(CONFORMANCE_PLANS, array_flip($plan));
    io()->title(sprintf('Conformance: %s', implode(', ', array_column($plans, 'name'))));

    $env = load_dot_env(getcwd() . '/apps/op/.env');
    $missing = array_filter(CONFORMANCE_REQUIRED_VALUES, static fn (string $name): bool => ($env[$name] ?? '') === '');
    if ($missing !== []) {
        io()->error(sprintf('%s: run "castor provision" first.', implode(', ', $missing) . ' missing from ' . DEV_ENV_LOCAL));
        exit(1);
    }
    if ($reset) {
        conformance_reset($env['BEFFROI_ISSUER']);
    }
    // What a run whose clients register themselves needs of the deployment is not a value of its
    // environment but its registration policy, so it is read where the provider says what it does
    // (CONFORMANCE_PLANS, "registers_its_own_clients").
    if (array_any($plans, static fn (array $definition): bool => (bool) ($definition['registers_its_own_clients'] ?? false))) {
        conformance_open_registration($env['BEFFROI_ISSUER']);
    }

    $server = conformance_server($suite);
    io()->text(sprintf('Suite %s (%s) on %s, OP %s', $server['version'] ?? '?', $server['tag'] ?? '?', $suite, $env['BEFFROI_ISSUER']));
    $rows = [];
    $verdict = [];
    $stale = [];
    $planUrls = [];
    // WARNING and REVIEW are what a human reads before submitting; SKIPPED is the suite's own choice, and
    // KNOWN a gap named in CONFORMANCE_PLANS with the issue that closes it. Under --strict a WARNING is a
    // failure: the CI keeps the plans at the state a submission needs, and REVIEW and SKIPPED stay
    // accepted because no run of a plan can avoid them (tests/conformance/README.md).
    $accepted = $strict ? [...CONFORMANCE_UNCONDITIONALLY_ACCEPTED, 'KNOWN'] : [...CONFORMANCE_UNCONDITIONALLY_ACCEPTED, 'KNOWN', 'WARNING'];
    // What a run that does not pass yet did not pass, by the short name "--plan" takes: printed at the end
    // with the issues that run waits on, and not counted against the task (CONFORMANCE_PLANS,
    // "waiting_on").
    $unpassed = [];
    $failed = 0;
    foreach ($plans as $short => $definition) {
        if ($definition['module'] ?? false) {
            $planId = null;
            $planUrl = null;
            $created = [
                'modules' => [
                    [
                        'testModule' => $definition['name'],
                        'variant' => $definition['variant'],
                    ],
                ],
            ];
        } else {
            $configuration = conformance_configuration($env, $definition);
            $created = conformance_request(
                $suite,
                'POST',
                '/api/plan',
                [
                    'query' => [
                        'planName' => $definition['name'],
                        'variant' => json_encode((object) $definition['variant'], \JSON_THROW_ON_ERROR),
                    ],
                    'headers' => [
                        'Content-Type' => 'application/json',
                    ],
                    'body' => $configuration,
                ],
                201,
            );
            $planId = (string) $created['id'];
            $planUrl = sprintf('%s/plan-detail.html?plan=%s', $suite, $planId);
            $planUrls[] = sprintf('%s: %s', $definition['name'], $planUrl);
        }
        // What a plan runs by default, which naming a module with --module lifts: the restriction is
        // there to keep a run lean, never to stop an operator from asking for a module by its name.
        $only = $module === [] ? $definition['modules'] ?? [] : [];
        $modules = array_values(array_filter(
            $created['modules'],
            static fn (array $moduleDefinition): bool => (
                ($only === [] || in_array((string) $moduleDefinition['testModule'], $only, true))
                && ($module === [] || array_any($module, static fn (string $needle): bool => str_contains((string) $moduleDefinition['testModule'], $needle)))
            ),
        ));
        io()->section(
            $planId === null
                ? sprintf('%s: one module on its own, no plan', $definition['name'])
                : sprintf('%s: plan %s, %d module(s)', $definition['name'], $planId, count($modules)),
        );
        if ($planUrl !== null) {
            io()->text($planUrl);
        }
        if ($modules === []) {
            io()->warning(sprintf('No module of %s matches %s.', $definition['name'], implode(', ', $module)));
            continue;
        }

        foreach ($modules as $index => $moduleDefinition) {
            $name = (string) $moduleDefinition['testModule'];
            io()->text(sprintf('[%d/%d] %s', $index + 1, count($modules), $name));
            conformance_forget_consents($name, conformance_clients_of($definition));
            $started = microtime(true);
            $run = conformance_run_module($suite, $planId, $moduleDefinition, $configuration, ($definition['before_start'] ?? [])[$name] ?? null);
            if ($planUrl === null) {
                $planUrls[] = sprintf('%s: %s', $name, $run['url']);
            }
            $elapsed = microtime(true) - $started;
            $known = $definition['known'][$name] ?? null;
            $result = $run['result'];
            $beyond = $known === null ? [] : conformance_beyond_known($known, $run);
            if ($known !== null && $beyond === []) {
                $result = 'KNOWN';
            }
            $rows[] = [$definition['name'], $name, $result, sprintf('%ds', (int) $elapsed), $run['url']];
            $verdict[$result] = ($verdict[$result] ?? 0) + 1;
            if (! in_array($result, $accepted, true)) {
                if (($definition['waiting_on'] ?? []) === []) {
                    ++$failed;
                } else {
                    $unpassed[$short][] = sprintf('%s: %s', $name, $result);
                }
            }
            io()->text(sprintf(
                '  %s in %ds: %s',
                $result === 'KNOWN' ? sprintf('%s, known (%s)', $run['result'], $known['reason']) : $result,
                (int) $elapsed,
                $run['url'],
            ));
            foreach ($run['findings'] as $finding) {
                io()->text('    ' . $finding);
            }
            if ($beyond !== []) {
                // The module is listed as known and this run is not that gap. Said here, module by module,
                // because the summary only counts results: what a reader needs is which line was written
                // down and what came instead.
                io()->warning([
                    sprintf('%s is listed as known (%s), and this run is not that gap:', $name, $known['reason']),
                    ...$beyond,
                ]);
            }
            if ($known !== null && in_array($result, CONFORMANCE_UNCONDITIONALLY_ACCEPTED, true)) {
                $stale[] = sprintf('%s: %s (listed as known: %s)', $definition['name'], $name, $known['reason']);
            }
        }
    }
    if ($rows === []) {
        io()->error(sprintf('No module of any plan matches %s.', implode(', ', $module)));
        exit(1);
    }

    io()->newLine();
    io()->table(['Plan', 'Module', 'Result', 'Time', 'Log'], $rows);
    io()->text(sprintf(
        '%d plan(s) on suite %s: %s',
        count($planUrls),
        $server['version'] ?? '?',
        implode(', ', array_map(
            static fn (string $result, int $count): string => sprintf('%d %s', $count, $result),
            array_keys($verdict),
            $verdict,
        )),
    ));
    io()->listing($planUrls);

    // A module listed as known that no longer fails is a line to delete, not a result to keep: the list
    // says what the OP cannot do yet, and it is wrong the moment it can.
    if ($stale !== []) {
        io()->error(['These modules no longer fail and must leave the "known" list of CONFORMANCE_PLANS:', ...$stale]);
        exit(1);
    }

    // A run of a plan the provider does not pass yet says so, module by module, with the issues that will
    // make it pass: it is the one thing a reader needs of it, and it is not a failure of the task while
    // the line is in CONFORMANCE_PLANS. A run that passes whole with the line still there is the line to
    // delete, as a module that no longer fails is the "known" line to delete.
    $passing = [];
    foreach ($plans as $short => $definition) {
        $waitingOn = $definition['waiting_on'] ?? [];
        if ($waitingOn === []) {
            continue;
        }
        if (($unpassed[$short] ?? []) !== []) {
            io()->warning([
                sprintf(
                    '%s does not pass yet and waits on %s; %d module(s) of it:',
                    $short,
                    implode(', ', $waitingOn),
                    count($unpassed[$short]),
                ),
                ...$unpassed[$short],
            ]);

            continue;
        }
        // Only a whole run says that: --module ran a few of them and says nothing of the rest.
        if ($module === []) {
            $passing[] = sprintf('%s (waiting on %s)', $short, implode(', ', $waitingOn));
        }
    }
    if ($passing !== []) {
        io()->error(['These runs pass whole and must lose their "waiting_on" line in CONFORMANCE_PLANS:', ...$passing]);
        exit(1);
    }

    if ($failed > 0) {
        io()->error(sprintf('%d module(s) did not pass.', $failed));
        exit(1);
    }
    $known = $verdict['KNOWN'] ?? 0;
    io()->success(
        $known === 0
            ? 'Every module of the runs that gate passed.'
            : sprintf('Every module of the runs that gate passed but %d left to a gap named in CONFORMANCE_PLANS.', $known),
    );
}

/**
 * What a module reported that the gap written down does not account for: a result other than the one it is
 * known to end in, and every finding beside the ones that result is made of. Empty when the run is exactly
 * that gap, which is the only case where its result is accepted. A finding is recognised by the condition
 * that raised it, which the log names before its message.
 *
 * @param array{result: string, findings: list<string>, reason: string} $known
 * @param array{result: string, url: string, findings: array<string>} $run
 * @return list<string>
 */
function conformance_beyond_known(array $known, array $run): array
{
    $beyond = $run['result'] === $known['result']
        ? []
        : [sprintf('it ended in %s, where %s is what is written down', $run['result'], $known['result'])];
    foreach ($run['findings'] as $finding) {
        if (! array_any($known['findings'], static fn (string $expected): bool => str_starts_with($finding, $expected))) {
            $beyond[] = $finding;
        }
    }

    return $beyond;
}

/**
 * What a run whose clients register themselves needs of the deployment and cannot draw for itself: a
 * tenant whose registration policy registers them (RFC 7591 §1.3, decision 0009). The document is what
 * says so, a tenant announcing where a client registers exactly when its policy registers one, so it is
 * read there rather than kept beside it; without it every module of the run fails on the same line,
 * which is the failure the check of CONFORMANCE_REQUIRED_VALUES saves the other runs from.
 */
function conformance_open_registration(string $issuer): void
{
    // The development OP is served by the internal CA of Caddy, which nothing on the host trusts.
    $url = $issuer . '/.well-known/openid-configuration';
    try {
        $document = json_decode(http_request('GET', $url, [
            'verify_peer' => false,
            'verify_host' => false,
        ])->getContent(), true, flags: \JSON_THROW_ON_ERROR);
    } catch (Throwable $exception) {
        io()->error(sprintf('%s could not be read: %s', $url, $exception->getMessage()));
        exit(1);
    }
    if (! is_array($document) || ! is_string($document['registration_endpoint'] ?? null)) {
        io()->error([
            sprintf('%s announces no "registration_endpoint", so no client can register itself.', $url),
            'The runs that register their own clients need the registration policy of the tenant, which apps/op/config/packages/beffroi.yaml writes under "when@dev" (decision 0009).',
        ]);
        exit(1);
    }
    io()->text(sprintf('Clients register themselves on %s.', $document['registration_endpoint']));
}

/**
 * The suite, once it answers. Its container is healthy before its JVM serves the API, and nginx answers
 * 502 until then: a plan created in that window fails for nothing, which is the difference between a
 * developer who waits and a CI that does not.
 *
 * @return array<string, mixed>
 */
function conformance_server(string $suite): array
{
    $deadline = microtime(true) + CONFORMANCE_SUITE_TIMEOUT;
    $announced = false;
    while (true) {
        try {
            return conformance_request($suite, 'GET', '/api/server');
        } catch (Throwable $exception) {
            if (microtime(true) >= $deadline) {
                throw $exception;
            }
            if (! $announced) {
                io()->text(sprintf('Waiting for the suite on %s.', $suite));
                $announced = true;
            }
            usleep(2_000_000);
        }
    }
}

/**
 * Puts the OP back in the state the plans were written against: the tables dropped, the migrations of the
 * bundle replayed and "castor provision" run again, which leaves the development user with a password and
 * nothing else. A second factor or a passkey enrolled by hand (a run of "castor demo --passkey", an
 * afternoon on the account pages) stops the scripted browser of the suite on the page that asks for it,
 * and every module of every plan fails on the same line, "unexpected url for task: Verify complete". The
 * client secrets live in apps/op/.env.local and the clients in apps/op/config/packages/beffroi.yaml, so
 * nothing of the configuration is lost; the signing keys are generated again, their sealed files in the
 * keys_data volume left behind as orphans.
 *
 * The containers are restarted at the end and the OP waited for: a worker of FrankenPHP holds the kernel
 * of the application for every request it serves, the opened signing key with it (architecture §3.3), and
 * a worker that was up before the tables went keeps a key no row names any more. It restarts on a source
 * change, never on a write in the database, so the reset restarts it.
 */
function conformance_reset(string $issuer): void
{
    io()->section('Resetting the OP');
    op_console(['doctrine:schema:drop', '--full-database', '--force', '--no-interaction']);
    op_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);
    provision();
    run(['docker', 'compose', ...compose_profiles(), 'restart', 'op', 'worker']);
    // Last, and after the two containers they follow, or the back-channel plan would wait for a token
    // that cannot arrive and the sector modules for a document that cannot be reached.
    compose_recreate_redirectors(['op', 'worker']);
    conformance_wait_for_op($issuer);
}

/**
 * The OP, once it serves its discovery document again: "docker compose restart" returns before the
 * container is healthy, and a plan created in that window fails for nothing.
 */
function conformance_wait_for_op(string $issuer): void
{
    $deadline = microtime(true) + CONFORMANCE_OP_TIMEOUT;
    // The development OP is served by the internal CA of Caddy, which nothing on the host trusts.
    $url = $issuer . '/.well-known/openid-configuration';
    io()->text(sprintf('Waiting for the OP on %s.', $url));
    while (true) {
        try {
            if (http_request('GET', $url, [
                'verify_peer' => false,
                'verify_host' => false,
            ])->getStatusCode() === 200) {
                return;
            }
        } catch (Throwable) {
        }
        if (microtime(true) >= $deadline) {
            io()->error(sprintf('The OP did not answer on %s within %d seconds after the reset.', $url, CONFORMANCE_OP_TIMEOUT));
            exit(1);
        }
        usleep(2_000_000);
    }
}

/**
 * The plan configuration with its placeholders filled: {NAME} is the value of NAME in the environment of
 * the application, {BEFFROI_DEV_USERNAME} the development user. The file itself carries no secret. A plan
 * that names a client of its own has the "client" of the file replaced before the placeholders are
 * filled, so that its secret comes from the environment like every other; a FAPI plan replaces the
 * clients and what goes with them, which is not in the file at all but in var/conformance/.
 *
 * @param array<string, string> $env
 * @param array<string, mixed> $definition the plan, as CONFORMANCE_PLANS declares it
 */
function conformance_configuration(array $env, array $definition): string
{
    $template = file_get_contents(getcwd() . '/' . CONFORMANCE_CONFIGURATION);
    if ($template === false) {
        throw new RuntimeException(sprintf('Cannot read %s.', CONFORMANCE_CONFIGURATION));
    }
    $client = $definition['client'] ?? [];
    $fapi = $definition['fapi'] ?? [];
    $ciba = $definition['ciba'] ?? [];
    $dynamic = $definition['registers_its_own_clients'] ?? false;
    if ($client !== [] || $fapi !== [] || $ciba !== [] || $dynamic) {
        $decoded = json_decode($template, true, 32, \JSON_THROW_ON_ERROR);
        if ($client !== []) {
            $decoded['client'] = $client;
        }
        if ($fapi !== []) {
            $decoded = conformance_fapi_sections($decoded, $fapi['clients'], (string) $definition['variant']['sender_constrain']);
        }
        if ($ciba !== []) {
            $decoded = conformance_ciba_sections($decoded, $ciba['clients'], $env);
        }
        if ($dynamic) {
            $decoded = conformance_dynamic_sections($decoded);
        }
        $template = json_encode($decoded, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT);
    }
    $values = [
        '{BEFFROI_DEV_USERNAME}' => DEV_USERNAME,
    ];
    foreach ($env as $name => $value) {
        $values['{' . $name . '}'] = $value;
    }
    $configuration = strtr($template, $values);
    if (preg_match_all('/\{[A-Z][A-Z0-9_]*\}/', $configuration, $matches) > 0) {
        throw new RuntimeException(sprintf('%s: no value for %s.', CONFORMANCE_CONFIGURATION, implode(', ', array_unique($matches[0]))));
    }
    // Validates the JSON before the suite sees it.
    json_decode($configuration, flags: \JSON_THROW_ON_ERROR);

    return $configuration;
}

/**
 * The sections a run whose clients register themselves needs in place of those a declared client uses
 * (RFC 7591 §1.3). The "dynamic_client" variant hides the secret and the key of a client section and
 * reads two things of it, the name the client registers under and the initial access token it presents,
 * of which the open mode of a tenant asks for none (decision 0009): the suite draws the key of every
 * client it registers and sends it in the registration request, so a secret or a key written here would
 * be read by nothing. The client that authenticates with a shared secret has no place in such a run, so
 * it goes, as it goes from a FAPI one; the second client stays, under a name of its own, for a module
 * that registers two.
 *
 * @param array<string, mixed> $configuration
 *
 * @return array<string, mixed>
 */
function conformance_dynamic_sections(array $configuration): array
{
    unset($configuration['client_secret_post']);
    $configuration['client'] = [
        'client_name' => CONFORMANCE_DYNAMIC_CLIENT_NAME,
    ];
    $configuration['client2'] = [
        'client_name' => CONFORMANCE_DYNAMIC_SECOND_CLIENT_NAME,
    ];

    return $configuration;
}

/**
 * The sections a FAPI 2 plan needs in place of those the six OpenID Connect plans use: two clients that
 * prove a key or a certificate instead of a shared secret, what each one presents at the handshake when
 * the tokens are bound to a certificate, and the resource a module calls with the token it obtained. The
 * client that authenticates with a shared secret in the file has no place in a FAPI run, so it goes.
 *
 * @param array<string, mixed> $configuration
 * @param list<string> $clients the two clients of the run, "client" and "client2"
 * @param string $senderConstrain what the tokens of the run are bound to, "dpop" or "mtls"
 *
 * @return array<string, mixed>
 */
function conformance_fapi_sections(array $configuration, array $clients, string $senderConstrain): array
{
    unset($configuration['client_secret_post']);
    $certificates = $senderConstrain === 'mtls';
    foreach (['client', 'client2'] as $index => $section) {
        $configuration[$section] = conformance_fapi_client($clients[$index], $certificates);
        if ($certificates) {
            $configuration[$index === 0 ? 'mtls' : 'mtls2'] = conformance_fapi_certificate($clients[$index]);
        }
    }
    // A token bound to a certificate is presented on a connection that carries that certificate, so the
    // resource is called on the host whose listener asks for one (RFC 8705 §5); a token bound to a key
    // is presented anywhere, and the ordinary host of the provider is where the other plans call too.
    $configuration['resource'] = [
        'resourceUrl' => ($certificates ? '{BEFFROI_MTLS_ORIGIN}' : '{BEFFROI_ISSUER}') . CONFORMANCE_FAPI_RESOURCE_PATH,
    ];

    return $configuration;
}

/**
 * The sections a FAPI-CIBA run needs: the ones of a FAPI run whose tokens are bound to a certificate,
 * and the two things this flow adds. There is no browser in it, so the "browser" section of the file is
 * never read and nothing of it is taken out; what replaces it is the URL the suite posts the answer of
 * the user to.
 *
 * Each client says how it names its user and what class it asks of their authentication (CIBA Core
 * §7.1). Both of them, and not the first only: the suite reads those out of the client the module is
 * asking as, and a module that asks as the second client reads them of that client.
 *
 * @param array<string, mixed> $configuration
 * @param list<string> $clients the two clients of the run, "client" and "client2"
 * @param array<string, string> $env the environment of the application, where the user and their password are
 *
 * @return array<string, mixed>
 */
function conformance_ciba_sections(array $configuration, array $clients, array $env): array
{
    $configuration = conformance_fapi_sections($configuration, $clients, 'mtls');
    foreach (['client', 'client2'] as $section) {
        $configuration[$section]['hint_type'] = CONFORMANCE_CIBA_HINT_TYPE;
        $configuration[$section]['hint_value'] = CONFORMANCE_CIBA_HINT_VALUE;
        $configuration[$section]['acr_value'] = CONFORMANCE_CIBA_ACR_VALUE;
    }
    // The values of the user are put in here and not left as placeholders: a password is a value of a
    // query and is encoded for one, which the filling of the file does not do.
    $configuration['automated_ciba_approval_url'] = sprintf(
        '%s%s?%s',
        $env['BEFFROI_ISSUER'],
        CONFORMANCE_CIBA_APPROVAL_PATH,
        implode('&', [
            http_build_query([
                'username' => DEV_USERNAME,
                'password' => $env['BEFFROI_DEV_USER_PASSWORD'],
            ]),
            // what the suite substitutes itself, left as it writes it
            'auth_req_id={auth_req_id}',
            'action={action}',
        ]),
    );

    return $configuration;
}

/**
 * One client of a FAPI run: its identifier, the whole of the key "castor provision" generated for it,
 * private half included, since the suite is the client here, and what it asks for. A run that binds its
 * tokens to a key names the algorithm the proofs are signed with; one that binds them to a certificate
 * presents that certificate instead, and the key is still what signs a request object.
 *
 * @return array<string, mixed>
 */
function conformance_fapi_client(string $clientId, bool $certificates): array
{
    $client = [
        'client_id' => $clientId,
        'jwks' => conformance_fapi_material($clientId, 'jwks.json', static fn (string $contents): array => json_decode(
            $contents,
            true,
            8,
            \JSON_THROW_ON_ERROR,
        )),
        'scope' => CONFORMANCE_FAPI_SCOPE,
    ];
    if (! $certificates) {
        $client['dpop_signing_alg'] = CONFORMANCE_FAPI_DPOP_ALGORITHM;
    }

    return $client;
}

/**
 * The certificate one client of a FAPI run presents at the handshake, with its key: the self-signed pair
 * of var/conformance/, which the provider authenticates against the "x5c" the client publishes (RFC 8705
 * §2.2). There is no chain and no authority, so the suite is given none.
 *
 * @return array<string, string>
 */
function conformance_fapi_certificate(string $clientId): array
{
    return [
        'cert' => conformance_fapi_material($clientId, 'crt', static fn (string $contents): string => $contents),
        'key' => conformance_fapi_material($clientId, 'key', static fn (string $contents): string => $contents),
    ];
}

/**
 * One file of var/conformance/, read as what it is. A file that is not there is a stack that was never
 * provisioned, or one provisioned before the FAPI clients existed: the task says so rather than creating
 * a plan the suite would fail on.
 *
 * @template T
 *
 * @param callable(string): T $read
 *
 * @return T
 */
function conformance_fapi_material(string $clientId, string $extension, callable $read): mixed
{
    $path = sprintf('%s/%s/%s.%s', getcwd(), CONFORMANCE_FAPI_DIRECTORY, $clientId, $extension);
    $contents = is_file($path) ? file_get_contents($path) : false;
    if ($contents === false) {
        io()->error(sprintf('%s holds nothing for the client "%s": run "castor provision" first.', CONFORMANCE_FAPI_DIRECTORY, $clientId));
        exit(1);
    }

    return $read($contents);
}

/**
 * Creates one module of the plan, or on its own with the configuration when there is no plan, starts it
 * when the suite waits for that, waits for it to finish while the scripted browser does the interaction,
 * and returns its result with the failures and warnings of its log. A module the browser cannot finish is
 * left to a human: the task prints the URLs the suite exposes and keeps waiting until
 * CONFORMANCE_MODULE_TIMEOUT. What the suite asks of the operator before the start ("Please rotate the
 * keys ... then press the 'Start' button") is $beforeStart, done by the task.
 *
 * @param array{testModule: string, variant?: array<string, string>} $definition
 * @return array{result: string, url: string, findings: array<string>}
 */
/**
 * The clients of a run that registers a pair of its own, whichever family of plans it belongs to, and
 * none for a run served by the clients of the file.
 *
 * @param array<string, mixed> $definition the plan, as CONFORMANCE_PLANS declares it
 *
 * @return list<string>
 */
function conformance_clients_of(array $definition): array
{
    return $definition['fapi']['clients'] ?? $definition['ciba']['clients'] ?? [];
}

/**
 * Takes back what the development user granted the clients of a run, for the modules that need to see
 * them ask again (CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT).
 *
 * @param list<string> $clients
 */
function conformance_forget_consents(string $module, array $clients): void
{
    if (! in_array($module, CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT, true)) {
        return;
    }
    foreach ($clients as $clientId) {
        op_console(['beffroi:user:revoke-consent', DEV_USERNAME, $clientId], context()->withQuiet());
    }
}

function conformance_run_module(string $suite, ?string $planId, array $definition, string $configuration = '', ?string $beforeStart = null): array
{
    $query = [
        'test' => $definition['testModule'],
    ];
    if ($planId !== null) {
        $query['plan'] = $planId;
    }
    if (($definition['variant'] ?? []) !== []) {
        $query['variant'] = json_encode($definition['variant'], \JSON_THROW_ON_ERROR);
    }
    $created = conformance_request(
        $suite,
        'POST',
        '/api/runner',
        [
            'query' => $query,
            // The configuration is the plan's, or the module's own when it has no plan; an empty POST must not
            // be declared as a form.
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            ...(
                $planId === null
                    ? [
                        'body' => $configuration,
                    ] : []
            ),
        ],
        201,
    );
    $id = (string) $created['id'];
    $url = sprintf('%s/log-detail.html?log=%s', $suite, $id);
    $deadline = microtime(true) + CONFORMANCE_MODULE_TIMEOUT;

    $state = conformance_wait_state($suite, $id, ['CONFIGURED', 'WAITING', 'FINISHED'], $deadline);
    if ($state === 'CONFIGURED') {
        if ($beforeStart === 'rotate') {
            conformance_rotate_signing_key();
        }
        $state = conformance_start_module($suite, $id, $deadline);
    }
    $announced = [];
    while ($state === 'WAITING') {
        $runner = conformance_request($suite, 'GET', sprintf('/api/runner/%s', $id));
        $pending = array_diff($runner['browser']['urls'] ?? [], $runner['browser']['visited'] ?? [], $announced);
        foreach ($pending as $pendingUrl) {
            io()->warning(sprintf('The suite waits for a browser on %s (see %s).', $pendingUrl, $url));
            $announced[] = $pendingUrl;
        }
        $state = conformance_wait_state($suite, $id, ['FINISHED'], $deadline);
    }

    $info = conformance_request($suite, 'GET', sprintf('/api/info/%s', $id));
    $result = (string) ($info['result'] ?? ($state === 'FINISHED' ? 'UNKNOWN' : $state));
    $findings = [];
    if ($result !== 'PASSED') {
        $log = conformance_request($suite, 'GET', sprintf('/api/log/%s', $id));
        foreach ($log as $entry) {
            if (! in_array($entry['result'] ?? null, ['FAILURE', 'WARNING', 'INTERRUPTED'], true)) {
                continue;
            }
            $message = (string) ($entry['msg'] ?? '');
            foreach (['error', 'error_description', 'detail'] as $key) {
                if (is_string($entry[$key] ?? null) && $entry[$key] !== '') {
                    $message .= sprintf(' [%s: %s]', $key, $entry[$key]);
                }
            }
            $findings[] = sprintf('%s %s: %s', $entry['result'], $entry['src'] ?? '?', $message);
        }
    }

    return [
        'result' => $result,
        'url' => $url,
        'findings' => $findings,
    ];
}

/**
 * Starts a module and returns the state it reached.
 *
 * The suite answers this call with the module as it renders it, and sometimes fails to render it: the
 * scripted browser of the previous module is still landing when the next one is asked for, and the state
 * the answer is built from is not finished being written ("Could not write JSON: null", a 500 while the
 * module starts all the same and runs seconds later). The start is therefore judged on the state of the
 * module and never on what that call answered. A module still CONFIGURED once the confirmation window
 * has passed is one that really did not start, and it is asked once more.
 */
function conformance_start_module(string $suite, string $id, float $deadline): string
{
    $start = static fn (): array => conformance_request(
        $suite,
        'POST',
        sprintf('/api/runner/%s', $id),
        [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
        ],
        null,
    );

    $start();
    if (
        conformance_wait_state($suite, $id, ['RUNNING', 'WAITING', 'FINISHED'], min($deadline, microtime(true) + CONFORMANCE_START_CONFIRMATION)) === 'TIMEOUT'
    ) {
        io()->text('  the suite did not report the module started; asking it again');
        $start();
    }

    return conformance_wait_state($suite, $id, ['WAITING', 'FINISHED'], $deadline);
}

/**
 * The rotation the key rotation module asks for, on the OP of the stack: the new key signs at once
 * (--now), the one that signed stays in the JWK Set for its retirement window, which is what the module
 * wants to see. The output of the command is shown: the two identifiers are what the log of the module
 * names.
 */
function conformance_rotate_signing_key(): void
{
    io()->text('  The suite asks for a rotation: "beffroi:keys:rotate --now" on the OP.');
    $rotated = op_console(['beffroi:keys:rotate', '--now', '--no-ansi'], context()->withAllowFailure()->withQuiet());
    if (! $rotated->isSuccessful()) {
        io()->error(['The signing key could not be rotated; the module will see no new key.', trim($rotated->getErrorOutput() . $rotated->getOutput())]);

        return;
    }
    foreach (preg_split('/\R/', trim($rotated->getOutput())) ?: [] as $line) {
        io()->text('  ' . $line);
    }
}

/**
 * Long-polls the state of a module until it is one of those wanted, or the deadline. An interrupted module
 * is returned as such: it is a result. Past the deadline the module is reported as TIMEOUT and left running.
 *
 * @param array<string> $states
 */
function conformance_wait_state(string $suite, string $id, array $states, float $deadline): string
{
    $states[] = 'INTERRUPTED';
    while (true) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) {
            return 'TIMEOUT';
        }
        $answer = conformance_request($suite, 'GET', sprintf('/api/runner/%s/wait-state', $id), [
            'query' => [
                'states' => implode(',', $states),
                'timeoutMs' => (string) min((int) ($remaining * 1000), 30000),
            ],
            'timeout' => 45,
        ]);
        if (($answer['timeout'] ?? false) === true || ! isset($answer['state'])) {
            continue;
        }

        return (string) $answer['state'];
    }
}

/**
 * One call to the API of the suite, decoded. The suite of "castor start --conformance" serves a self-signed
 * certificate for localhost and needs no token; a hosted suite has a public certificate and a token
 * (CONFORMANCE_TOKEN). Nothing here follows a redirect.
 *
 * $expected is the status the call must answer, or null when the answer is not what the call is judged
 * on.
 *
 * @param array<string, mixed> $options
 * @return array<mixed>
 */
function conformance_request(string $suite, string $method, string $path, array $options = [], ?int $expected = 200): array
{
    $local = in_array(parse_url($suite, \PHP_URL_HOST), ['localhost', '127.0.0.1', '::1'], true);
    $token = getenv('CONFORMANCE_TOKEN') ?: null;
    $options['max_redirects'] = 0;
    $options['verify_peer'] = ! $local;
    $options['verify_host'] = ! $local;
    if ($token !== null) {
        $options['auth_bearer'] = $token;
    }

    $response = http_request($method, $suite . $path, $options);
    $status = $response->getStatusCode();
    $content = $response->getContent(false);
    if ($expected !== null && $status !== $expected) {
        throw new RuntimeException(sprintf('%s %s answered %d: %s', $method, $path, $status, mb_substr($content, 0, 500)));
    }
    if ($content === '') {
        return [];
    }
    $decoded = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);

    return (
        is_array($decoded)
            ? $decoded
            : [
                'value' => $decoded,
            ]
    );
}
