<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Domain\Ciba\PingDelivery;
use Beffroi\Oidc\Domain\Ciba\PollDelivery;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\InitiateLoginUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\RequestUri;
use Beffroi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Client\TokenExchange;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Scope\Scope;

final class Clients
{
    /**
     * Where a client registered to be called back when a backchannel request has been answered.
     */
    public const string NOTIFICATION_ENDPOINT = 'https://terminal.example/ciba';

    public const string SECRET = 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3e7f2a6b0c4d8e1f5a9b3c7d0e4f8a2b6';

    /**
     * What a native client registers (RFC 8252 §7.3): the loopback IP literal, no port, the port being what
     * the operating system hands it when it starts.
     */
    public const string LOOPBACK_REDIRECT_URI = 'http://127.0.0.1/callback';

    public const string LOOPBACK_POST_LOGOUT_URI = 'http://127.0.0.1/after-logout';

    /**
     * Two resources a client may be registered for (RFC 8707 §2), as the examples of the RFC name them.
     */
    public const string CALENDAR = 'https://cal.example.com/';

    public const string CONTACTS = 'https://contacts.example.com/';

    /**
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the browser flow and its renewal unless the test says otherwise
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<string> $authorizationDetailsTypes what this client may ask for beyond its scopes (RFC 9396 §2, §11)
     * @param list<RedirectUri>|null $redirectUris where its browser is sent back to, the HTTPS one of the demonstration unless the test says otherwise
     */
    public static function confidential(
        Tenant $tenant,
        PasswordHash $secretHash,
        ?ClientAuthenticationMethodInterface $method = null,
        string $clientId = 'oidc-demo',
        bool $requiresPkce = true,
        ?AccessTokenShapeInterface $accessTokenShape = null,
        ?array $grantTypes = null,
        array $resources = [],
        array $authorizationDetailsTypes = [],
        ?array $redirectUris = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('OIDC demo'),
                $method ?? Methods::clientSecretBasic(),
                true,
                $redirectUris ?? [new RedirectUri('https://demo.localhost/login/check')],
                $accessTokenShape ?? Shapes::jwt(),
                [new RedirectUri('https://demo.localhost/')],
                $grantTypes ?? [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                requiresPkce: $requiresPkce,
                resources: $resources,
                authorizationDetailsTypes: $authorizationDetailsTypes,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * A service acting for itself (RFC 6749 §4.4): a confidential client registered for the client
     * credentials grant, for the resources it asks its tokens for, and for no redirect URI, there being no
     * browser of anybody's to send anywhere.
     *
     * @param list<ResourceIndicator>|null $resources what this client may ask a token for, both fixtures unless the test says otherwise
     */
    public static function service(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'batch',
        ?array $resources = null,
        ?Scopes $allowedScopes = null,
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Nightly batch'),
                Methods::clientSecretBasic(),
                true,
                [],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::clientCredentials()],
                $allowedScopes ?? new Scopes([new Scope('invoices.read'), new Scope('invoices.write')]),
                resources: $resources ?? self::resources(),
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * A service that acts for somebody else (RFC 8693 §2.1): a confidential client registered for the token
     * exchange, for the types of token it may present and for the resources it may ask a token for. It
     * registers no redirect URI, there being no browser of anybody's in the flow.
     *
     * @param list<ResourceIndicator>|null $resources what this client may ask a token for, both fixtures unless the test says otherwise
     * @param list<TokenTypeIdentifier>|null $subjectTokenTypes what it may present, the access token unless the test says otherwise
     */
    public static function gateway(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'gateway',
        ?array $resources = null,
        ?Scopes $allowedScopes = null,
        bool $mayActForAUser = true,
        ?array $subjectTokenTypes = null,
        ?MayAct $mayAct = null,
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('API gateway'),
                Methods::clientSecretBasic(),
                true,
                [],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::tokenExchange()],
                $allowedScopes ?? new Scopes([new Scope('invoices.read'), new Scope('invoices.write')]),
                resources: $resources ?? self::resources(),
                tokenExchange: new TokenExchange($subjectTokenTypes ?? [TokenTypeIdentifier::accessToken()], $mayActForAUser),
                mayAct: $mayAct,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * A service that presents an assertion of an issuer the tenant trusts (RFC 7523 §2.1): a confidential
     * client registered for the JWT bearer grant, for the scopes it may ask for and for the resources its
     * tokens are addressed to. It registers no redirect URI: the user was authenticated elsewhere.
     *
     * @param list<ResourceIndicator>|null $resources what this client may ask a token for, both fixtures unless the test says otherwise
     */
    public static function presentingAssertions(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'job-runner',
        ?array $resources = null,
        ?Scopes $allowedScopes = null,
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Nightly job runner'),
                Methods::clientSecretBasic(),
                true,
                [],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::jwtBearer()],
                $allowedScopes ?? new Scopes([new Scope('invoices.read'), new Scope('invoices.write')]),
                resources: $resources ?? self::resources(),
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * An appliance with no browser and no keyboard (RFC 8628 §3.1): a client registered for the device grant
     * and for the renewal that goes with it, for no redirect URI, there being nothing of anybody's to send
     * anywhere, and for the scopes it shows its user on the approval page.
     *
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the device grant and its renewal unless the test says otherwise
     */
    public static function appliance(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'television',
        ?array $grantTypes = null,
        array $resources = [],
        ?Scopes $allowedScopes = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Television in the waiting room'),
                Methods::clientSecretBasic(),
                true,
                [],
                Shapes::jwt(),
                [],
                $grantTypes ?? [Grants::deviceCode(), Grants::refreshToken()],
                $allowedScopes ?? new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                resources: $resources,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * A client that asks for a user it names and waits for them to approve on a device of their own (CIBA
     * Core §7): registered for the backchannel grant and for the renewal that goes with it, for no
     * redirect URI, there being no browser of its own anywhere in the flow, and for a delivery mode,
     * without which it is not a client of this flow at all.
     *
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the backchannel grant and its renewal unless the test says otherwise
     * @param string|null $jwksUri where this client publishes its keys, which is also what says which sector it is of, a client of this flow registering no redirection URI (CIBA Core §4)
     * @param non-empty-string|null $subjectType the kind of "sub" it sees, null for the one the provider assigns by default
     */
    public static function backchannel(
        Tenant $tenant,
        PasswordHash $secretHash,
        string $clientId = 'payment-terminal',
        ?DeliveryModeInterface $delivery = new PollDelivery(),
        ?ClientUri $notificationEndpoint = null,
        ?array $grantTypes = null,
        array $resources = [],
        ?Scopes $allowedScopes = null,
        ?ClientJwks $jwks = null,
        bool $requiresSignedRequestObject = false,
        ?string $jwksUri = null,
        ?string $sectorIdentifierUri = null,
        ?string $subjectType = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Payment terminal at the counter'),
                Methods::clientSecretBasic(),
                true,
                [],
                Shapes::jwt(),
                [],
                $grantTypes ?? [Grants::ciba(), Grants::refreshToken()],
                $allowedScopes ?? new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                jwks: $jwks,
                requiresSignedRequestObject: $requiresSignedRequestObject,
                resources: $resources,
                backchannelTokenDeliveryMode: $delivery,
                backchannelClientNotificationEndpoint: $notificationEndpoint,
                jwksUri: $jwksUri === null ? null : new ClientUri($jwksUri),
                subjectType: $subjectType,
                sectorIdentifierUri: $sectorIdentifierUri === null ? null : new ClientUri($sectorIdentifierUri),
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * The same client, registered for the mode where this provider calls it back (CIBA Core §10.2).
     */
    public static function pinged(Tenant $tenant, PasswordHash $secretHash, string $clientId = 'payment-terminal'): Client
    {
        return self::backchannel(
            $tenant,
            $secretHash,
            $clientId,
            new PingDelivery(),
            new ClientUri(self::NOTIFICATION_ENDPOINT),
        );
    }

    /**
     * The client of a FAPI-CIBA plan: it authenticates with an assertion, and the tokens it comes for
     * are bound to the certificate it presents all the same (RFC 8705 §3.4, FAPI 1.0 Advanced Final
     * §5.2.2). It registers neither a secret nor a redirect URI, as every client of that flow.
     */
    public static function boundToItsCertificate(Tenant $tenant, string $clientId = 'bound-terminal'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Payment terminal holding a certificate'),
                Methods::privateKeyJwt(),
                false,
                [],
                Shapes::jwt(),
                grantTypes: [Grants::ciba(), Grants::refreshToken()],
                allowedScopes: new Scopes([new Scope('openid'), new Scope('profile')]),
                requiresConsent: false,
                jwks: ClientAssertions::publishedKeys(),
                backchannelTokenDeliveryMode: new PollDelivery(),
                requiresCertificateBoundTokens: true,
            ),
        );
    }

    /**
     * A client whose only way of starting an authorization request is to push it (RFC 9126 §6), which is
     * what FAPI 2.0 asks of one.
     */
    public static function pushingOnly(Tenant $tenant, PasswordHash $secretHash, string $clientId = 'fapi-demo'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('FAPI demo'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://fapi.localhost/login/check')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                requiresPushedAuthorizationRequests: true,
            ),
            new HashedClientSecret($secretHash),
        );
    }

    /**
     * @param list<ResourceIndicator> $resources what this client may ask a token for (RFC 8707 §2)
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the browser flow unless the test says otherwise
     * @param list<RedirectUri>|null $redirectUris where its browser is sent back to, an HTTPS URI unless the test says otherwise
     * @param list<RedirectUri> $postLogoutRedirectUris where it is sent back to at the end of a session (RP-Initiated Logout §2)
     * @param Scopes|null $allowedScopes what this client may ask for, "openid" alone unless the test says otherwise
     */
    public static function public(
        Tenant $tenant,
        string $clientId = 'spa',
        array $resources = [],
        ?array $grantTypes = null,
        ?array $redirectUris = null,
        array $postLogoutRedirectUris = [],
        ?Scopes $allowedScopes = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                $redirectUris ?? [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                $postLogoutRedirectUris,
                grantTypes: $grantTypes ?? [Grants::authorizationCode()],
                allowedScopes: $allowedScopes,
                resources: $resources,
            ),
        );
    }

    /**
     * A client registered for a pairwise "sub" (OIDC Core §8.1): the kind it names, where its browser comes
     * back to, which says which sector it belongs to, and the document it registers to say so instead.
     */
    public static function pairwise(
        Tenant $tenant,
        string $clientId = 'pairwise-app',
        string $redirectUri = 'https://rp.example/callback',
        ?string $sectorIdentifierUri = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Application of a sector'),
                Methods::none(),
                false,
                [new RedirectUri($redirectUri)],
                Shapes::jwt(),
                grantTypes: [Grants::authorizationCode()],
                subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE,
                sectorIdentifierUri: $sectorIdentifierUri === null ? null : new ClientUri($sectorIdentifierUri),
            ),
        );
    }

    /**
     * A client this provider begins a login at (OIDC Core §4): the "initiate_login_uri" it registered,
     * which is where the browser is sent, and the redirection URIs a "target_link_uri" is held to.
     *
     * @param list<RedirectUri>|null $redirectUris where this client's browser comes back to, which is
     *                                             also the set a landing page is named out of
     * @param non-empty-string|null $subjectType the kind of "sub" this client sees, null for the one the
     *                                           provider assigns by default
     */
    public static function withThirdPartyInitiatedLogin(
        Tenant $tenant,
        string $clientId = 'launched-app',
        string $initiateLoginUri = 'https://rp.example/start',
        ?array $redirectUris = null,
        ?string $subjectType = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Application a third party starts'),
                Methods::none(),
                false,
                $redirectUris ?? [new RedirectUri('https://rp.example/callback')],
                Shapes::jwt(),
                grantTypes: [Grants::authorizationCode()],
                subjectType: $subjectType,
                initiateLoginUri: new InitiateLoginUri($initiateLoginUri),
            ),
        );
    }

    /**
     * A native client (RFC 8252 §8.3): a public client whose browser comes back to the loopback interface,
     * on whatever port the operating system handed it, and which registers the IP literal without a port.
     *
     * @param list<RedirectUri>|null $postLogoutRedirectUris the loopback one unless the test says otherwise
     */
    public static function native(Tenant $tenant, string $clientId = 'native-app', ?array $postLogoutRedirectUris = null): Client
    {
        return self::public(
            $tenant,
            $clientId,
            redirectUris: [new RedirectUri(self::LOOPBACK_REDIRECT_URI)],
            postLogoutRedirectUris: $postLogoutRedirectUris ?? [new RedirectUri(self::LOOPBACK_POST_LOGOUT_URI)],
        );
    }

    /**
     * The two resources the fixtures name, for the tests that ask a token for one of them.
     *
     * @return list<ResourceIndicator>
     */
    public static function resources(): array
    {
        return [new ResourceIndicator(self::CALENDAR), new ResourceIndicator(self::CONTACTS)];
    }

    /**
     * The types of authorization detail a client of the tests is registered for (RFC 9396 §11): the one a
     * deployment invents, which InventedAuthorizationDetailType answers for.
     *
     * @return list<string>
     */
    public static function authorizationDetailsTypes(): array
    {
        return [AuthorizationDetailTypes::INVENTED];
    }

    /**
     * A client that signs its assertions with a key of its own (OIDC Core §9, "private_key_jwt"),
     * publishing its JWK Set inline or behind a "jwks_uri".
     *
     * @param list<GrantTypeName>|null $grantTypes what this client registered for, the browser flow alone unless the test says otherwise
     */
    public static function withKeys(
        Tenant $tenant,
        string $clientId = 'key-client',
        ?ClientJwks $jwks = null,
        ?ClientUri $jwksUri = null,
        ?ClientAuthenticationMethodInterface $method = null,
        ?array $grantTypes = null,
        ?string $sectorIdentifierUri = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a key'),
                $method ?? Methods::privateKeyJwt(),
                false,
                [new RedirectUri('https://key.example/callback')],
                Shapes::jwt(),
                grantTypes: $grantTypes ?? [Grants::authorizationCode()],
                jwks: $jwksUri === null ? $jwks ?? ClientAssertions::publishedKeys() : null,
                jwksUri: $jwksUri,
                sectorIdentifierUri: $sectorIdentifierUri === null ? null : new ClientUri($sectorIdentifierUri),
            ),
        );
    }

    /**
     * A client that registered an encryption for what the provider hands it (OIDC Registration §2): it
     * publishes the key the document is addressed to, and receives the shapes given, signed then
     * encrypted. What it registers nothing for it receives as every other client does.
     */
    public static function encryptedFor(
        Tenant $tenant,
        ?ResponseFormat $idToken = null,
        ?ResponseFormat $userInfo = null,
        ?ResponseFormat $authorizationResponse = null,
        string $clientId = 'encrypted-client',
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client that is written to in private'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://encrypted.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                new Scopes([new Scope('openid'), new Scope('profile'), new Scope('email')]),
                jwks: ClientEncryption::publishedKeys(),
                idToken: $idToken,
                authorizationResponse: $authorizationResponse,
                userInfo: $userInfo,
            ),
            new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET)),
        );
    }

    /**
     * A client that sends its authorization requests in a JWT (RFC 9101 §4): it publishes the keys the
     * signature is verified against and registers, or not, the algorithm it signs with, the URLs its
     * objects are published at and that its requests are read from nothing else (§10.5).
     *
     * @param list<RequestUri> $requestUris
     */
    public static function sendingRequestObjects(
        Tenant $tenant,
        ?RequestObjectSigningInterface $signing = null,
        array $requestUris = [],
        string $clientId = 'jar-client',
        bool $requiresSignedRequestObject = false,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client that signs its requests'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://jar.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode()],
                new Scopes([new Scope('openid'), new Scope('profile')]),
                jwks: ClientAssertions::publishedKeys(),
                requestObjectSigning: $signing ?? new AnyRegisteredAlgorithm(),
                requestUris: $requestUris,
                requiresSignedRequestObject: $requiresSignedRequestObject,
            ),
            new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET)),
        );
    }

    /**
     * A client that signs its assertions with the secret it registered (OIDC Core §9,
     * "client_secret_jwt"), which the provider therefore holds in clear.
     */
    public static function withSharedSecret(Tenant $tenant, string $clientId = 'mac-client', string $secret = self::SECRET): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a shared secret'),
                Methods::clientSecretJwt(),
                true,
                [new RedirectUri('https://mac.example/callback')],
                Shapes::jwt(),
            ),
            new SharedClientSecret($secret),
        );
    }

    /**
     * A client recognised by what its certificate says about it (RFC 8705 §2.1): it registers one of the
     * five values of §2.1.2, here the subject distinguished name unless the test names another.
     */
    public static function withCertificateIdentity(
        Tenant $tenant,
        ?CertificateIdentityInterface $identity = null,
        string $clientId = 'mtls-client',
        ?AccessTokenShapeInterface $accessTokenShape = null,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a certificate'),
                Methods::tlsClientAuth(),
                false,
                [new RedirectUri('https://mtls.example/callback')],
                $accessTokenShape ?? Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                null,
                certificateIdentity: $identity ?? new SubjectDistinguishedName(Certificates::SUBJECT_DN),
            ),
        );
    }

    /**
     * A client that publishes the certificate it signs itself (RFC 8705 §2.2), in its JWK Set.
     */
    public static function withPublishedCertificate(Tenant $tenant, ?ClientJwks $jwks = null, string $clientId = 'self-signed-client'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Client with a self-signed certificate'),
                Methods::selfSignedTlsClientAuth(),
                false,
                [new RedirectUri('https://self-signed.example/callback')],
                Shapes::jwt(),
                [],
                [Grants::authorizationCode(), Grants::refreshToken()],
                null,
                jwks: $jwks ?? Certificates::publishedIn(Certificates::selfSigned()),
            ),
        );
    }

    /**
     * A client the logout page loads in a frame when a session it signed in ends (Front-Channel Logout
     * 1.0 §3), which reads "iss" and "sid" only when it said so.
     */
    public static function withFrontChannelLogout(
        Tenant $tenant,
        string $clientId = 'spa',
        string $logoutUri = 'https://spa.example/frontchannel-logout',
        bool $sessionRequired = false,
    ): Client {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                frontChannelLogoutUri: new ClientUri($logoutUri),
                frontChannelLogoutSessionRequired: $sessionRequired,
            ),
        );
    }

    /**
     * A client the provider tells when a session it signed in ends (Back-Channel Logout 1.0 §2.2).
     */
    public static function withBackChannelLogout(Tenant $tenant, string $clientId = 'spa', string $logoutUri = 'https://spa.example/backchannel-logout'): Client
    {
        return new Client(
            $tenant,
            new ClientRegistration(
                $clientId,
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                backChannelLogoutUri: new ClientUri($logoutUri),
            ),
        );
    }
}
