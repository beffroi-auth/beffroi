<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\RequestUri;
use Beffroi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\OneRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use function array_map;
use function hrtime;
use function range;
use function str_repeat;

/**
 * RFC 7591 §2
 */
final class ClientRegistrationTest extends TestCase
{
    /**
     * RFC 9126 §6
     */
    #[Test]
    public function aClientStartsAnOrdinaryAuthorizationRequestUnlessItSaysOtherwise(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $hash = new FakePasswordHasher()->hash(Clients::SECRET);

        // When / Then
        static::assertFalse(Clients::confidential($tenant, $hash)->registration->requiresPushedAuthorizationRequests);
        static::assertTrue(Clients::pushingOnly($tenant, $hash)->registration->requiresPushedAuthorizationRequests);
    }

    #[Test]
    public function aClientAllowsItsRegisteredGrantsOnly(): void
    {
        // Given
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertTrue($client->registration->allowsGrant(Grants::authorizationCode()));
        static::assertTrue($client->registration->allowsGrant(Grants::refreshToken()));
        static::assertFalse(Clients::public(Fixtures::tenant())->registration->allowsGrant(Grants::refreshToken()));
    }

    #[Test]
    public function aClientAllowsItsRegisteredScopesOnly(): void
    {
        // Given
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertSame(['openid', 'profile', 'email'], $client->registration->allowedScopes->values());
        static::assertTrue($client->registration->allowedScopes->has(Scope::openid()));
        static::assertTrue($client->registration->allowedScopes->has(new Scope('email')));
        static::assertFalse($client->registration->allowedScopes->has(new Scope('offline_access')));
    }

    #[Test]
    public function aClientRequiresConsentUnlessRegisteredOtherwise(): void
    {
        // When
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        static::assertTrue($client->registration->requiresConsent);
    }

    /**
     * Decision 0008
     */
    #[Test]
    public function aClientRequiresPkceUnlessRegisteredOtherwise(): void
    {
        // When
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        static::assertTrue($client->registration->requiresPkce);
    }

    /**
     * Decision 0008
     */
    #[Test]
    public function aConfidentialClientMayBeRegisteredWithoutThePkceRequirement(): void
    {
        // When
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET), requiresPkce: false);

        // Then
        static::assertFalse($client->registration->requiresPkce);
    }

    /**
     * RFC 9449 §5.2, RFC 8705 §3
     */
    #[Test]
    #[DataProvider('provideClientsWhoseTokensAreBoundToTheirCertificate')]
    public function aClientWhoseTokensAreBoundToItsCertificateDoesNotBindThemToADpopKey(
        ClientAuthenticationMethodInterface $method,
        bool $certificateBound,
        ?CertificateIdentityInterface $identity,
    ): void {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "terminal" registers dpop_bound_access_tokens while its tokens are bound to its certificate, by tls_client_certificate_bound_access_tokens or by the mutual TLS it authenticates with, and a token is bound to one thing (RFC 9449 section 5.2, RFC 8705 section 3).');

        // When
        new ClientRegistration(
            'terminal',
            new ClientPresentation('Payment terminal'),
            $method,
            false,
            [new RedirectUri('https://terminal.example/callback')],
            Shapes::jwt(),
            certificateIdentity: $identity,
            requiresCertificateBoundTokens: $certificateBound,
            requiresDpopBoundTokens: true,
        );
    }

    /**
     * @return iterable<string, array{ClientAuthenticationMethodInterface, bool, CertificateIdentityInterface|null}>
     */
    public static function provideClientsWhoseTokensAreBoundToTheirCertificate(): iterable
    {
        yield 'it registers certificate-bound tokens' => [Methods::none(), true, null];

        yield 'it authenticates with mutual TLS' => [Methods::tlsClientAuth(), false, new SubjectDistinguishedName(Certificates::SUBJECT_DN)];
    }

    /**
     * RFC 9700 §2.1.1, Decision 0008
     */
    #[Test]
    public function aPublicClientCannotBeRegisteredWithoutThePkceRequirement(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "spa" is public and must use PKCE (RFC 9700 section 2.1.1): requires_pkce cannot be false.');

        // When
        new ClientRegistration(
            'spa',
            new ClientPresentation('Single page application'),
            Methods::none(),
            false,
            [new RedirectUri('https://spa.example/callback')],
            Shapes::jwt(),
            requiresPkce: false,
        );
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function aClientRegistersNoEmptyContact(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "spa" registers no empty contact (OIDC Registration section 2).');

        // When
        new ClientRegistration(
            'spa',
            new ClientPresentation('Single page application', contacts: ['support@rp.example', '']),
            Methods::none(),
            false,
            [new RedirectUri('https://spa.example/callback')],
            Shapes::jwt(),
        );
    }

    /**
     * RFC 6749 §2.1
     */
    #[Test]
    public function aPublicClientHasNoSecret(): void
    {
        // When
        $client = Clients::public(Fixtures::tenant());

        // Then
        static::assertTrue($client->registration->isPublic());
        static::assertNull($client->secret);
        static::assertEquals([Grants::authorizationCode()], $client->registration->grantTypes);
        static::assertSame([Scope::openid()->value], $client->registration->allowedScopes->values());
    }

    /**
     * RFC 6749 §3.1.2.3
     */
    #[Test]
    #[DataProvider('provideRedirectUris')]
    public function itMatchesItsRedirectUrisExactly(string $uri, bool $registered): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());

        // When / Then
        static::assertSame($registered, $client->registration->hasRedirectUri($uri));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideRedirectUris(): iterable
    {
        yield 'as registered' => ['https://spa.example/callback', true];
        yield 'trailing slash' => ['https://spa.example/callback/', false];
        yield 'different case' => ['https://spa.example/Callback', false];
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    #[DataProvider('provideLoopbackRedirectUris')]
    public function aPublicClientIsAnsweredOnAnyPortOfItsLoopbackRedirectUri(string $uri, bool $registered): void
    {
        // Given
        $client = Clients::native(Fixtures::tenant());

        // When / Then
        static::assertSame($registered, $client->registration->hasRedirectUri($uri));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideLoopbackRedirectUris(): iterable
    {
        yield 'as registered' => [Clients::LOOPBACK_REDIRECT_URI, true];
        yield 'on the port it was given' => ['http://127.0.0.1:53127/callback', true];
        yield 'another path on that port' => ['http://127.0.0.1:53127/other', false];
        yield 'a name in place of the literal' => ['http://localhost:53127/callback', false];
        yield 'a private address' => ['http://192.168.1.10/callback', false];
        yield 'the other literal' => ['http://[::1]:53127/callback', false];
    }

    /**
     * RFC 8252 §8.3
     */
    #[Test]
    #[DataProvider('provideNamesAPublicClientCannotBeSentBackTo')]
    public function aPublicClientInPlainHttpNamesTheLoopbackLiteral(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('never by a name (RFC 8252 section 8.3)');

        // When
        Clients::public(Fixtures::tenant(), redirectUris: [new RedirectUri($value)]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesAPublicClientCannotBeSentBackTo(): iterable
    {
        yield 'localhost' => ['http://localhost/callback'];
        yield 'localhost with a port' => ['http://localhost:53127/callback'];
        yield 'a name under localhost' => ['http://rp.localhost/callback'];
        yield 'another address of the loopback block' => ['http://127.0.0.2/callback'];
    }

    #[Test]
    public function aPublicClientInPlainHttpNamesTheLoopbackLiteralAtTheEndOfASessionToo(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('never by a name (RFC 8252 section 8.3)');

        // When
        Clients::public(
            Fixtures::tenant(),
            redirectUris: [new RedirectUri(Clients::LOOPBACK_REDIRECT_URI)],
            postLogoutRedirectUris: [new RedirectUri('http://localhost/after-logout')],
        );
    }

    /**
     * RFC 8252 §8.3
     */
    #[Test]
    public function aConfidentialClientMayBeSentBackToALoopbackName(): void
    {
        // Given
        $client = Clients::confidential(
            Fixtures::tenant(),
            new FakePasswordHasher()->hash(Clients::SECRET),
            redirectUris: [new RedirectUri('http://demo.localhost:8003/oidc/callback')],
        );

        // When / Then
        static::assertTrue($client->registration->hasRedirectUri('http://demo.localhost:8003/oidc/callback'));
        static::assertFalse($client->registration->hasRedirectUri('http://demo.localhost:8004/oidc/callback'));
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    public function aConfidentialClientIsHeldToThePortOfItsLoopbackRedirectUri(): void
    {
        // Given
        $client = Clients::confidential(
            Fixtures::tenant(),
            new FakePasswordHasher()->hash(Clients::SECRET),
            redirectUris: [new RedirectUri(Clients::LOOPBACK_REDIRECT_URI)],
        );

        // When / Then
        static::assertTrue($client->registration->hasRedirectUri(Clients::LOOPBACK_REDIRECT_URI));
        static::assertFalse($client->registration->hasRedirectUri('http://127.0.0.1:53127/callback'));
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    public function aPublicClientIsHeldToThePortOfAUriThatIsNotALoopbackOne(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());

        // When / Then
        static::assertFalse($client->registration->hasRedirectUri('https://spa.example:8443/callback'));
    }

    /**
     * RP-Initiated Logout §2
     */
    #[Test]
    public function aPublicClientIsSentBackOnAnyPortOfItsLoopbackPostLogoutRedirectUri(): void
    {
        // Given
        $client = Clients::native(Fixtures::tenant());

        // When / Then
        static::assertTrue($client->registration->hasPostLogoutRedirectUri('http://127.0.0.1:53127/after-logout'));
        static::assertFalse($client->registration->hasPostLogoutRedirectUri('http://127.0.0.1:53127/callback'));
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2
     */
    #[Test]
    #[DataProvider('providePostLogoutRedirectUris')]
    public function itMatchesItsPostLogoutRedirectUrisExactly(string $uri, bool $registered): void
    {
        // Given
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertSame($registered, $client->registration->hasPostLogoutRedirectUri($uri));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function providePostLogoutRedirectUris(): iterable
    {
        yield 'as registered' => ['https://demo.localhost/', true];
        yield 'without the trailing slash' => ['https://demo.localhost', false];
        yield 'a redirect URI' => ['https://demo.localhost/login/check', false];
    }

    #[Test]
    public function aClientWithoutPostLogoutRedirectUriMatchesNone(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());

        // When / Then
        static::assertFalse($client->registration->hasPostLogoutRedirectUri('https://spa.example/'));
    }

    #[Test]
    public function itKeepsEachUriGrantAndScopeOnce(): void
    {
        // When
        $client = new ClientRegistration(
            'twice',
            new ClientPresentation('Twice'),
            Methods::none(),
            false,
            [new RedirectUri('https://rp.example/cb'), new RedirectUri('https://rp.example/cb'), new RedirectUri('https://rp.example/cb2')],
            Shapes::jwt(),
            [new RedirectUri('https://rp.example/'), new RedirectUri('https://rp.example/')],
            [Grants::authorizationCode(), Grants::authorizationCode()],
            new Scopes([new Scope('openid'), new Scope('openid'), new Scope('email')]),
        );

        // Then
        static::assertCount(2, $client->redirectUris);
        static::assertCount(1, $client->postLogoutRedirectUris);
        static::assertEquals([Grants::authorizationCode()], $client->grantTypes);
        static::assertSame(['openid', 'email'], $client->allowedScopes->values());
    }

    #[Test]
    public function theFirstOfTwoEqualUrisIsTheOneKept(): void
    {
        // Given
        $first = new RedirectUri('https://rp.example/cb');

        // When
        $client = new ClientRegistration(
            'twice',
            new ClientPresentation('Twice'),
            Methods::none(),
            false,
            [$first, new RedirectUri('https://rp.example/cb2'), new RedirectUri('https://rp.example/cb')],
            Shapes::jwt(),
        );

        // Then
        static::assertSame($first, $client->redirectUris[0]);
    }

    #[Test]
    public function itKeepsTwentyThousandDistinctUrisAndResourcesInLessThanASecond(): void
    {
        // Given
        $redirectUris = array_map(static fn (int $index): RedirectUri => new RedirectUri('https://rp.example/cb/' . $index), range(1, 20_000));
        $requestUris = array_map(static fn (int $index): RequestUri => new RequestUri('https://rp.example/request/' . $index), range(1, 20_000));
        $resources = self::resources(20_000);

        // When
        $start = hrtime(true);
        $client = new ClientRegistration(
            'many',
            new ClientPresentation('Many'),
            Methods::none(),
            false,
            $redirectUris,
            Shapes::jwt(),
            $redirectUris,
            requestUris: $requestUris,
            resources: $resources,
        );
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertCount(20_000, $client->redirectUris);
        static::assertCount(20_000, $client->postLogoutRedirectUris);
        static::assertCount(20_000, $client->requestUris);
        static::assertCount(20_000, $client->resources);
        static::assertLessThan(1_000, $milliseconds);
    }

    #[Test]
    public function itKeepsFiftyThousandDistinctAuthorizationDetailTypesInLessThanASecond(): void
    {
        // Given
        $types = array_map(static fn (int $index): string => 'type_' . $index, range(1, 50_000));

        // When
        $start = hrtime(true);
        $client = new ClientRegistration(
            'many',
            new ClientPresentation('Many'),
            Methods::none(),
            false,
            [new RedirectUri('https://rp.example/cb')],
            Shapes::jwt(),
            authorizationDetailsTypes: $types,
        );
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertCount(50_000, $client->authorizationDetailsTypes);
        static::assertLessThan(1_000, $milliseconds);
    }

    /**
     * @param callable(): ClientRegistration $build
     */
    #[Test]
    #[DataProvider('provideInvalidClients')]
    public function itRefusesAnInconsistentRegistration(callable $build, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $build();
    }

    /**
     * @return iterable<string, array{callable(): ClientRegistration, string}>
     */
    public static function provideInvalidClients(): iterable
    {
        new FakePasswordHasher()->hash(Clients::SECRET);
        $uris = [new RedirectUri('https://rp.example/cb')];

        yield 'empty client id' => [
            static fn (): ClientRegistration => new ClientRegistration('', new ClientPresentation('Name'), Methods::none(), false, $uris, Shapes::jwt()),
            'visible ASCII',
        ];
        yield 'client id with a trailing space' => [
            static fn (): ClientRegistration => new ClientRegistration('demo ', new ClientPresentation('Name'), Methods::none(), false, $uris, Shapes::jwt()),
            'visible ASCII',
        ];
        yield 'client id with a control character' => [
            static fn (): ClientRegistration => new ClientRegistration("de\tmo", new ClientPresentation('Name'), Methods::none(), false, $uris, Shapes::jwt()),
            'visible ASCII',
        ];
        yield 'client id with a line feed behind it' => [
            static fn (): ClientRegistration => new ClientRegistration("demo\n", new ClientPresentation('Name'), Methods::none(), false, $uris, Shapes::jwt()),
            'visible ASCII',
        ];
        yield 'client id beyond ASCII (RFC 6749 appendix A.1)' => [
            static fn (): ClientRegistration => new ClientRegistration('démo', new ClientPresentation('Name'), Methods::none(), false, $uris, Shapes::jwt()),
            'visible ASCII',
        ];
        yield 'client id longer than an act names its client by (decision 0066)' => [
            static fn (): ClientRegistration => new ClientRegistration(
                str_repeat('d', 256),
                new ClientPresentation('Name'),
                Methods::none(),
                false,
                $uris,
                Shapes::jwt(),
            ),
            'longer than the 255 characters an act names its client by',
        ];
        yield 'empty name' => [
            static fn (): ClientRegistration => new ClientRegistration('demo', new ClientPresentation(''), Methods::none(), false, $uris, Shapes::jwt()),
            'has a name',
        ];
        yield 'client_secret_basic without a secret' => [
            static fn (): ClientRegistration => new ClientRegistration(
                'demo',
                new ClientPresentation('Name'),
                Methods::clientSecretBasic(),
                false,
                $uris,
                Shapes::jwt(),
            ),
            'needs a secret',
        ];
        yield 'client_secret_post without a secret' => [
            static fn (): ClientRegistration => new ClientRegistration(
                'demo',
                new ClientPresentation('Name'),
                Methods::clientSecretPost(),
                false,
                $uris,
                Shapes::jwt(),
            ),
            'needs a secret',
        ];
        yield 'none with a secret (RFC 6749 §2.1)' => [
            static fn (): ClientRegistration => new ClientRegistration('demo', new ClientPresentation('Name'), Methods::none(), true, $uris, Shapes::jwt()),
            'cannot hold a secret',
        ];
        yield 'no grant type' => [
            static fn (): ClientRegistration => new ClientRegistration(
                'demo',
                new ClientPresentation('Name'),
                Methods::none(),
                false,
                $uris,
                Shapes::jwt(),
                [],
                [],
            ),
            'at least one grant type',
        ];
        yield 'no scope' => [
            static fn (): ClientRegistration => new ClientRegistration(
                'demo',
                new ClientPresentation('Name'),
                Methods::none(),
                false,
                $uris,
                Shapes::jwt(),
                [],
                [Grants::authorizationCode()],
                new Scopes([]),
            ),
            'at least one scope',
        ];
        yield 'a resource that is the client itself (RFC 8707 §2, OIDC Core §5.3)' => [
            static fn (): ClientRegistration => new ClientRegistration(
                'https://app.example/',
                new ClientPresentation('Name'),
                Methods::none(),
                false,
                $uris,
                Shapes::jwt(),
                resources: [new ResourceIndicator(Clients::CALENDAR), new ResourceIndicator('https://app.example/')],
            ),
            'names itself among its resources',
        ];
    }

    /**
     * RFC 6749 §2.1
     */
    #[Test]
    #[DataProvider('provideAuthenticationMethods')]
    public function aMethodSaysWhetherItAuthenticatesTheClient(ClientAuthenticationMethodInterface $method, bool $authenticates): void
    {
        // When / Then
        static::assertSame($authenticates, $method->authenticatesClient());
    }

    /**
     * @return iterable<string, array{ClientAuthenticationMethodInterface, bool}>
     */
    public static function provideAuthenticationMethods(): iterable
    {
        yield 'client_secret_basic' => [Methods::clientSecretBasic(), true];
        yield 'client_secret_post' => [Methods::clientSecretPost(), true];
        yield 'private_key_jwt' => [Methods::privateKeyJwt(), true];
        yield 'client_secret_jwt' => [Methods::clientSecretJwt(), true];
        yield 'none' => [Methods::none(), false];
    }

    /**
     * OIDC Core §9
     */
    #[Test]
    public function aClientThatSignsItsAssertionsPublishesItsKeys(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('publishes its keys in "jwks" or behind a "jwks_uri"');

        // When
        new ClientRegistration(
            'key-client',
            new ClientPresentation('Key client'),
            Methods::privateKeyJwt(),
            false,
            [new RedirectUri('https://key.example/callback')],
            Shapes::jwt(),
        );
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientPublishesItsKeysOneWayOrTheOther(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('either inline in "jwks" or behind a "jwks_uri", never both');

        // When
        new ClientRegistration(
            'key-client',
            new ClientPresentation('Key client'),
            Methods::privateKeyJwt(),
            false,
            [new RedirectUri('https://key.example/callback')],
            Shapes::jwt(),
            jwks: ClientAssertions::publishedKeys(),
            jwksUri: new ClientUri('https://key.example/jwks'),
        );
    }

    /**
     * RFC 8705 §2.1
     */
    #[Test]
    public function aClientRecognisedByItsCertificateRegistersWhatNamesItInIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers one of the values of RFC 8705 section 2.1.2');

        // When
        new ClientRegistration(
            'mtls-client',
            new ClientPresentation('Mutual TLS client'),
            Methods::tlsClientAuth(),
            false,
            [new RedirectUri('https://mtls.example/callback')],
            Shapes::jwt(),
        );
    }

    #[Test]
    public function aClientAuthenticatedOtherwiseRegistersNothingOfACertificate(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers none of the values of RFC 8705 section 2.1.2');

        // When
        new ClientRegistration(
            'spa',
            new ClientPresentation('Single page application'),
            Methods::none(),
            false,
            [new RedirectUri('https://spa.example/callback')],
            Shapes::jwt(),
            certificateIdentity: new SubjectDistinguishedName('cn=client'),
        );
    }

    /**
     * RFC 8705 §2.2
     */
    #[Test]
    public function aClientAuthenticatedByASelfSignedCertificatePublishesIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('publishes its keys in "jwks" or behind a "jwks_uri"');

        // When
        new ClientRegistration(
            'self-signed-client',
            new ClientPresentation('Self-signed client'),
            Methods::selfSignedTlsClientAuth(),
            false,
            [new RedirectUri('https://self-signed.example/callback')],
            Shapes::jwt(),
        );
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientMayPublishKeysWithoutAuthenticatingWithThem(): void
    {
        // When
        $client = new ClientRegistration(
            'spa',
            new ClientPresentation('Single page application'),
            Methods::none(),
            false,
            [new RedirectUri('https://spa.example/callback')],
            Shapes::jwt(),
            jwks: ClientAssertions::publishedKeys(),
        );

        // Then
        static::assertInstanceOf(ClientJwks::class, $client->jwks);
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function aRegisteredRequestUriIsMatchedByteForByte(): void
    {
        // Given
        $client = Clients::sendingRequestObjects(Fixtures::tenant(), requestUris: [
            new RequestUri('https://jar.example/request.jwt'),
            new RequestUri('https://jar.example/request.jwt'),
        ]);

        // When / Then
        static::assertCount(1, $client->registration->requestUris);
        static::assertSame('https://jar.example/request.jwt', $client->registration->registeredRequestUri('https://jar.example/request.jwt')?->value);
        static::assertNull($client->registration->registeredRequestUri('https://jar.example/request.jwt?v=2'));
        static::assertNull($client->registration->registeredRequestUri('https://jar.example/Request.jwt'));
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aRegisteredResourceIsMatchedByteForByte(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), resources: [
            new ResourceIndicator(Clients::CALENDAR),
            new ResourceIndicator(Clients::CALENDAR),
        ]);

        // When / Then
        static::assertCount(1, $client->registration->resources);
        static::assertTrue($client->registration->allowsResources(ResourceIndicators::of([Clients::CALENDAR])));
        static::assertFalse($client->registration->allowsResources(ResourceIndicators::of([Clients::CONTACTS])));
        static::assertFalse($client->registration->allowsResources(ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS])));
    }

    #[Test]
    public function aClientRegisteredForTwentyThousandResourcesIsAllowedThemInLessThanASecond(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), resources: self::resources(20_000));
        $asked = new ResourceIndicators(self::resources(20_000));

        // When
        $start = hrtime(true);
        $allowed = $client->registration->allowsResources($asked);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertTrue($allowed);
        static::assertLessThan(1_000, $milliseconds);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aClientRegisteredForNoResourceAsksForNone(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());

        // When / Then
        static::assertFalse($client->registration->allowsResources(ResourceIndicators::of([Clients::CALENDAR])));
    }

    /**
     * RFC 9396 §11
     */
    #[Test]
    public function aRegisteredAuthorizationDetailTypeIsMatchedByteForByte(): void
    {
        // Given
        $client = Clients::confidential(
            Fixtures::tenant(),
            new FakePasswordHasher()->hash(Clients::SECRET),
            authorizationDetailsTypes: [AuthorizationDetailTypes::INVENTED, AuthorizationDetailTypes::INVENTED],
        );

        // When / Then
        static::assertSame([AuthorizationDetailTypes::INVENTED], $client->registration->authorizationDetailsTypes);
        static::assertTrue($client->registration->allowsAuthorizationDetails(AuthorizationDetailTypes::details()));
    }

    /**
     * RFC 9396 §11
     */
    #[Test]
    public function aClientAsksForNoAuthorizationDetailTypeItDidNotRegister(): void
    {
        // Given
        $registered = Clients::confidential(
            Fixtures::tenant(),
            new FakePasswordHasher()->hash(Clients::SECRET),
            authorizationDetailsTypes: [AuthorizationDetailTypes::INVENTED],
        );
        $none = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET), clientId: 'no-details');
        $other = new AuthorizationDetails([new AuthorizationDetail(AuthorizationDetailTypes::UNSERVED)]);

        // When / Then
        static::assertFalse($registered->registration->allowsAuthorizationDetails($other));
        static::assertSame([], $none->registration->authorizationDetailsTypes);
        static::assertFalse($none->registration->allowsAuthorizationDetails(AuthorizationDetailTypes::details()));
    }

    #[Test]
    public function itRefusesAnEmptyAuthorizationDetailTypeName(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "oidc-demo" registers no empty name in a closed list.');

        // When
        Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET), authorizationDetailsTypes: ['']);
    }

    /**
     * RFC 8707 §2
     *
     * @param list<string> $audience
     */
    #[Test]
    #[DataProvider('provideAudiences')]
    public function aTokenIsAddressedToTheClientOrToAResourceItRegistered(array $audience, bool $addressable): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), resources: [new ResourceIndicator(Clients::CALENDAR)]);

        // When / Then
        static::assertSame($addressable, $client->registration->mayBeAddressedTo(new TokenAudience($audience)));
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function provideAudiences(): iterable
    {
        yield 'the client itself' => [['spa'], true];
        yield 'a registered resource' => [[Clients::CALENDAR], true];
        yield 'another client' => [['other'], false];
        yield 'a resource it did not register' => [[Clients::CONTACTS], false];
        yield 'a registered resource and one it did not register' => [[Clients::CALENDAR, Clients::CONTACTS], false];
    }

    /**
     * RFC 8707 §2
     *
     * @param list<string> $audience
     */
    #[Test]
    #[DataProvider('provideAudiencesOfAClientOfDigits')]
    public function aTokenIsAddressedToAClientOfDigitsAsItIsWritten(array $audience, bool $addressable): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), '12');

        // When / Then
        static::assertSame($addressable, $client->registration->mayBeAddressedTo(new TokenAudience($audience)));
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function provideAudiencesOfAClientOfDigits(): iterable
    {
        yield 'the client itself' => [['12'], true];
        yield 'the client written with a leading zero' => [['012'], false];
    }

    #[Test]
    public function aTokenAddressedToTwentyThousandRegisteredResourcesIsAddressableInLessThanASecond(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), resources: self::resources(20_000));
        $audience = new TokenAudience(array_map(static fn (ResourceIndicator $resource): string => $resource->value, self::resources(20_000)));

        // When
        $start = hrtime(true);
        $addressable = $client->registration->mayBeAddressedTo($audience);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertTrue($addressable);
        static::assertLessThan(1_000, $milliseconds);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientRegisteringARequestObjectAlgorithmPublishesItsKeys(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers a request_object_signing_alg');

        // When
        new ClientRegistration(
            'jar-client',
            new ClientPresentation('Client that signs its requests'),
            Methods::none(),
            false,
            [new RedirectUri('https://jar.example/callback')],
            Shapes::jwt(),
            requestObjectSigning: new OneRegisteredAlgorithm(Algorithms::es256()),
        );
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aClientSendingUnsignedRequestObjectsPublishesNothing(): void
    {
        // When
        $client = new ClientRegistration(
            'unsigned-client',
            new ClientPresentation('Client that signs nothing'),
            Methods::none(),
            false,
            [new RedirectUri('https://jar.example/callback')],
            Shapes::jwt(),
            requestObjectSigning: new UnsignedRequestObjects(),
        );

        // Then
        static::assertTrue($client->requestObjectSigning->acceptsUnsigned());
    }

    /**
     * RFC 9101 §10.5
     */
    #[Test]
    public function aClientHeldToSignedRequestObjectsRegistersNothingThatReadsThemUnsigned(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "unsigned-client" has its requests read only from a request object it signed (require_signed_request_object), and therefore registers no request_object_signing_alg under which an unsigned one is read (RFC 9101 section 10.5).');

        // When
        new ClientRegistration(
            'unsigned-client',
            new ClientPresentation('Client that signs nothing'),
            Methods::none(),
            false,
            [new RedirectUri('https://jar.example/callback')],
            Shapes::jwt(),
            requestObjectSigning: new UnsignedRequestObjects(),
            requiresSignedRequestObject: true,
        );
    }

    /**
     * RFC 9101 §10.5, OIDC Registration §2
     */
    #[Test]
    #[DataProvider('provideSignedRequestObjectRegistrations')]
    public function aClientHeldToSignedRequestObjectsRegistersWhatReadsThemSigned(RequestObjectSigningInterface $requestObjectSigning): void
    {
        // When
        $client = new ClientRegistration(
            'jar-client',
            new ClientPresentation('Client that signs its requests'),
            Methods::none(),
            false,
            [new RedirectUri('https://jar.example/callback')],
            Shapes::jwt(),
            jwks: ClientAssertions::publishedKeys(),
            requestObjectSigning: $requestObjectSigning,
            requiresSignedRequestObject: true,
        );

        // Then
        static::assertTrue($client->requiresSignedRequestObject);
    }

    /**
     * @return iterable<string, array{RequestObjectSigningInterface}>
     */
    public static function provideSignedRequestObjectRegistrations(): iterable
    {
        yield 'no algorithm, any the provider verifies' => [new AnyRegisteredAlgorithm()];
        yield 'one algorithm' => [new OneRegisteredAlgorithm(Algorithms::es256())];
    }

    /**
     * @return list<ResourceIndicator>
     */
    private static function resources(int $count): array
    {
        return array_map(static fn (int $index): ResourceIndicator => new ResourceIndicator('https://api.example/' . $index), range(1, $count));
    }
}
