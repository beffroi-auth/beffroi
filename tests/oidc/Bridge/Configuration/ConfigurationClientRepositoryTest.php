<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Configuration;

use function array_column;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use function array_map;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Bridge\Configuration\ClientDefinition;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeGrant;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Beffroi\Oidc\Tests\Fixture\TokenTypes;

final class ConfigurationClientRepositoryTest extends TestCase
{
    /**
     * @var array<string, mixed>
     */
    private const array DEMO = [
        'secret' => Clients::SECRET,
        'redirect_uris' => ['https://demo.localhost/login/check'],
        'post_logout_redirect_uris' => ['https://demo.localhost/'],
        'token_endpoint_auth_method' => 'client_secret_basic',
        'requires_consent' => false,
    ];

    /**
     * @var array<string, mixed>
     */
    private const array SUITE = [
        'client_name' => 'Conformance suite, second client',
        'secret' => Clients::SECRET,
        'redirect_uris' => ['https://localhost:8443/test/a/beffroi/callback', 'https://localhost:8443/test/a/beffroi/callback?dummy1=lorem&dummy2=ipsum'],
        'grant_types' => ['authorization_code'],
        'scope' => 'openid email',
        'token_endpoint_auth_method' => 'client_secret_post',
    ];

    /**
     * @var array<string, mixed>
     */
    private const array SPA = [
        'redirect_uris' => ['https://spa.example/callback'],
        'token_endpoint_auth_method' => 'none',
    ];

    /**
     * A client that authenticates with a key of its own (OIDC Core §9), publishing its JWK Set inline.
     *
     * @var array<string, mixed>
     */
    private const array GATEWAY = [
        'secret' => Clients::SECRET,
        'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
        'resources' => [Clients::CALENDAR],
        'token_exchange' => [
            'subject_token_types' => ['urn:ietf:params:oauth:token-type:access_token'],
            'may_act_for_a_user' => true,
        ],
        'may_act' => 'backend',
    ];

    /**
     * A client that authenticates with a key of its own (OIDC Core §9), publishing its JWK Set inline.
     *
     * @var array<string, mixed>
     */
    private const array KEY_CLIENT = [
        'redirect_uris' => ['https://key.example/callback'],
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks' => [
            'keys' => [[
                'kty' => 'EC',
                'crv' => 'P-256',
                'kid' => 'one',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            ]],
        ],
    ];

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * RFC 7591 §2: a client that authenticates with a key of its own publishes its JWK Set inline.
     */
    #[Test]
    public function aClientMayPublishItsKeysInline(): void
    {
        // Given
        $repository = $this->repository([
            'key-client' => self::KEY_CLIENT,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'key-client');

        // Then
        static::assertSame('private_key_jwt', $client->registration->authenticationMethod->name());
        static::assertInstanceOf(ClientJwks::class, $client->registration->jwks);
        static::assertSame(['one'], array_column($client->registration->jwks->keys, 'kid'));
        static::assertNull($client->registration->jwksUri);
    }

    /**
     * RFC 7591 §2: or behind a "jwks_uri", read as every other URI a client registers.
     */
    #[Test]
    public function aClientMayPublishItsKeysBehindAJwksUri(): void
    {
        // Given
        $repository = $this->repository([
            'key-client' => [
                'redirect_uris' => ['https://key.example/callback'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks_uri' => 'https://key.example/jwks',
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'key-client');

        // Then
        static::assertSame('https://key.example/jwks', $client->registration->jwksUri?->value);
        static::assertNull($client->registration->jwks);
    }

    /**
     * RFC 8705 §2.1.2: a client recognised by its certificate registers one of the five values, each one
     * under the metadata name of the specification.
     */
    #[Test]
    #[DataProvider('provideCertificateRegistrations')]
    public function aClientRegistersWhatNamesItInItsCertificate(string $name, string $value): void
    {
        // Given
        $repository = $this->repository([
            'mtls-client' => [
                'redirect_uris' => ['https://mtls.example/callback'],
                'token_endpoint_auth_method' => 'tls_client_auth',
                $name => $value,
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'mtls-client');

        // Then
        static::assertSame($name, $client->registration->certificateIdentity?->name());
    }

    /**
     * RFC 8705 §2.1.2 asks for a predictable treatment of distinguished names: what a deployment
     * registers is written back by the reader that will read the name of the certificate, once, at boot.
     */
    #[Test]
    public function aRegisteredDistinguishedNameIsWrittenTheWayTheOneOfACertificateIs(): void
    {
        // Given
        $repository = $this->repository([
            'mtls-client' => [
                'redirect_uris' => ['https://mtls.example/callback'],
                'token_endpoint_auth_method' => 'tls_client_auth',
                'tls_client_auth_subject_dn' => 'C=FR,O=Beffroi Test,CN=beffroi mtls client',
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'mtls-client');

        // Then
        static::assertInstanceOf(SubjectDistinguishedName::class, $client->registration->certificateIdentity);
        static::assertSame('c=FR,o=Beffroi Test,cn=beffroi mtls client', $client->registration->certificateIdentity->distinguishedName);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCertificateRegistrations(): iterable
    {
        yield 'tls_client_auth_subject_dn' => ['tls_client_auth_subject_dn', 'cn=beffroi mtls client'];

        yield 'tls_client_auth_san_dns' => ['tls_client_auth_san_dns', 'client.example.com'];

        yield 'tls_client_auth_san_uri' => ['tls_client_auth_san_uri', 'https://client.example.com/callback'];

        yield 'tls_client_auth_san_ip' => ['tls_client_auth_san_ip', '198.51.100.7'];

        yield 'tls_client_auth_san_email' => ['tls_client_auth_san_email', 'ops@client.example.com'];
    }

    /**
     * OIDC Core §9: "client_secret_jwt" computes a MAC with the registered secret, so the secret is kept
     * and not hashed; that is the method's own cost and the reason FAPI 2.0 §5.2.2 takes none.
     */
    #[Test]
    public function aClientThatSignsWithItsSecretKeepsTheSecretAndNotAHash(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $repository = $this->repository([
            'mac-client' => [
                'secret' => Clients::SECRET,
                'redirect_uris' => ['https://mac.example/callback'],
                'token_endpoint_auth_method' => 'client_secret_jwt',
            ],
        ], $hasher);

        // When
        $client = self::find($repository, $this->tenant, 'mac-client');

        // Then
        static::assertInstanceOf(SharedClientSecret::class, $client->secret);
        static::assertSame(Clients::SECRET, $client->secret->value);
        static::assertSame(0, $hasher->hashed);
    }

    /**
     * A client that names no method takes the first wired one (issue #98).
     */
    #[Test]
    public function aClientThatNamesNoMethodTakesTheFirstWiredOne(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => [
                'secret' => Clients::SECRET,
                'redirect_uris' => ['https://demo.localhost/login/check'],
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertSame('client_secret_basic', $client->registration->authenticationMethod->name());
    }

    /**
     * The acceptance of the issue: a client declared in configuration is found by id in its tenant, with
     * the defaults of a confidential client.
     */
    #[Test]
    public function aConfiguredClientIsFoundByIdInItsTenantWithTheDefaults(): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ], new NativePasswordHasher());

        // When
        $demo = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame('oidc-demo', $demo->registration->clientId);
        static::assertSame('oidc-demo', $demo->registration->presentation->name);
        static::assertTrue($demo->belongsTo($this->tenant));
        static::assertSame('client_secret_basic', $demo->registration->authenticationMethod->name());
        static::assertFalse($demo->registration->requiresConsent);
        static::assertTrue($demo->registration->requiresPkce);
        static::assertTrue($demo->registration->hasRedirectUri('https://demo.localhost/login/check'));
        static::assertTrue($demo->registration->hasPostLogoutRedirectUri('https://demo.localhost/'));
        static::assertEquals([Grants::authorizationCode(), Grants::refreshToken()], $demo->registration->grantTypes);
        static::assertSame(['openid', 'profile', 'email'], $demo->registration->allowedScopes->values());
    }

    /**
     * RFC 9396 §11: a client declares the types of authorization detail it may ask for, among the ones the
     * provider is wired with; a name nothing serves fails at boot, and a deployment wired with none says so
     * rather than naming an empty list.
     */
    #[Test]
    public function aClientDeclaresTheAuthorizationDetailTypesItMayAskFor(): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO
                + [
                    'authorization_details_types' => [AuthorizationDetailTypes::INVENTED],
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame([AuthorizationDetailTypes::INVENTED], $client->registration->authorizationDetailsTypes);
    }

    /**
     * A deployment wired with no type serves none, so a client that names one is refused at boot with what
     * the provider actually holds.
     */
    #[Test]
    public function aClientNamingATypeOfADeploymentWiredWithNoneFailsAtBoot(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must be one of: none: this provider is wired with no authorization detail type');

        // When
        new ConfigurationClientRepository(
            'acme',
            [
                'oidc-demo' => self::DEMO
                    + [
                        'authorization_details_types' => [AuthorizationDetailTypes::INVENTED],
                    ],
            ],
            new FakePasswordHasher(),
            Registrations::reader(authorizationDetailTypes: AuthorizationDetailTypes::none()),
        );
    }

    /**
     * RFC 6749 §4.4: a client of a grant it uses for itself registers no redirect URI, there being no
     * browser of anybody's to send anywhere, and it authenticates itself. What a registration of such a
     * grant must carry and must not is read from what the wired grant declares.
     */
    #[Test]
    public function aClientOfAGrantItUsesForItselfRegistersNoRedirectUri(): void
    {
        // Given
        $repository = $this->repository([
            'batch' => [
                'secret' => Clients::SECRET,
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['client_credentials'],
                'scope' => 'invoices.read',
                'resources' => [Clients::CALENDAR],
            ],
        ], grants: Grants::servedWithClientCredentials());

        // When
        $client = self::find($repository, $this->tenant, 'batch');

        // Then
        static::assertSame([], $client->registration->redirectUris);
        static::assertEquals([Grants::clientCredentials()], $client->registration->grantTypes);
        static::assertFalse($client->registration->isPublic());
        static::assertSame([Clients::CALENDAR], array_column($client->registration->resources, 'value'));
    }

    /**
     * What a registration of a grant must carry and must not, read where the registration meets the
     * wiring: only the wired grants say whether one of them sends a browser anywhere, or authenticates the
     * client it serves (issue #98).
     *
     * @param array<string, mixed> $definition
     */
    #[Test]
    #[DataProvider('provideRegistrationsTheseGrantsRefuse')]
    public function aRegistrationTheWiredGrantsRefuseFailsAtBoot(array $definition, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $this->repository([
            'bad' => $definition,
        ], grants: Grants::servedWithClientCredentials());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideRegistrationsTheseGrantsRefuse(): iterable
    {
        yield 'a public client for a grant that authenticates it (RFC 6749 §4.4)' => [
            [
                'token_endpoint_auth_method' => 'none',
                'grant_types' => ['client_credentials'],
                'resources' => [Clients::CALENDAR],
            ],
            'which requires client authentication, and authenticates with none, which proves nothing',
        ];
        yield 'a redirect URI no grant would send the user to' => [
            [
                'secret' => Clients::SECRET,
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['client_credentials'],
                'redirect_uris' => ['https://batch.example/callback'],
                'resources' => [Clients::CALENDAR],
            ],
            'registers redirect URIs and no grant that would send the user to one',
        ];
        yield 'no redirect URI for the grant that sends the user back (RFC 6749 §3.1.2.2)' => [
            [
                'secret' => Clients::SECRET,
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['authorization_code'],
            ],
            'whose flow sends the user back to it, and therefore registers at least one redirect URI',
        ];
    }

    /**
     * OIDC Core §2, RFC 6749 appendix A.1: a client identifier may carry a space and a subject may not, so
     * a client named that way cannot be the "sub" of a token it holds for itself, and is refused the grant
     * at boot rather than at its first request.
     */
    #[Test]
    public function aClientNamedInAWayASubjectCannotBeIsRefusedThatGrant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('cannot be the "sub" of a token it holds for itself');

        // When
        $this->repository([
            'the batch' => [
                'secret' => Clients::SECRET,
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['client_credentials'],
                'resources' => [Clients::CALENDAR],
            ],
        ], grants: Grants::servedWithClientCredentials());
    }

    /**
     * RFC 6749 §4.5, RFC 7591 §2: a client registers the grants the provider serves, whatever their
     * names, and a grant the provider gains needs no line here to be registrable.
     */
    #[Test]
    public function aClientRegistersAGrantNothingHereKnowsTheNameOf(): void
    {
        // Given
        $repository = new ConfigurationClientRepository(
            $this->tenant->slug,
            [
                'invented-client' => [
                    'token_endpoint_auth_method' => 'none',
                    'grant_types' => ['urn:example:params:oauth:grant-type:invented'],
                ],
            ],
            new FakePasswordHasher(),
            Registrations::reader(grants: new ServedGrants([new FakeGrant(Grants::invented())])),
        );

        // When
        $client = self::find($repository, $this->tenant, 'invented-client');

        // Then
        static::assertTrue($client->registration->allowsGrant(Grants::invented()));
    }

    /**
     * The secret is hashed by the real hasher.
     */
    #[Test]
    public function theSecretIsHashedByTheHasherOfTheCore(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ], $hasher);

        // When
        $demo = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertInstanceOf(HashedClientSecret::class, $demo->secret);
        static::assertSame(Argon2id::NAME, $demo->secret->hash->algorithm->name());
        static::assertTrue($hasher->verify($demo->secret->hash, Clients::SECRET));
        static::assertFalse($hasher->verify($demo->secret->hash, 'not ' . Clients::SECRET));
    }

    /**
     * Every option of a definition is read.
     */
    #[Test]
    public function everyOptionOfADefinitionIsRead(): void
    {
        // Given
        $repository = $this->repository([
            'suite-second' => self::SUITE,
        ]);

        // When
        $suite = self::find($repository, $this->tenant, 'suite-second');

        // Then
        static::assertSame('Conformance suite, second client', $suite->registration->presentation->name);
        static::assertSame('client_secret_post', $suite->registration->authenticationMethod->name());
        static::assertTrue($suite->registration->requiresConsent);
        static::assertTrue($suite->registration->hasRedirectUri('https://localhost:8443/test/a/beffroi/callback?dummy1=lorem&dummy2=ipsum'));
        static::assertFalse($suite->registration->hasPostLogoutRedirectUri('https://localhost:8443/'));
        static::assertEquals([Grants::authorizationCode()], $suite->registration->grantTypes);
        static::assertSame(['openid', 'email'], $suite->registration->allowedScopes->values());
    }

    #[Test]
    public function aClientIsNotBuiltBeforeItIsLookedUp(): void
    {
        // Given
        $hasher = new FakePasswordHasher();

        // When
        $this->repository([
            'oidc-demo' => self::DEMO,
        ], $hasher);

        // Then
        static::assertSame(0, $hasher->hashed);
    }

    #[Test]
    public function aClientIsBuiltOnce(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ], $hasher);

        // When
        $first = self::find($repository, $this->tenant, 'oidc-demo');
        $second = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame($first, $second);
        static::assertSame(1, $hasher->hashed);
    }

    /**
     * The integration may hold a tenant instance per request: each instance gets clients of its own,
     * pointing at it.
     */
    #[Test]
    public function anotherInstanceOfTheTenantGetsClientsOfItsOwn(): void
    {
        // Given
        $again = Fixtures::tenant();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ]);

        // When
        $first = self::find($repository, $this->tenant, 'oidc-demo');
        $second = self::find($repository, $again, 'oidc-demo');

        // Then
        static::assertNotSame($first, $second);
        static::assertSame($this->tenant, $first->tenant);
        static::assertSame($again, $second->tenant);
        static::assertSame($second, self::find($repository, $again, 'oidc-demo'));
    }

    /**
     * The secret is still hashed once per process, whatever the tenant instances.
     */
    #[Test]
    public function theSecretIsHashedOncePerProcess(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
            'spa' => self::SPA,
        ], $hasher);

        // When
        $first = self::find($repository, $this->tenant, 'oidc-demo');
        $second = self::find($repository, Fixtures::tenant(), 'oidc-demo');
        self::find($repository, $this->tenant, 'spa');

        // Then
        static::assertSame($first->secret, $second->secret);
        static::assertSame(1, $hasher->hashed);
    }

    /**
     * @param callable(self): Tenant $tenant
     */
    #[Test]
    #[DataProvider('provideLookupsThatFindNothing')]
    public function anUnknownIdOrAnotherTenantFindsNothing(callable $tenant, string $clientId): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ]);

        // When / Then
        static::assertNull($repository->findByClientId($tenant($this), $clientId));
    }

    /**
     * @return iterable<string, array{callable(self): Tenant, string}>
     */
    public static function provideLookupsThatFindNothing(): iterable
    {
        yield 'unknown id' => [
            static fn (self $test): Tenant => $test->tenant,
            'nobody',
        ];
        yield 'id in another case' => [
            static fn (self $test): Tenant => $test->tenant,
            'OIDC-DEMO',
        ];
        yield 'another tenant' => [
            static fn (self $test): Tenant => Fixtures::tenant('other', 'https://id.other.example'),
            'oidc-demo',
        ];
    }

    /**
     * RFC 6749 §2.1: a public client has no secret and identifies itself with "none".
     */
    #[Test]
    public function aPublicClientIsDeclaredWithNoneAndNoSecret(): void
    {
        // Given
        $repository = $this->repository([
            'spa' => self::SPA,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'spa');

        // Then
        static::assertTrue($client->registration->isPublic());
        static::assertNull($client->secret);
    }

    /**
     * Decision 0008: requires_pkce is read like requires_consent, false only where the configuration says so.
     */
    #[Test]
    public function aConfidentialClientIsDeclaredWithoutThePkceRequirement(): void
    {
        // Given
        $repository = $this->repository([
            'legacy' => self::DEMO
                + [
                    'requires_pkce' => false,
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'legacy');

        // Then
        static::assertFalse($client->registration->requiresPkce);
    }

    /**
     * RFC 9126 §6: a client declares that the only way it starts an authorization request is by pushing
     * it, which is what FAPI 2.0 asks of one; a client that says nothing starts an ordinary one.
     */
    #[Test]
    public function aClientIsDeclaredAsOneThatOnlyPushesItsRequests(): void
    {
        // Given
        $repository = $this->repository([
            'fapi' => self::DEMO
                + [
                    'require_pushed_authorization_requests' => true,
                ],
            'demo' => self::DEMO,
        ]);

        // When
        $fapi = self::find($repository, $this->tenant, 'fapi');

        // Then
        static::assertTrue($fapi->registration->requiresPushedAuthorizationRequests);
        static::assertFalse(self::find($repository, $this->tenant, 'demo')->registration->requiresPushedAuthorizationRequests);
    }

    /**
     * Back-Channel Logout 1.0 §2.2: a client says where to be told a session ended, and whether it reads
     * the "sid" of the token.
     */
    #[Test]
    public function aClientDeclaresWhereItIsToldASessionEnded(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO
                + [
                    'backchannel_logout_uri' => 'https://demo.localhost/backchannel-logout',
                    'backchannel_logout_session_required' => true,
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertSame('https://demo.localhost/backchannel-logout', (string) $client->registration->backChannelLogoutUri);
        static::assertTrue($client->registration->backChannelLogoutSessionRequired);
    }

    /**
     * Back-Channel Logout 1.0 §2.2: a client that declares nothing is told nothing.
     */
    #[Test]
    public function aClientIsToldOfNoLogoutUntilItDeclaresAUri(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertNull($client->registration->backChannelLogoutUri);
        static::assertFalse($client->registration->backChannelLogoutSessionRequired);
    }

    /**
     * Front-Channel Logout 1.0 §2 and §3: a client says where the logout page loads it, and whether it
     * reads the "iss" and the "sid" on that URI.
     */
    #[Test]
    public function aClientDeclaresWhereTheLogoutPageLoadsIt(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO
                + [
                    'frontchannel_logout_uri' => 'https://demo.localhost/frontchannel-logout',
                    'frontchannel_logout_session_required' => true,
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertSame('https://demo.localhost/frontchannel-logout', (string) $client->registration->frontChannelLogoutUri);
        static::assertTrue($client->registration->frontChannelLogoutSessionRequired);
    }

    /**
     * Front-Channel Logout 1.0 §3: a client that declares nothing is not loaded.
     */
    #[Test]
    public function aClientIsLoadedByNoLogoutPageUntilItDeclaresAUri(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertNull($client->registration->frontChannelLogoutUri);
        static::assertFalse($client->registration->frontChannelLogoutSessionRequired);
    }

    /**
     * A wrong definition fails when the repository is built, not when the client first shows up.
     *
     * @param array<string, mixed> $definition
     */
    #[Test]
    #[DataProvider('provideInvalidDefinitions')]
    public function aWrongDefinitionFailsAtBoot(array $definition, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new ConfigurationClientRepository(
            'acme',
            [
                'bad' => $definition,
            ],
            new FakePasswordHasher(),
            Registrations::reader(),
        );
    }

    /**
     * OIDC Registration §2 and JARM §3: what a client registers for each of the three documents it
     * receives is read back on it, the algorithm it is signed with and the pair it is encrypted with.
     */
    #[Test]
    public function aClientIsReadBackWithWhatItRegisteredForEachDocument(): void
    {
        // Given
        $repository = $this->repository([
            'key-client' => self::KEY_CLIENT
                + [
                    'id_token_signed_response_alg' => 'ES256',
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                    'userinfo_signed_response_alg' => 'ES256',
                    'authorization_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'authorization_encrypted_response_enc' => 'A256GCM',
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'key-client');

        // Then
        static::assertSame('ES256', $client->registration->idToken->signature?->name());
        static::assertSame('ECDH-ES+A256KW', $client->registration->idToken->encryption?->algorithm->name());
        static::assertSame('A256GCM', $client->registration->idToken->encryption?->method->name());
        static::assertTrue($client->registration->userInfo->isSigned);
        static::assertFalse($client->registration->userInfo->isEncrypted());
        static::assertTrue($client->registration->authorizationResponse->isEncrypted());
    }

    /**
     * A client that registers nothing receives what every client receives: its ID tokens and its signed
     * authorization responses signed with what the provider signs with, its UserInfo answer as JSON.
     */
    #[Test]
    public function aClientThatRegistersNothingTakesTheOrdinaryShapes(): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame('RS256', $client->registration->idToken->signature?->name());
        static::assertFalse($client->registration->idToken->isEncrypted());
        static::assertTrue($client->registration->userInfo->isPlain());
        static::assertFalse($client->registration->authorizationResponse->isEncrypted());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideInvalidDefinitions(): iterable
    {
        $base = [
            'secret' => Clients::SECRET,
            'redirect_uris' => ['https://rp.example/cb'],
        ];

        yield 'unknown key' => [
            $base
                + [
                    'insecure_allow_plain_pkce' => true,
                ],
            'unknown keys: insecure_allow_plain_pkce',
        ];
        yield 'an encryption algorithm without a content encryption' => [
            self::KEY_CLIENT
                + [
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                ],
            'registers id_token_encrypted_response_alg without id_token_encrypted_response_enc',
        ];
        yield 'a content encryption without an encryption algorithm' => [
            self::KEY_CLIENT
                + [
                    'userinfo_encrypted_response_enc' => 'A256GCM',
                ],
            'registers userinfo_encrypted_response_enc without userinfo_encrypted_response_alg',
        ];
        yield 'an encryption algorithm the provider is not wired with' => [
            self::KEY_CLIENT
                + [
                    'authorization_encrypted_response_alg' => 'RSA1_5',
                    'authorization_encrypted_response_enc' => 'A256GCM',
                ],
            'The authorization_encrypted_response_alg option of the client "bad" must be one of: ECDH-ES+A256KW, RSA-OAEP-256.',
        ];
        yield 'a content encryption the provider is not wired with' => [
            self::KEY_CLIENT
                + [
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A128CBC-HS256',
                ],
            'The id_token_encrypted_response_enc option of the client "bad" must be one of: A256GCM.',
        ];
        yield 'an encrypted response and no key published at all' => [
            $base
                + [
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                ],
            'registers an encrypted response, which is addressed to a key of the client, and therefore publishes its keys',
        ];
        yield 'an encrypted response and no key it can be addressed to' => [
            self::KEY_CLIENT
                + [
                    'id_token_encrypted_response_alg' => 'RSA-OAEP-256',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                ],
            'publishes no key it can be addressed to',
        ];
        yield 'an encrypted response and only a signing key' => [
            [
                'redirect_uris' => ['https://key.example/callback'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'kid' => 'one',
                        'use' => 'sig',
                        'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                        'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                    ]],
                ],
                'userinfo_encrypted_response_alg' => 'ECDH-ES+A256KW',
                'userinfo_encrypted_response_enc' => 'A256GCM',
            ],
            'publishes no key it can be addressed to',
        ];
        yield 'secret not a string' => [
            [
                'secret' => 12345,
            ] + $base,
            'must be a string',
        ];
        yield 'secret too short' => [
            [
                'secret' => 'short',
            ] + $base,
            'at least 32 visible ASCII characters',
        ];
        yield 'secret with a non-ASCII character' => [
            [
                'secret' => 'é' . Clients::SECRET,
            ] + $base,
            'at least 32 visible ASCII characters',
        ];
        yield 'confidential without a secret' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            'needs a secret',
        ];
        yield 'public with a secret' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'none',
                ],
            'cannot hold a secret',
        ];
        yield 'an authentication method nothing is wired with' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'smoke_signal',
                ],
            'must be one of: client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt, tls_client_auth, self_signed_tls_client_auth, none',
        ];
        yield 'an access token shape nothing writes' => [
            $base
                + [
                    'access_token_format' => 'paseto',
                ],
            'The access_token_format option of the client "bad" must be one of: jwt, opaque.',
        ];
        yield 'two of the values of RFC 8705 §2.1.2' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'tls_client_auth',
                    'tls_client_auth_subject_dn' => 'cn=client',
                    'tls_client_auth_san_dns' => 'client.example.com',
                ],
            'registers exactly one of the values of RFC 8705 section 2.1.2',
        ];
        yield 'a subject distinguished name that is not one' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'tls_client_auth',
                    'tls_client_auth_subject_dn' => 'beffroi mtls client',
                ],
            'must be a distinguished name of RFC 4514',
        ];
        yield 'a certificate name that is not a string' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'tls_client_auth',
                    'tls_client_auth_san_dns' => 42,
                ],
            'tls_client_auth_san_dns option of the client "bad" must be a string',
        ];
        yield 'authentication method not a string' => [
            $base
                + [
                    'token_endpoint_auth_method' => true,
                ],
            'token_endpoint_auth_method option of the client "bad" must be a string',
        ];
        yield 'private_key_jwt without keys (RFC 7591 §2)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
            ],
            'publishes its keys in "jwks" or behind a "jwks_uri"',
        ];
        yield 'jwks and jwks_uri together (RFC 7591 §2)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'x',
                        'y' => 'y',
                    ]],
                ],
                'jwks_uri' => 'https://rp.example/jwks',
            ],
            'either inline in "jwks" or behind a "jwks_uri", never both',
        ];
        yield 'jwks not a JWK Set' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => 'no',
                ],
            ],
            'object with a "keys" member',
        ];
        yield 'a symmetric key in jwks (RFC 8725 §3.5)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'oct',
                        'k' => 'AAAA',
                    ]],
                ],
            ],
            'symmetric key in a JWK Set is refused',
        ];
        yield 'requires_consent as a string' => [
            $base
                + [
                    'requires_consent' => 'false',
                ],
            'must be a boolean',
        ];
        yield 'requires_pkce as a string' => [
            $base
                + [
                    'requires_pkce' => 'false',
                ],
            'requires_pkce option of the client "bad" must be a boolean',
        ];
        yield 'require_pushed_authorization_requests as a string' => [
            $base
                + [
                    'require_pushed_authorization_requests' => 'true',
                ],
            'require_pushed_authorization_requests option of the client "bad" must be a boolean',
        ];
        yield 'public client without the PKCE requirement (RFC 9700 §2.1.1)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'none',
                'requires_pkce' => false,
            ],
            'is public and must use PKCE',
        ];
        yield 'client_name not a string' => [
            $base
                + [
                    'client_name' => ['x'],
                ],
            'client_name option of the client "bad" must be a string',
        ];
        yield 'redirect_uris not a list' => [
            [
                'redirect_uris' => 'https://rp.example/cb',
            ] + $base,
            'redirect_uris option of the client "bad" must be a list of strings',
        ];
        yield 'redirect_uris with a non-string' => [
            [
                'redirect_uris' => [42],
            ] + $base,
            'redirect_uris option of the client "bad" must be a list of strings',
        ];
        yield 'redirect URI with a fragment' => [
            [
                'redirect_uris' => ['https://rp.example/cb#x'],
            ] + $base,
            'fragment',
        ];
        yield 'no redirect URI' => [
            [
                'redirect_uris' => [],
            ] + $base,
            'at least one redirect URI',
        ];
        yield 'post logout URI over plain http' => [
            $base
                + [
                    'post_logout_redirect_uris' => ['http://rp.example/'],
                ],
            'HTTPS',
        ];
        yield 'no grant type' => [
            $base
                + [
                    'grant_types' => [],
                ],
            'at least one grant type',
        ];
        yield 'a grant that spends a refresh token, alone' => [
            $base
                + [
                    'grant_types' => ['refresh_token'],
                ],
            'cannot spend with "refresh_token" a refresh token it has no way to obtain: register it for one of: authorization_code',
        ];
        yield 'a grant nothing is wired with' => [
            $base
                + [
                    'grant_types' => ['implicit'],
                ],
            'must be one of: authorization_code, refresh_token',
        ];
        yield 'a scope that is no scope token' => [
            $base
                + [
                    'scope' => 'openid "quoted"',
                ],
            'scope token',
        ];
        yield 'scope not a string' => [
            $base
                + [
                    'scope' => ['openid'],
                ],
            'scope option of the client "bad" must be a string',
        ];
        yield 'empty client_name' => [
            $base
                + [
                    'client_name' => '',
                ],
            'has a name',
        ];
        yield 'unknown signing algorithm' => [
            $base
                + [
                    'id_token_signed_response_alg' => 'HS256',
                ],
            'must be one of: RS256, PS256, ES256, EdDSA',
        ];
        yield 'unknown request object algorithm' => [
            $base
                + [
                    'request_object_signing_alg' => 'HS256',
                ],
            'must be "none" or one of: RS256, PS256, ES256, EdDSA',
        ];
        yield 'request object algorithm without a key to verify it' => [
            $base
                + [
                    'request_object_signing_alg' => 'ES256',
                ],
            'registers a request_object_signing_alg',
        ];
        yield 'signed request objects required, and read unsigned' => [
            $base
                + [
                    'require_signed_request_object' => true,
                    'request_object_signing_alg' => 'none',
                ],
            'registers no request_object_signing_alg under which an unsigned one is read (RFC 9101 section 10.5)',
        ];
        yield 'request_uri over plain http' => [
            $base
                + [
                    'request_uris' => ['http://rp.example/request.jwt'],
                ],
            'HTTPS',
        ];
        yield 'request_uris as a string' => [
            $base
                + [
                    'request_uris' => 'https://rp.example/request.jwt',
                ],
            'request_uris option of the client "bad" must be a list of strings',
        ];
        yield 'a resource that is not an absolute URI' => [
            $base
                + [
                    'resources' => ['cal.example.com'],
                ],
            'is not an absolute URI (RFC 8707 section 2, RFC 3986 section 4.3)',
        ];
        yield 'a resource with a fragment' => [
            $base
                + [
                    'resources' => ['https://cal.example.com/#today'],
                ],
            'must not carry a fragment component (RFC 8707 section 2)',
        ];
        yield 'resources as a string' => [
            $base
                + [
                    'resources' => 'https://cal.example.com/',
                ],
            'resources option of the client "bad" must be a list of strings',
        ];
        yield 'an authorization detail type nothing serves' => [
            $base
                + [
                    'authorization_details_types' => ['payment_initiation'],
                ],
            'authorization_details_types option of the client "bad" must be one of: account_information',
        ];
        yield 'authorization_details_types as a string' => [
            $base
                + [
                    'authorization_details_types' => 'account_information',
                ],
            'authorization_details_types option of the client "bad" must be a list of strings',
        ];
        yield 'back-channel logout URI over plain http' => [
            $base
                + [
                    'backchannel_logout_uri' => 'http://rp.example/backchannel-logout',
                ],
            'HTTPS',
        ];
        yield 'back-channel logout URI with a fragment' => [
            $base
                + [
                    'backchannel_logout_uri' => 'https://rp.example/backchannel-logout#x',
                ],
            'fragment',
        ];
        yield 'back-channel logout URI not a string' => [
            $base
                + [
                    'backchannel_logout_uri' => ['https://rp.example/backchannel-logout'],
                ],
            'backchannel_logout_uri option of the client "bad" must be a string',
        ];
        yield 'backchannel_logout_session_required as a string' => [
            $base
                + [
                    'backchannel_logout_uri' => 'https://rp.example/backchannel-logout',
                    'backchannel_logout_session_required' => 'true',
                ],
            'backchannel_logout_session_required option of the client "bad" must be a boolean',
        ];
        yield 'a "sid" required with nowhere to send it' => [
            $base
                + [
                    'backchannel_logout_session_required' => true,
                ],
            'registers no backchannel_logout_uri',
        ];
        yield 'front-channel logout URI over plain http' => [
            $base
                + [
                    'frontchannel_logout_uri' => 'http://rp.example/frontchannel-logout',
                ],
            'HTTPS',
        ];
        yield 'front-channel logout URI with a fragment' => [
            $base
                + [
                    'frontchannel_logout_uri' => 'https://rp.example/frontchannel-logout#x',
                ],
            'fragment',
        ];
        yield 'front-channel logout URI not a string' => [
            $base
                + [
                    'frontchannel_logout_uri' => ['https://rp.example/frontchannel-logout'],
                ],
            'frontchannel_logout_uri option of the client "bad" must be a string',
        ];
        yield 'frontchannel_logout_session_required as a string' => [
            $base
                + [
                    'frontchannel_logout_uri' => 'https://rp.example/frontchannel-logout',
                    'frontchannel_logout_session_required' => 'true',
                ],
            'frontchannel_logout_session_required option of the client "bad" must be a boolean',
        ];
        yield 'an "iss" and a "sid" required on no URI' => [
            $base
                + [
                    'frontchannel_logout_session_required' => true,
                ],
            'registers no frontchannel_logout_uri',
        ];
    }

    /**
     * RFC 6749 §2.1: a public client has no secret, so there is nothing to hash.
     */
    #[Test]
    public function aPublicDefinitionHasNoSecret(): void
    {
        // When / Then
        static::assertFalse(
            ClientDefinition::fromArray(
                'spa',
                self::SPA,
                Registrations::reader(),
            )->hasSecret(),
        );
        static::assertTrue(
            ClientDefinition::fromArray(
                'oidc-demo',
                self::DEMO,
                Registrations::reader(),
            )->hasSecret(),
        );
    }

    /**
     * Keeping the secret of a public definition is a programming error: the repository asks first.
     */
    #[Test]
    public function aPublicDefinitionRefusesToKeepASecret(): void
    {
        // Given
        $definition = ClientDefinition::fromArray(
            'spa',
            self::SPA,
            Registrations::reader(),
        );

        // Then
        $this->expectException(LogicException::class);

        // When
        $definition->keepSecret(new FakePasswordHasher());
    }

    /**
     * @param array<string, array<string, mixed>> $clients
     */
    private function repository(array $clients, ?PasswordHasherInterface $hasher = null, ?ServedGrantsInterface $grants = null): ConfigurationClientRepository
    {
        return new ConfigurationClientRepository(
            $this->tenant->slug,
            $clients,
            $hasher ?? new FakePasswordHasher(),
            Registrations::reader(grants: $grants ?? Grants::served()),
        );
    }

    private static function find(ConfigurationClientRepository $repository, Tenant $tenant, string $clientId): Client
    {
        return $repository->findByClientId($tenant, $clientId) ?? static::fail(sprintf('The client "%s" should have been found.', $clientId));
    }

    /**
     * OIDC Registration §2: what the client registered in "request_object_signing_alg" and in
     * "request_uris" is read as it is written, the algorithm among those the provider is wired with.
     */
    #[Test]
    public function aClientRegistersHowItSignsItsRequestObjectsAndWhereTheyArePublished(): void
    {
        // Given
        $repository = $this->repository([
            'jar' => self::KEY_CLIENT
                + [
                    'request_object_signing_alg' => 'ES256',
                    'request_uris' => ['https://key.example/request.jwt'],
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'jar');

        // Then
        static::assertTrue($client->registration->requestObjectSigning->accepts('ES256', ['RS256', 'PS256', 'ES256', 'EdDSA']));
        static::assertFalse($client->registration->requestObjectSigning->accepts('PS256', ['RS256', 'PS256', 'ES256', 'EdDSA']));
        static::assertSame('https://key.example/request.jwt', $client->registration->registeredRequestUri('https://key.example/request.jwt')?->value);
    }

    /**
     * RFC 8707 §2: what a client may ask a token for is read as it is written.
     */
    #[Test]
    public function aClientRegistersTheResourcesItMayAskATokenFor(): void
    {
        // Given
        $repository = $this->repository([
            'calendar-client' => self::SPA
                + [
                    'resources' => [Clients::CALENDAR, Clients::CONTACTS],
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'calendar-client');

        // Then
        static::assertTrue($client->registration->allowsResources(ResourceIndicators::of([Clients::CALENDAR])));
        static::assertFalse($client->registration->allowsResources(ResourceIndicators::of(['https://files.example.com/'])));
    }

    /**
     * Issue #334: what this source holds for a tenant, which is what every question about the set of the
     * clients of that tenant is answered from, in the order the deployment declared them.
     */
    #[Test]
    public function itHoldsTheRegistrationsItReadForItsTenant(): void
    {
        // Given
        $repository = $this->repository([
            'spa' => self::SPA,
            'demo' => self::DEMO,
        ]);

        // When
        $registrations = [...$repository->registrationsIn($this->tenant)];

        // Then
        static::assertSame(
            ['spa', 'demo'],
            array_map(static fn (ClientRegistration $registration): string => $registration->clientId, $registrations),
        );
    }

    /**
     * The clients declared here are those of one tenant: another is answered as if there were none.
     */
    #[Test]
    public function itHoldsNoRegistrationOfAnotherTenant(): void
    {
        // Given
        $repository = $this->repository([
            'spa' => self::SPA,
        ]);

        // When / Then
        static::assertSame([], [...$repository->registrationsIn(Fixtures::tenant('other', 'https://id.other.example'))]);
    }

    /**
     * RFC 8693 §2.1, §4.4: what a client may do at the exchange is read as it is written, and so is who may
     * act for the subject of a token issued to it.
     */
    #[Test]
    public function aClientRegistersWhatItMayExchangeAndWhoMayActForItsTokens(): void
    {
        // Given
        $repository = $this->repository([
            'gateway' => self::GATEWAY,
        ], grants: Grants::servedWithTokenExchange());

        // When
        $registration = self::find($repository, $this->tenant, 'gateway')->registration;

        // Then
        static::assertTrue($registration->tokenExchange?->allowsTokenType(TokenTypes::accessToken()));
        static::assertFalse($registration->tokenExchange->allowsTokenType(TokenTypes::invented()));
        static::assertTrue($registration->tokenExchange->mayActForAUser);
        static::assertTrue($registration->mayAct?->equals(new MayAct(new Subject('backend'))));
    }

    /**
     * RFC 8693 §2.1: a client that registers nothing there may exchange nothing, and one that registers
     * nothing about who may act for its tokens says nothing.
     */
    #[Test]
    public function aClientThatRegistersNoExchangeMayExchangeNothing(): void
    {
        // Given
        $repository = $this->repository([
            'spa' => self::SPA,
        ]);

        // When
        $registration = self::find($repository, $this->tenant, 'spa')->registration;

        // Then
        static::assertNull($registration->tokenExchange);
        static::assertNull($registration->mayAct);
    }

    /**
     * RFC 8693 §4.1, §4.4: the client is named where a subject is expected, in the "act" of the token it
     * receives and in the comparison a "may_act" is read for, so an identifier a subject cannot be is refused
     * at boot.
     */
    #[Test]
    public function aClientNamedInAWayASubjectCannotBeIsRefusedTheExchange(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('cannot be the "sub" of a token it holds for itself');

        // When
        $this->repository([
            'the gateway' => self::GATEWAY,
        ], grants: Grants::servedWithTokenExchange());
    }

    /**
     * RFC 8693 §2.1, §3: a registration the wiring of the exchange refuses fails at boot, and not at the
     * first request.
     *
     * @param array<string, mixed> $definition
     */
    #[Test]
    #[DataProvider('provideExchangesThatFailAtBoot')]
    public function anExchangeTheWiringRefusesFailsAtBoot(array $definition, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $this->repository([
            'bad' => $definition,
        ], grants: Grants::servedWithTokenExchange());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideExchangesThatFailAtBoot(): iterable
    {
        yield 'a grant that exchanges and nothing declared' => [
            [
                'secret' => Clients::SECRET,
                'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'resources' => [Clients::CALENDAR],
            ],
            'declares under "token_exchange" what it may present and what it may ask for',
        ];
        yield 'a declaration and no grant that would exchange anything' => [
            [
                'secret' => Clients::SECRET,
                'redirect_uris' => ['https://gateway.example/callback'],
                'token_exchange' => [
                    'subject_token_types' => ['urn:ietf:params:oauth:token-type:access_token'],
                ],
            ],
            'declares a token_exchange and no grant that would exchange anything',
        ];
        yield 'a type nothing reads' => [
            [
                'secret' => Clients::SECRET,
                'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'resources' => [Clients::CALENDAR],
                'token_exchange' => [
                    'subject_token_types' => ['urn:example:params:oauth:token-type:invented'],
                ],
            ],
            'which this provider does not read',
        ];
        yield 'no type at all' => [
            [
                'secret' => Clients::SECRET,
                'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'resources' => [Clients::CALENDAR],
                'token_exchange' => [
                    'subject_token_types' => [],
                ],
            ],
            'registers at least one subject_token_types',
        ];
        yield 'an unknown key in the declaration' => [
            [
                'secret' => Clients::SECRET,
                'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'resources' => [Clients::CALENDAR],
                'token_exchange' => [
                    'subject_token_types' => ['urn:ietf:params:oauth:token-type:access_token'],
                    'may_act_for_anybody' => true,
                ],
            ],
            'has unknown keys: may_act_for_anybody',
        ];
        yield 'a declaration that is not a map' => [
            [
                'secret' => Clients::SECRET,
                'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'resources' => [Clients::CALENDAR],
                'token_exchange' => 'yes',
            ],
            'must be a map (RFC 8693 section 2.1)',
        ];
        yield 'a may_act that is not a subject' => [
            [
                'secret' => Clients::SECRET,
                'grant_types' => ['urn:ietf:params:oauth:grant-type:token-exchange'],
                'resources' => [Clients::CALENDAR],
                'token_exchange' => [
                    'subject_token_types' => ['urn:ietf:params:oauth:token-type:access_token'],
                ],
                'may_act' => 'the backend',
            ],
            'names a subject (OIDC Core section 2)',
        ];
    }
}
