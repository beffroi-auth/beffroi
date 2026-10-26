<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\InvalidRedirectUriException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;

/**
 * RFC 7591 §2, OIDC Registration §2: the one reader of the metadata a client is registered with, whether a
 * deployment declared it or a client sent it. What differs between the two is the sources of members each
 * reads behind the ones it was given, and what each does with the refusal it raises (issue #335).
 */
final class ClientMetadataReaderTest extends TestCase
{
    /**
     * A JWK Set a client publishes inline (RFC 7517 §5).
     *
     * @var array<string, mixed>
     */
    private const array JWKS = [
        'keys' => [[
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => 'one',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]],
    ];

    /**
     * RFC 7591 §2: a client that registers nothing beyond its redirection URI is registered for the
     * authorization code grant alone, and not for the renewal a deployment would have written for it.
     */
    #[Test]
    public function aClientThatRegistersNothingTakesTheGrantOfTheSpecification(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame(['authorization_code'], array_map(static fn (object $grant): string => (string) $grant, $registration->grantTypes));
    }

    /**
     * RFC 7591 §2: and with "client_secret_basic", which is the method it authenticates with, and not the
     * first method this provider happens to be wired with.
     */
    #[Test]
    public function aClientThatRegistersNothingTakesTheMethodOfTheSpecification(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame('client_secret_basic', $registration->authenticationMethod->name());
    }

    /**
     * A deployment that writes nothing means the browser flow and the renewal that goes with it, which is
     * what it always meant: the two defaults are two sources and not two branches.
     */
    #[Test]
    public function aDeclarationThatWritesNothingTakesTheDefaultsOfADeployment(): void
    {
        // When
        $registration = Registrations::reader()->read('oidc-demo', self::declared([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]));

        // Then
        static::assertSame(
            ['authorization_code', 'refresh_token'],
            array_map(static fn (object $grant): string => (string) $grant, $registration->grantTypes),
        );
    }

    /**
     * RFC 7591 §3.1.1: the members of a source put in front of another take precedence over the same members
     * sent behind it, which is what an attested registration will be. Nothing here is a branch: the source
     * that wins is the first one asked.
     */
    #[Test]
    public function theSourceInFrontWinsTheMemberTheSourceBehindAlsoCarries(): void
    {
        // Given
        $metadata = new ClientMetadata([
            new RegisteredMembers([
                'client_name' => 'What the statement says',
            ]),
            new RegisteredMembers([
                'client_name' => 'What the client says',
                'redirect_uris' => ['https://rp.example/cb'],
            ]),
            new SpecifiedDefaults(),
        ]);

        // When
        $registration = Registrations::reader()->read('drawn', $metadata, true);

        // Then
        static::assertSame('What the statement says', $registration->presentation->name);
    }

    /**
     * OIDC Registration §2: what a user is shown of the client that is asking, read here and shown by the
     * consent page.
     */
    #[Test]
    public function itReadsWhatAUserIsShownOfTheClient(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => 'An application',
            'client_uri' => 'https://rp.example/',
            'logo_uri' => 'https://rp.example/logo.png',
            'policy_uri' => 'https://rp.example/privacy',
            'tos_uri' => 'https://rp.example/terms',
            'contacts' => ['support@rp.example', 'support@rp.example'],
        ]);

        // Then
        static::assertSame('An application', $registration->presentation->name);
        static::assertSame('https://rp.example/', (string) $registration->presentation->uri);
        static::assertSame('https://rp.example/logo.png', (string) $registration->presentation->logoUri);
        static::assertSame('https://rp.example/privacy', (string) $registration->presentation->policyUri);
        static::assertSame('https://rp.example/terms', (string) $registration->presentation->tosUri);
        static::assertSame(['support@rp.example'], $registration->presentation->contacts);
    }

    /**
     * OIDC Registration §2: a client that registers no name is shown under its identifier, which is the only
     * thing this provider is sure of about it.
     */
    #[Test]
    public function aClientThatRegistersNoNameIsShownUnderItsIdentifier(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame('drawn', $registration->presentation->name);
    }

    /**
     * OIDC Core §8, §8.1, §4: three members this reader holds for whoever resolves a "sub" and whoever
     * begins a login at the client.
     */
    #[Test]
    public function itReadsWhatTheSubjectAndAThirdPartyLoginAreResolvedFrom(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'subject_type' => 'public',
            'sector_identifier_uri' => 'https://rp.example/sector.json',
            'initiate_login_uri' => 'https://rp.example/start',
        ]);

        // Then
        static::assertSame('public', $registration->subjectType);
        static::assertSame('https://rp.example/sector.json', (string) $registration->sectorIdentifierUri);
        static::assertSame('https://rp.example/start', (string) $registration->initiateLoginUri);
    }

    /**
     * OIDC Core §6.2, OIDC Registration §2: a "request_uris" a client registers may carry the fragment §6.2
     * defines, and the value is kept byte for byte, hash included, because that is what a request naming it
     * is compared with (modules `oidcc-request-uri-unsigned` and `-request-uri-signed-rs256`).
     */
    #[Test]
    public function aRequestUriMayCarryTheFragmentOfTheSpecification(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'request_uris' => ['https://rp.example/request.jwt#ZmFrZS1oYXNoLW9mLXRoZS1jb250ZW50'],
        ]);

        // Then
        static::assertSame(
            ['https://rp.example/request.jwt#ZmFrZS1oYXNoLW9mLXRoZS1jb250ZW50'],
            array_map(static fn (object $uri): string => (string) $uri, $registration->requestUris),
        );
    }

    /**
     * The one member held to "https" is held to it alone: plain HTTP on a loopback host is what the URIs of
     * a client on a development stack are, and the exception stays where it is earned rather than being
     * lifted or narrowed for every member at once (decision 0006).
     */
    #[Test]
    public function theMembersThatAcceptPlainHttpOnALoopbackHostStillDo(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'jwks_uri' => 'http://localhost:8000/jwks.json',
            'frontchannel_logout_uri' => 'http://localhost:8000/logout',
        ]);

        // Then
        static::assertSame('http://localhost:8000/jwks.json', (string) $registration->jwksUri);
        static::assertSame('http://localhost:8000/logout', (string) $registration->frontChannelLogoutUri);
    }

    /**
     * OIDC Core §8: a client that registers no kind of "sub" registers none, and sees the kind the provider
     * assigns by default; the registration holds what was registered and nothing it invents.
     */
    #[Test]
    public function aClientThatRegistersNoSubjectTypeRegistersNone(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertNull($registration->subjectType);
    }

    /**
     * RFC 7591 §3.2.2: what the endpoint answers with, which is the class of the refusal, and the member it
     * names. One case per rule the plan judges, read from a body and refused the same way it would be refused
     * in a declaration.
     *
     * @param array<string, mixed> $members
     * @param class-string<UnreadableClientMetadataException> $refusal
     */
    #[Test]
    #[DataProvider('provideRefusedRegistrations')]
    public function aRegistrationThatDoesNotHoldTogetherIsRefusedWithTheCodeOfTheSpecification(
        array $members,
        string $refusal,
        ?string $member,
        string $message,
    ): void {
        // Given
        $metadata = self::registered($members);

        // When
        try {
            Registrations::reader()->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (UnreadableClientMetadataException $exception) {
            // Then
            static::assertInstanceOf($refusal, $exception);
            static::assertSame($member, $exception->member);
            static::assertStringContainsString($message, $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, class-string<UnreadableClientMetadataException>, string|null, string}>
     */
    public static function provideRefusedRegistrations(): iterable
    {
        yield 'a member nobody reads' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'application_type' => 'web',
            ],
            InvalidClientMetadataException::class,
            null,
            'has unknown keys: application_type',
        ];
        yield 'a redirect URI with a fragment (oidcc-registration-regfrag)' => [
            [
                'redirect_uris' => ['https://rp.example/cb#part'],
            ],
            InvalidRedirectUriException::class,
            'redirect_uris',
            'must not carry a fragment',
        ];
        yield 'a logo served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'logo_uri' => 'http://rp.example/logo.png',
            ],
            InvalidClientMetadataException::class,
            'logo_uri',
            'must use HTTPS',
        ];
        yield 'a policy served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'policy_uri' => 'http://rp.example/privacy',
            ],
            InvalidClientMetadataException::class,
            'policy_uri',
            'must use HTTPS',
        ];
        yield 'terms served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'tos_uri' => 'http://rp.example/terms',
            ],
            InvalidClientMetadataException::class,
            'tos_uri',
            'must use HTTPS',
        ];
        yield 'a home page served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'client_uri' => 'http://rp.example/',
            ],
            InvalidClientMetadataException::class,
            'client_uri',
            'must use HTTPS',
        ];
        yield 'keys published inline and behind a URL' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'jwks' => self::JWKS,
                'jwks_uri' => 'https://rp.example/jwks.json',
            ],
            InvalidClientMetadataException::class,
            null,
            'either inline in "jwks" or behind a "jwks_uri", never both',
        ];
        yield 'signed request objects required, and read unsigned (RFC 9101 section 10.5)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'require_signed_request_object' => true,
                'request_object_signing_alg' => 'none',
            ],
            InvalidClientMetadataException::class,
            null,
            'registers no request_object_signing_alg under which an unsigned one is read',
        ];
        yield 'a response type this provider does not answer with' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'response_types' => ['id_token token'],
            ],
            InvalidClientMetadataException::class,
            'response_types',
            'response_types option of the client "drawn" must be one of: code',
        ];
        yield 'a scope that is no scope token' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'scope' => 'openid "quoted"',
            ],
            InvalidClientMetadataException::class,
            'scope',
            'is not a scope token',
        ];
        // The provider of these cases is wired with the public kind alone, so a client that asks for a
        // pairwise "sub" is refused by the same rule that refuses a grant nothing serves (issue #341).
        yield 'a kind of subject this provider assigns none' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'subject_type' => 'pairwise',
            ],
            InvalidClientMetadataException::class,
            'subject_type',
            'subject_type option of the client "drawn" must be one of: public',
        ];
        // RFC 6749 §3.1.2: a redirection carries no fragment, and the kind that accepts one is the kind
        // "request_uris" is read as, never a member name read inside ClientUri (issue #376).
        yield 'a redirection URI that carries a fragment (oidcc-redirect-uri-regfrag)' => [
            [
                'redirect_uris' => ['https://rp.example/cb#frag'],
            ],
            InvalidRedirectUriException::class,
            'redirect_uris',
            'must not carry a fragment',
        ];
        yield 'a login begun by a third party over plain HTTP (oidcc-3rd_party-init-login-nohttps)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'initiate_login_uri' => 'http://rp.example/start',
            ],
            InvalidClientMetadataException::class,
            'initiate_login_uri',
            'must use HTTPS, on a loopback host as anywhere else',
        ];
        // The module sends the URL of the run with its scheme replaced, and the suite runs on
        // "localhost:8443": the member OIDC Registration §2 holds to "https" is held to it on the host a
        // development stack is reached at as well (issue #377).
        yield 'a login begun by a third party over plain HTTP on a loopback host' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'initiate_login_uri' => 'http://localhost:8443/test/a/beffroi/initiate-login',
            ],
            InvalidClientMetadataException::class,
            'initiate_login_uri',
            'must use HTTPS, on a loopback host as anywhere else',
        ];
    }

    /**
     * OIDC Core §8: the kinds a client may name are the ones the provider is wired to assign, so the same
     * registration that is refused on a provider wired with one kind is read on a provider wired with two,
     * and nothing but the wiring says so.
     */
    #[Test]
    public function aKindOfSubjectTheProviderAssignsIsRegistered(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
        ]);

        // When
        $registration = Registrations::reader(subjects: Subjects::bothKinds())->read('drawn', $metadata);

        // Then
        static::assertSame('pairwise', $registration->subjectType);
    }

    /**
     * OIDC Core §8.1: what the pairwise kind needs of a registration is read where a registration meets the
     * wiring, so a client whose sector cannot be read from what it registered is refused at the moment it
     * registers and not at the first token it asks for.
     */
    #[Test]
    public function aClientOfAKindThatNeedsASectorAndNamesNoneIsRefused(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://one.example/cb', 'https://other.example/cb'],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
        ]);

        // When
        try {
            Registrations::reader(subjects: Subjects::bothKinds())->read('drawn', $metadata);
            static::fail('The registration was read.');
        } catch (InvalidClientMetadataException $exception) {
            // Then
            static::assertSame('sector_identifier_uri', $exception->member);
            static::assertStringContainsString('registers redirection URIs on one.example and other.example', $exception->getMessage());
        }
    }

    /**
     * OIDC Registration §2: a client that registers no kind is not a client of no kind, it is a client of
     * the kind the provider assigns by default, which is the first one wired.
     */
    #[Test]
    public function aClientThatRegistersNoKindNamesNone(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // When
        $registration = Registrations::reader(subjects: Subjects::bothKinds())->read('drawn', $metadata);

        // Then
        static::assertNull($registration->subjectType);
    }

    /**
     * OIDC Registration §2: a client that asks for a code and registers no grant that answers with one is
     * refused rather than believed by halves.
     */
    #[Test]
    public function aResponseTypeNoGrantOfTheRegistrationAnswersWithIsRefused(): void
    {
        // Given
        $metadata = self::registered([
            'grant_types' => ['client_credentials'],
            'response_types' => ['code'],
        ]);

        // When
        try {
            Registrations::reader(grants: Grants::servedWithClientCredentials())->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (UnreadableClientMetadataException $exception) {
            // Then
            static::assertSame('response_types', $exception->member);
            static::assertStringContainsString('registers the response type "code" and no grant that would answer with one', $exception->getMessage());
        }
    }

    /**
     * A refusal says which source carried the value, which is what an attested registration needs to be
     * debugged: the same body read from the configuration and from a request names a different one.
     */
    #[Test]
    public function aRefusalSaysWhichSourceCarriedTheValue(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'logo_uri' => 'http://rp.example/logo.png',
        ]);

        // When
        try {
            Registrations::reader()->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (UnreadableClientMetadataException $exception) {
            // Then
            static::assertSame('the registration the client sent', $exception->source);
        }
    }

    /**
     * A grant the tenant serves is read where the registration meets the wiring, wherever the registration
     * came from: a client that registers itself is held to the same list as a declared one.
     */
    #[Test]
    public function aGrantNothingServesIsRefusedInARegistrationAsInADeclaration(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'grant_types' => ['client_credentials'],
        ]);

        // Then
        $this->expectException(UnreadableClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('must be one of: authorization_code, refresh_token');

        // When
        Registrations::reader()->read('drawn', $metadata);
    }

    /**
     * RFC 7591 §2 has no member for the secret the provider assigned (§3.2.1), so the reader is told whether
     * one is held: a store says it by holding a column, a declaration by carrying one.
     */
    #[Test]
    public function aMethodThatProvesASecretNeedsTheProviderToHoldOne(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        $this->expectException(UnreadableClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('therefore needs a secret');

        // When
        Registrations::reader()->read('drawn', $metadata);
    }

    #[Test]
    public function aRegistrationWhoseSecretTheProviderHoldsIsRead(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        static::assertTrue($registration->registersASecret);
    }

    /**
     * What the registration endpoint reads: the members the client sent, behind the defaults of RFC 7591 §2,
     * with the secret the provider drew for it held in a column of its own (§3.2.1).
     *
     * @param array<string, mixed> $members
     */
    private static function read(array $members): ClientRegistration
    {
        return Registrations::reader()->read('drawn', self::registered($members), true);
    }

    /**
     * @param array<string, mixed> $members
     */
    private static function registered(array $members): ClientMetadata
    {
        return Registrations::registered($members);
    }

    /**
     * @param array<string, mixed> $members
     */
    private static function declared(array $members): ClientMetadata
    {
        return Registrations::declared($members);
    }
}
