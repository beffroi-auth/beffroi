<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Repository\DoctrineClientRepository;
use Beffroi\Bundle\Tests\Fixture\RecordedMessages;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LogLevel;
use Symfony\Component\HttpFoundation\Response;
use function array_map;
use function base64_encode;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #334: a client this provider registered is a client. It is written through the store, resolved
 * by the identifier it was given like any other, signs in end to end, and is refused everything a client
 * declared in the configuration is refused. Nothing of the flow knows that it came from a row.
 */
final class RegisteredClientFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'drawn-identifier';

    private const string SECRET = 'a-secret-the-provider-handed-it-of-at-least-32-characters';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    private const string STALE_REDIRECT_URI = 'https://registered.test;sandbox/callback';

    #[Test]
    public function aClientWrittenThroughTheStoreIsResolvedByItsIdentifier(): void
    {
        // Given
        $this->register();

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), self::CLIENT_ID);

        // Then
        static::assertSame(self::CLIENT_ID, $client?->registration->clientId);
        static::assertSame('A client that registered itself', $client->registration->presentation->name);
    }

    /**
     * RFC 7591 §2, issue #335: a row is read behind the defaults of the specification and not behind those of
     * a deployment. A client that registered nothing beyond its redirection URI is registered for the
     * authorization code grant alone and authenticates with "client_secret_basic", where a declaration that
     * writes nothing takes the renewal and the first wired method.
     */
    #[Test]
    public function aClientThatRegisteredNothingTakesTheDefaultsOfTheSpecification(): void
    {
        // Given
        $this->registerMembers([
            'redirect_uris' => [self::REDIRECT_URI],
        ]);

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), self::CLIENT_ID);

        // Then
        static::assertInstanceOf(Client::class, $client);
        static::assertSame(['authorization_code'], array_map(
            static fn (GrantTypeName $grantType): string => $grantType->value,
            $client->registration->grantTypes,
        ));
        static::assertSame('client_secret_basic', $client->registration->authenticationMethod->name());
    }

    /**
     * OIDC Core §3.1: the code flow, from the authorization request to the tokens, for a client no line
     * of configuration names.
     */
    #[Test]
    public function aClientWrittenThroughTheStoreSignsAUserInEndToEnd(): void
    {
        // Given
        self::signingKey();
        $this->register();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $tokens = self::json($response);
        static::assertSame('Bearer', $tokens['token_type']);
        static::assertIsString($tokens['id_token']);
        static::assertIsString($tokens['access_token']);
    }

    /**
     * RFC 7591 §2, RFC 3986 §3.2.2, architecture §4.1: a row the reader refuses now, a redirection URI registered
     * before its host was held to a name or an address, names no client, so that the client is unusable rather
     * than the pages that load what it was granted.
     */
    #[Test]
    public function aClientWhoseRowNoLongerReadsIsNoClient(): void
    {
        // Given
        $this->registerAHostThatCarriesADirective();

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), self::CLIENT_ID);

        // Then
        static::assertNull($client);
    }

    /**
     * RFC 6749 §4.1.2.1: the authorization request of that client is the request of a client nobody knows,
     * answered without a redirection.
     */
    #[Test]
    public function aClientWhoseRowNoLongerReadsIsRefusedItsAuthorizationRequest(): void
    {
        // Given
        $this->registerAHostThatCarriesADirective();

        // When
        $this->browser->request('GET', '/authorize', self::parameters([
            'redirect_uri' => self::STALE_REDIRECT_URI,
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
    }

    /**
     * OIDC Discovery §3, architecture §4.1: the document of the tenant reads what its clients registered, and is
     * served whatever a row the reader refuses holds.
     */
    #[Test]
    public function aClientWhoseRowNoLongerReadsLeavesTheDocumentOfTheTenantServed(): void
    {
        // Given
        $this->registerAHostThatCarriesADirective();

        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Architecture §4.1: the row that names no client says so, at the level an operator is alerted on, with the
     * rule it breaks.
     */
    #[Test]
    public function aClientWhoseRowNoLongerReadsIsLoggedAsAnError(): void
    {
        // Given
        $this->registerAHostThatCarriesADirective();
        $said = new RecordedMessages();
        $repository = new DoctrineClientRepository(
            self::service(EntityManagers::class, EntityManagers::class),
            self::service(ClientMetadataReader::class, ClientMetadataReader::class),
            $said,
        );

        // When
        $repository->findByClientId(self::tenant(), self::CLIENT_ID);

        // Then
        static::assertSame(
            [\sprintf(
                'The client "%s" registered metadata this provider refuses now, and is served as no client: The URI "%s" registered for a client must name a host of letters, digits, hyphens and dots, or an IP address (RFC 3986 §3.2.2).',
                self::CLIENT_ID,
                self::STALE_REDIRECT_URI,
            )],
            $said->at(LogLevel::ERROR),
        );
    }

    /**
     * RFC 6749 §3.1.2.3: byte for byte, for a registered client as for a declared one.
     */
    #[Test]
    public function aRegisteredClientIsHeldToTheRedirectUriItRegistered(): void
    {
        // Given
        $this->register();

        // When
        $this->browser->request('GET', '/authorize', self::parameters([
            'redirect_uri' => self::REDIRECT_URI . '?extra=1',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    /**
     * RFC 6749 §3.3: a scope the client did not register is not its to ask for.
     */
    #[Test]
    public function aRegisteredClientIsHeldToTheScopesItRegistered(): void
    {
        // Given
        $this->register();

        // When
        $this->browser->request('GET', '/authorize', self::parameters([
            'scope' => 'openid email',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('invalid_scope', self::redirectedQuery($response)['error'] ?? null);
    }

    /**
     * RFC 6749 §4.1.3: a grant the client did not register is refused at the token endpoint, whichever
     * source holds that client.
     */
    #[Test]
    public function aRegisteredClientIsHeldToTheGrantsItRegistered(): void
    {
        // Given
        $this->register();

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'openid',
            ],
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic(self::SECRET),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('unauthorized_client', self::json($response)['error']);
    }

    /**
     * RFC 8707 §2: a resource outside the list the client registered is "invalid_target", a registered
     * client being held to its list as a declared one is.
     */
    #[Test]
    public function aRegisteredClientIsHeldToTheResourcesItRegistered(): void
    {
        // Given
        $this->register();

        // When
        $this->browser->request('GET', '/authorize', self::parameters([
            'resource' => 'https://files.example.com/',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('invalid_target', self::redirectedQuery($response)['error'] ?? null);
    }

    /**
     * RFC 6749 §2.3.1: the client presents the secret it was handed, and the row holds the digest of it
     * and never the secret, which is what a method that receives one verifies against.
     */
    #[Test]
    public function aClientThatPresentsItsSecretIsAuthenticatedByTheDigestTheRowHolds(): void
    {
        // Given
        self::signingKey();
        $this->register();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertStringNotContainsString(self::SECRET, self::storedSecret());
    }

    /**
     * RFC 6749 §2.3.1: the secret of another client is not this one's, the digest being what is compared.
     */
    #[Test]
    public function aClientPresentingAnotherSecretIsRefused(): void
    {
        // Given
        self::signingKey();
        $this->register();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code, 'another-secret-of-at-least-32-characters-long');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * OIDC Core §9, "client_secret_jwt": a client that signs with the secret it was handed is
     * authenticated by the same MAC the provider computes, which is why the row holds that secret whole
     * and not a digest of it. The registration says which of the two shapes the row keeps.
     */
    #[Test]
    public function aClientThatSignsWithItsSecretIsAuthenticatedByTheAssertionItSigned(): void
    {
        // Given
        self::signingKey();
        $this->register('client_secret_jwt', new SharedClientSecret(self::SECRET));
        $code = $this->codeAllowedByAlice();

        // When
        $this->browser->request(
            'POST',
            '/token',
            ClientAssertions::parameters(ClientAssertions::signedWithSecret(
                ClientAssertions::claims(self::CLIENT_ID, self::tenant()->issuer->value, self::currentSecond()),
                self::SECRET,
            ))
            + [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'client_id' => self::CLIENT_ID,
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['access_token']);
    }

    /**
     * The client written through the store, with the metadata it registered and the secret the provider
     * handed it, hashed as the method it registered verifies against.
     */
    private function register(string $method = 'client_secret_basic', ?ClientSecretInterface $secret = null): void
    {
        $this->registerMembers([
            'client_name' => 'A client that registered itself',
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => $method,
            'scope' => 'openid profile',
        ], $secret);
    }

    /**
     * A row written before the host of a URI a client registers was held to a name or an address.
     */
    private function registerAHostThatCarriesADirective(): void
    {
        $this->registerMembers([
            'client_name' => 'A client that registered itself before the rule',
            'redirect_uris' => [self::STALE_REDIRECT_URI],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => 'openid profile',
        ]);
    }

    /**
     * One row, holding exactly the members given and the secret the provider drew for it.
     *
     * @param array<string, mixed> $members
     */
    private function registerMembers(array $members, ?ClientSecretInterface $secret = null): void
    {
        $secret ??= new HashedClientSecret(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->hash(self::SECRET));
        self::service('test.beffroi.client_store', ClientStoreInterface::class)
            ->save(new ClientRecord(
                Uuid::v7(),
                self::tenant(),
                self::CLIENT_ID,
                $members,
                [],
                $secret,
                DrawnSecret::digestOf(Secrets::draw()),
                self::now(),
            ));
        self::reload();
    }

    /**
     * What the row holds of the secret, read as the database holds it.
     */
    private static function storedSecret(): string
    {
        $connection = self::entityManager()->getConnection();
        $secret = $connection->fetchOne('SELECT secret FROM beffroi_client WHERE client_id = :clientId', [
            'clientId' => self::CLIENT_ID,
        ]);

        return self::string($secret);
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function parameters(array $parameters = []): array
    {
        return self::authorizationParameters(
            self::CLIENT_ID,
            $parameters
            + [
                'redirect_uri' => self::REDIRECT_URI,
            ],
        );
    }

    /**
     * The code the registered client gets once alice signed in and allowed. A client that registered
     * itself asks for a consent like any other: the exemption of architecture §7 is a member only a
     * deployment writes, and a registration that sent it would have been refused.
     */
    private function codeAllowedByAlice(): string
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::parameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * The token request of the registered client, presenting the secret it was handed the way it
     * registered to present it (RFC 6749 §2.3.1).
     */
    private function exchange(string $code, string $secret = self::SECRET): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic($secret),
            ],
        );
    }

    private static function basic(string $secret): string
    {
        return 'Basic ' . base64_encode(self::CLIENT_ID . ':' . $secret);
    }
}
