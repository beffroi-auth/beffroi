<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationAccess;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationReplacement;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\RegistrationPolicies;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7592 §2.2: a client replaces its own registration. It is whole and never a patch, it cannot reach
 * what a registration could not, and what the provider assigned does not change.
 */
final class ClientConfigurationReplacementTest extends TestCase
{
    private const string TOKEN = 'a-value-the-provider-handed-that-client';

    private const string CLIENT_ID = 'drawn-identifier';

    private const string SECRET = 'a-secret-the-provider-handed-it-of-at-least-32-characters';

    private Tenant $tenant;

    private InMemoryClientStore $clients;

    private string $digest;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientStore();
        $this->digest = DrawnSecret::digestOf(self::TOKEN);
    }

    /**
     * RFC 7592 §2.2: a member the request leaves out is a member the client no longer registers.
     */
    #[Test]
    public function aMemberTheRequestLeavesOutIsAMemberTheClientNoLongerRegisters(): void
    {
        // Given
        $this->register([
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => 'What it was called',
        ]);

        // When
        $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame(
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            $this->clients->findRecord($this->tenant, self::CLIENT_ID)?->metadata,
        );
    }

    /**
     * What the provider assigned does not change: the identifier, the date it was drawn on, and the token
     * the client reads itself with, which §2.3 does not require rotating.
     */
    #[Test]
    public function whatTheProviderAssignedStays(): void
    {
        // Given
        $this->register();

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/elsewhere'],
        ]);

        // Then
        static::assertSame(ClientInformationResponse::INFORMED, $response->statusCode);
        static::assertSame($this->digest, $response->record->registrationAccessTokenDigest);
        static::assertNull($response->registrationAccessToken);
        static::assertSame(Fixtures::now()->getTimestamp(), $response->parameters()['client_id_issued_at']);
    }

    /**
     * RFC 7592 §2.2: the request names the client it is for, and a client may not rename itself.
     */
    #[Test]
    #[DataProvider('provideRequestsThatDoNotNameTheClient')]
    public function aRequestThatDoesNotNameTheClientItIsForIsRefused(mixed $named): void
    {
        // Given
        $this->register();
        $members = [
            'redirect_uris' => ['https://rp.example/cb'],
        ];
        if ($named !== null) {
            $members['client_id'] = $named;
        }

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('A client replacing its own registration names itself, and the client "drawn-identifier" is the one this endpoint answers for (RFC 7592 section 2.2).');

        // When
        $this->replace($members);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideRequestsThatDoNotNameTheClient(): iterable
    {
        yield 'a request that names none' => [null];

        yield 'a request that names another client' => ['another-drawn-identifier'];

        yield 'a request whose identifier is no string' => [42];
    }

    /**
     * RFC 7592 §2.2: what the provider assigned is not carried by a replacement.
     */
    #[Test]
    #[DataProvider('provideMembersTheProviderAssigned')]
    public function aRequestThatCarriesWhatTheProviderAssignedIsRefused(string $member, mixed $value): void
    {
        // Given
        $this->register();

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The member "%s" of the client "drawn-identifier" is what the provider assigned, and a replacement does not carry it (RFC 7592 section 2.2).',
            $member,
        ));

        // When
        $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            $member => $value,
        ]);
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function provideMembersTheProviderAssigned(): iterable
    {
        yield 'the date the identifier was drawn on' => ['client_id_issued_at', 1_790_000_000];

        yield 'the date the secret expires on' => ['client_secret_expires_at', 0];

        yield 'the token it reads itself with' => ['registration_access_token', self::TOKEN];

        yield 'the URI it reads itself at' => ['registration_client_uri', 'https://id.acme.example/register/drawn-identifier'];
    }

    /**
     * RFC 7592 §2.2: a client may echo back the secret it holds, which is what §2.2 asks it to send back.
     */
    #[Test]
    public function aClientMayEchoBackTheSecretItHolds(): void
    {
        // Given
        $this->register(secret: $this->hashed());

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'client_secret' => self::SECRET,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        static::assertNull($response->secret);
        static::assertInstanceOf(HashedClientSecret::class, $response->record->secret);
    }

    /**
     * RFC 7592 §2.2: and it may echo back no other.
     */
    #[Test]
    public function aSecretThatIsNotTheClientOwnIsRefused(): void
    {
        // Given
        $this->register(secret: $this->hashed());

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('The "client_secret" of the client "drawn-identifier" is not the secret it holds (RFC 7592 section 2.2).');

        // When
        $this->replace([
            'client_id' => self::CLIENT_ID,
            'client_secret' => 'a-secret-of-somebody-else-of-at-least-32-characters',
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);
    }

    /**
     * A client that holds none is a client no secret is the secret of.
     */
    #[Test]
    public function aClientThatHoldsNoSecretEchoesNone(): void
    {
        // Given
        $this->register();

        // Then
        $this->expectException(InvalidClientMetadataException::class);

        // When
        $this->replace([
            'client_id' => self::CLIENT_ID,
            'client_secret' => self::SECRET,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);
    }

    /**
     * RFC 7591 §3.2.1: the provider assigns a secret exactly when the registered method proves one, so a
     * client that registers such a method where it held none is handed one, answered once.
     */
    #[Test]
    public function aClientThatRegistersAMethodProvingASecretIsHandedOne(): void
    {
        // Given
        $this->register([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        static::assertIsString($response->secret);
        static::assertInstanceOf(HashedClientSecret::class, $response->record->secret);
    }

    /**
     * And a client that registers a method proving none keeps nothing of the secret it held.
     */
    #[Test]
    public function aClientThatRegistersAMethodProvingNoSecretKeepsNone(): void
    {
        // Given
        $this->register([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ], $this->hashed());

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // Then
        static::assertNull($response->record->secret);
    }

    /**
     * OIDC Core §9: a client that registers the method that signs with its secret needs the value, which
     * the provider does not hold of a hash, so it is handed a new one.
     */
    #[Test]
    public function aClientThatRegistersTheMethodSigningWithItsSecretIsHandedOneItCanSignWith(): void
    {
        // Given
        $this->register([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ], $this->hashed());

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_jwt',
        ]);

        // Then
        static::assertIsString($response->secret);
        static::assertInstanceOf(SharedClientSecret::class, $response->record->secret);
    }

    /**
     * Decision 0009: a replacement cannot reach what a registration could not, being read by the same
     * thing under the same policy of the same tenant.
     */
    #[Test]
    public function aReplacementIsHeldToWhatTheTenantOffers(): void
    {
        // Given
        $this->register();

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('which this tenant does not hand out tokens for (decision 0009)');

        // When
        $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => 'openid billing.read',
        ]);
    }

    /**
     * RFC 9101 §10.5: a replacement cannot write the registration a registration could not, a client held
     * to signed request objects that would have them read unsigned.
     */
    #[Test]
    public function aReplacementCannotHaveTheSignedObjectsItRequiresReadUnsigned(): void
    {
        // Given
        $this->register();

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('registers no request_object_signing_alg under which an unsigned one is read (RFC 9101 section 10.5)');

        // When
        $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'require_signed_request_object' => true,
            'request_object_signing_alg' => 'none',
        ]);
    }

    /**
     * Decision 0017: the exemption is read from the policy every time that policy writes a registration,
     * the replacement of §2.2 included.
     */
    #[Test]
    public function thePolicyWritesTheExemptionAgainOnAReplacement(): void
    {
        // Given
        $this->register();

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ], RegistrationPolicies::controlled(true));

        // Then
        static::assertSame(
            [
                'requires_pkce' => false,
            ],
            $response->record->assigned,
        );
    }

    /**
     * And a policy that stops exempting stops writing it, which is how the exception of decision 0017 is
     * withdrawn tenant by tenant.
     */
    #[Test]
    public function aPolicyThatNoLongerExemptsWritesNothingOnAReplacement(): void
    {
        // Given
        $this->register(assigned: [
            'requires_pkce' => false,
        ], secret: $this->hashed());

        // When
        $response = $this->replace([
            'client_id' => self::CLIENT_ID,
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        static::assertSame([], $response->record->assigned);
    }

    #[Test]
    public function aRequestThatReadsNoClientReplacesNothing(): void
    {
        // Given
        $this->register();

        // Then
        $this->expectException(UnauthorizedClientConfigurationException::class);

        // When
        new ClientConfigurationReplacement(
            new ClientConfigurationAccess($this->clients),
            Registrations::reader(),
            RegistrationPolicies::controlled(),
            Registrations::underThePolicy(),
            $this->clients,
            new Endpoints(),
        )->replace($this->tenant, self::CLIENT_ID, new RegistrationRequest([
            'client_id' => self::CLIENT_ID,
        ]));
    }

    /**
     * @param array<string, mixed>|null $metadata
     * @param array<string, mixed> $assigned
     */
    private function register(?array $metadata = null, ?ClientSecretInterface $secret = null, array $assigned = []): void
    {
        $this->clients->save(new ClientRecord(
            Uuid::v7(),
            $this->tenant,
            self::CLIENT_ID,
            $metadata ?? [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            $assigned,
            $secret,
            $this->digest,
            Fixtures::now(),
        ));
    }

    /**
     * @param array<string, mixed> $members
     */
    private function replace(array $members, ?ClientRegistrationPolicyInterface $policies = null): ClientInformationResponse
    {
        return new ClientConfigurationReplacement(
            new ClientConfigurationAccess($this->clients),
            Registrations::reader(),
            $policies ?? RegistrationPolicies::controlled(),
            Registrations::underThePolicy(),
            $this->clients,
            new Endpoints(),
        )->replace($this->tenant, self::CLIENT_ID, new RegistrationRequest($members, 'Bearer ' . self::TOKEN));
    }

    private function hashed(): HashedClientSecret
    {
        return new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET));
    }
}
