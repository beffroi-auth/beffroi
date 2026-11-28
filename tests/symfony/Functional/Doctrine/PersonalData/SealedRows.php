<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use DateTimeImmutable;
use function array_values;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Credential\Attestation\AttestationEvidence;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use LogicException;
use Psr\Container\ContainerInterface;
use function random_bytes;
use function sprintf;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use Symfony\Component\Uid\Uuid;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use function str_replace;

final readonly class SealedRows
{
    public const int SHORTEST_VALUE = 5;

    /**
     * @var array<string, array<string, string>> table, then column, then one value the column holds
     */
    public const array VALUES = [
        'beffroi_user' => [
            'username' => 'ada-lovelace',
            'email' => 'ada@example.org',
            'phone_number' => '+441632960541',
            'address' => '12 Grand Rue, Saint-Germain',
            'profile' => 'Augusta Ada King-Noel',
            'source' => 'login.acme-federation.example',
            'mail_encryption' => 'the certificate of ada-lovelace',
            'notification_channels' => 'carrier_pigeon',
        ],
        'beffroi_linked_identity' => [
            'provider' => 'login.acme-federation.example',
            'subject' => '110169484474386276334',
            'claims' => 'ada@example.org',
        ],
        'beffroi_passkey_credential' => [
            'name' => 'The key Ada keeps on her keyring',
            'serial_number' => '0ada1815deadbeef',
        ],
        'beffroi_push_subscription' => [
            'endpoint' => 'https://push.example.org/subscriptions/ada-at-the-difference-engine',
            'label' => 'Ada on the laptop by the window',
        ],
        'beffroi_authentication_session' => [
            'created_from' => self::IP_ADDRESS,
            'last_seen_from' => self::USER_AGENT,
        ],
        'beffroi_device_authorization_request' => [
            'requested_from' => self::IP_ADDRESS,
        ],
        'beffroi_journal' => [
            'context' => self::IP_ADDRESS,
        ],
        'beffroi_personal_archive' => [
            'content' => '{"profile":[{"name":"Augusta Ada King-Noel","email":"ada@example.org"}]}',
        ],
        'beffroi_claim_change' => [
            'was' => 'Ada-of-the-notes',
            'became' => 'the-enchantress-of-numbers',
            'context' => self::USER_AGENT,
        ],
        'beffroi_disclosure' => [
            'scopes' => 'engine.notes.read',
            'claims' => 'the_nickname_of_ada',
            'authorization_details' => 'urn:example:the-analytical-engine',
        ],
        'beffroi_backchannel_authentication_request' => [
            'binding_message' => 'Payment of 42 euros to the Analytical Engine Company',
            'requested_from' => self::USER_AGENT,
        ],
        'beffroi_interaction' => [
            'login_hint' => 'ada@example.org',
            'id_token_hint' => 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZGEtc3ViamVjdCJ9.sig',
        ],
        'beffroi_pushed_authorization_request' => [
            'parameters' => 'ada@example.org',
        ],
        'beffroi_saml_service_provider' => [
            'document' => 'grace.hopper@sp.example.org',
        ],
        'beffroi_saml_upstream_identity_provider' => [
            'document' => 'katherine.johnson@idp.example.org',
        ],
        'beffroi_client' => [
            'metadata' => 'The Difference Engine',
            'assigned_metadata' => 'urn:example:scope:assigned-by-the-policy',
            // The software a statement says the client is (RFC 7591 §2.3).
            'attested_metadata' => 'babbage-difference-engine',
            // The API an initial access token gave the client (decision 0043).
            'granted_metadata' => 'https://analytical-engine.example.org/',
            'secret' => 'a-shared-secret-this-provider-handed-over',
        ],
    ];

    /**
     * @var list<string> the other values written inside a column that holds several
     */
    public const array ALSO_WRITTEN = [
        'Augusta Ada King-Noel',
        'ada@example.org',
        self::IP_ADDRESS,
        self::USER_AGENT,
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZGEtc3ViamVjdCJ9.sig',
    ];

    public const string IP_ADDRESS = '203.0.113.10';

    public const string USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0';

    private const array CLAIMS = [
        'email' => 'ada@example.org',
        'email_verified' => true,
        'name' => 'Augusta Ada King-Noel',
        'locale' => 'en-GB',
    ];

    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public function __construct(
        private ContainerInterface $container,
        private Tenant $tenant,
        private DateTimeImmutable $now,
    ) {
    }

    /**
     * @return list<string> every value written into a sealed column, each once
     */
    public static function searchable(): array
    {
        $values = [];
        foreach (self::VALUES as $columns) {
            foreach ($columns as $value) {
                $values[$value] = $value;
            }
        }
        foreach (self::ALSO_WRITTEN as $value) {
            $values[$value] = $value;
        }

        return array_values($values);
    }

    public function all(Client $client): void
    {
        $user = $this->user();
        $this->linkedIdentity($user);
        $this->passkey($user);
        $this->subscription($user);
        $this->session($user);
        $this->deviceRequest($client);
        $this->backchannelRequest($client, $user);
        $this->interaction($client);
        $this->pushedRequest($client);
        $this->client(new SharedClientSecret(self::VALUES['beffroi_client']['secret']), attested: true, granted: true);
        $this->act($user);
        $this->archive($user);
        $this->change($user);
        $this->disclosure($user, $client);
        $this->serviceProviderMetadata();
        $this->identityProviderMetadata();
    }

    public function serviceProviderMetadata(): AcceptedMetadata
    {
        $metadata = new AcceptedServiceProviderMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIMPLESAMLPHP,
            str_replace(
                '</md:EntityDescriptor>',
                sprintf(
                    '<md:ContactPerson contactType="technical"><md:GivenName>Grace</md:GivenName><md:EmailAddress>mailto:%s</md:EmailAddress></md:ContactPerson></md:EntityDescriptor>',
                    self::VALUES['beffroi_saml_service_provider']['document'],
                ),
                ServiceProviderDocuments::simpleSamlPhp(),
            ),
            null,
            $this->now,
        );
        $this->service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)->register($metadata);

        return $metadata;
    }

    public function identityProviderMetadata(): AcceptedUpstreamMetadata
    {
        $metadata = new AcceptedUpstreamMetadata(
            Uuid::v7(),
            $this->tenant,
            IdentityProviderDocuments::SIMPLESAMLPHP,
            str_replace(
                '</md:EntityDescriptor>',
                sprintf(
                    '<md:ContactPerson contactType="technical"><md:GivenName>Katherine</md:GivenName><md:EmailAddress>mailto:%s</md:EmailAddress></md:ContactPerson></md:EntityDescriptor>',
                    self::VALUES['beffroi_saml_upstream_identity_provider']['document'],
                ),
                IdentityProviderDocuments::simpleSamlPhp(),
            ),
            null,
            $this->now,
        );
        $this->service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)->register($metadata);

        return $metadata;
    }

    public function disclosure(User $user, Client $client): Disclosure
    {
        $values = self::VALUES['beffroi_disclosure'];
        $disclosure = new Disclosure(
            Uuid::v7(),
            $user->tenant,
            $user->subject,
            $client->registration->clientId,
            TokensIssued::NAME,
            $this->now,
            new Scopes([new Scope($values['scopes'])]),
            new ClaimsRequest([
                $values['claims'] => new ClaimRequest(),
            ]),
            new AuthorizationDetails([new AuthorizationDetail($values['authorization_details'])]),
            'jwt',
        );
        $this->service('test.beffroi.disclosures', DisclosuresInterface::class)->record($disclosure);

        return $disclosure;
    }

    public function act(User $user): JournalEntry
    {
        $entry = new JournalEntry(
            Uuid::v7(),
            $user->tenant,
            UserAuthenticated::NAME,
            $this->now,
            $this->context(),
            $user->subject,
        );
        $this->service('test.beffroi.journal', JournalInterface::class)->record($entry);

        return $entry;
    }

    public function archive(User $user): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), $user, $this->now);
        $archive->fill(self::VALUES['beffroi_personal_archive']['content'], $this->now);
        $this->service('test.beffroi.archives', PersonalArchiveRepositoryInterface::class)->save($archive);

        return $archive;
    }

    public function change(User $user): ClaimChange
    {
        $change = new ClaimChange(
            Uuid::v7(),
            $user,
            'nickname',
            self::VALUES['beffroi_claim_change']['was'],
            self::VALUES['beffroi_claim_change']['became'],
            $this->now,
            $this->context(),
            new ThePerson(),
        );
        $this->service('test.beffroi.claim_history', ClaimHistoryInterface::class)->record($change);

        return $change;
    }

    public function user(): User
    {
        $values = self::VALUES['beffroi_user'];
        $user = User::create(
            Uuid::v7(),
            $this->tenant,
            new Subject('ada-subject'),
            $values['username'],
            $this->now,
            new EmailAddress($values['email']),
            source: UserSource::upstream($values['source'], ['email', 'name']),
        );
        $user->changePhoneNumber($values['phone_number'], false, $this->now);
        $user->changeAddress(new Address($values['address']), $this->now);
        $user->changeEmail(new EmailAddress($values['email']), true, $this->now);
        $user->encryptMailTo(new MailEncryptionKey('smime', $values['mail_encryption'], 'ADA0', [new EmailAddress($values['email'])]), $this->now);
        $user->chooseChannels(new ChosenChannels([$values['notification_channels']]), $this->now);
        $user->updateProfile(
            new Profile(
                $values['profile'],
            ),
            $this->now,
        );
        $this->service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        return $user;
    }

    public function linkedIdentity(User $user): LinkedIdentity
    {
        $values = self::VALUES['beffroi_linked_identity'];
        $identity = new LinkedIdentity(
            Uuid::v7(),
            $user,
            $values['provider'],
            $values['subject'],
            self::CLAIMS,
            $this->now,
            $this->now,
        );
        $this->service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)->save($identity);

        return $identity;
    }

    public function passkey(User $user): PasskeyCredential
    {
        $passkey = new PasskeyCredential(
            Uuid::v7(),
            $user,
            self::VALUES['beffroi_passkey_credential']['name'],
            random_bytes(16),
            'cose-public-key',
            0,
            ['internal'],
            true,
            true,
            Uuid::v4(),
            Fixtures::userHandle(),
            $this->now,
            AttestationEvidence::enterprise(self::VALUES['beffroi_passkey_credential']['serial_number']),
        );
        $this->service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($passkey);

        return $passkey;
    }

    public function subscription(User $user, ?string $label = self::VALUES['beffroi_push_subscription']['label']): PushSubscription
    {
        $subscription = new PushSubscription(
            Uuid::v7(),
            $user,
            self::VALUES['beffroi_push_subscription']['endpoint'],
            'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM',
            'tBHItJI5svbpez7KI4CCXg',
            'the-application-server-key',
            $label,
            $this->now,
        );
        $this->service('test.beffroi.push_subscriptions', PushSubscriptionRepositoryInterface::class)->save($subscription);

        return $subscription;
    }

    public function session(User $user): AuthenticationSession
    {
        $session = new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            $this->now,
            AuthenticationProofs::of(AuthenticationMethod::password(), $this->now),
            $this->context(),
            $this->now->modify('+12 hours'),
        );
        $this->service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->save($session);

        return $session;
    }

    public function deviceRequest(Client $client): void
    {
        $this->service('test.beffroi.device_authorization_requests', DeviceAuthorizationRecordRepositoryInterface::class)->save(new DeviceAuthorizationRecord(
            DrawnSecret::digestOf('a-device-code'),
            UserCode::hashOf('ZXWVTSRQ'),
            Uuid::v7(),
            $client,
            new Scopes([new Scope('openid')]),
            new ResourceIndicators([new ResourceIndicator('https://cal.example.com/')]),
            $this->context(),
            $this->now,
            $this->now->modify('+10 minutes'),
        ));
    }

    public function backchannelRequest(Client $client, User $user): void
    {
        $this->service(
            'test.beffroi.backchannel_authentication_requests',
            BackchannelAuthenticationRecordRepositoryInterface::class,
        )->save(new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf('an-auth-request-id'),
            Uuid::v7(),
            $client,
            $user,
            new Scopes([new Scope('openid')]),
            new ResourceIndicators([new ResourceIndicator('https://cal.example.com/')]),
            new BindingMessage(self::VALUES['beffroi_backchannel_authentication_request']['binding_message']),
            ['phr'],
            null,
            null,
            $this->context(),
            $this->now,
            $this->now->modify('+5 minutes'),
        ));
    }

    public function interaction(
        Client $client,
        ?string $loginHint = self::VALUES['beffroi_interaction']['login_hint'],
        ?string $idTokenHint = self::VALUES['beffroi_interaction']['id_token_hint'],
    ): string {
        $request = new AuthorizationRequest(
            $client,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid'), new Scope('profile')]),
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
            loginHint: $loginHint,
            idTokenHint: $idTokenHint,
        );
        $id = Secrets::draw();
        $this->service('test.beffroi.interactions', InteractionRepositoryInterface::class)->save(
            new Interaction($id, $this->tenant, $request, 'en', $this->now, $this->now->modify('+10 minutes')),
        );

        return $id;
    }

    public function pushedRequest(Client $client): string
    {
        $hash = DrawnSecret::digestOf(Secrets::draw());
        $this->service('test.beffroi.pushed_authorization_requests', PushedAuthorizationRecordRepositoryInterface::class)->save(new PushedAuthorizationRecord(
            $hash,
            $client,
            [
                'response_type' => 'code',
                'scope' => ['openid', 'profile'],
                'login_hint' => self::VALUES['beffroi_interaction']['login_hint'],
                'id_token_hint' => self::VALUES['beffroi_interaction']['id_token_hint'],
            ],
            $this->now,
            $this->now->modify('+90 seconds'),
        ));

        return $hash;
    }

    /**
     * RFC 7591 §3.1.1
     */
    public function client(?ClientSecretInterface $secret = null, bool $attested = false, bool $granted = false): ClientRecord
    {
        $values = self::VALUES['beffroi_client'];
        $signed = [
            'software_id' => $values['attested_metadata'],
        ];
        $record = new ClientRecord(
            Uuid::v7(),
            $this->tenant,
            'the-engine',
            [
                'client_name' => $values['metadata'],
                'contacts' => [self::VALUES['beffroi_user']['email']],
                'redirect_uris' => ['https://engine.example.org/callback'],
                'token_endpoint_auth_method' => $secret instanceof SharedClientSecret ? 'client_secret_jwt' : 'client_secret_basic',
                ...($attested ? $signed : []),
            ],
            [
                'scope' => [$values['assigned_metadata']],
            ],
            $secret,
            DrawnSecret::digestOf('the-registration-access-token'),
            $this->now,
            attested: $attested ? $signed : null,
            granted: $granted ? ['resources' => [$values['granted_metadata']]] : null,
        );
        $this->service('test.beffroi.client_store', ClientStoreInterface::class)->save($record);

        return $record;
    }

    private function context(): RequestContext
    {
        return new RequestContext($this->now, self::IP_ADDRESS, self::USER_AGENT);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private function service(string $id, string $class): object
    {
        $service = $this->container->get($id);

        return $service instanceof $class
            ? $service
            : throw new LogicException(sprintf('The test service "%s" is not a %s.', $id, $class));
    }
}
