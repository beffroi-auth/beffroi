<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

use DateTimeImmutable;
use function array_values;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
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

/**
 * One row of every family of columns the classification declares sealed, written with the values declared
 * here and nowhere else.
 *
 * It is shared rather than written per test because the two uses have to agree. A test that reads one table
 * asserts that its own values are not in its own row; the test that reads the whole database asserts that no
 * value the suite ever wrote is anywhere in the file. Written twice, the second list drifts from the first
 * and the dump passes for the wrong reason: it searched for values nothing had written.
 *
 * What it does not do is drive the application. These are the rows as the domain writes them, which is what
 * says the types seal; what a journey leaves behind is the business of the walk against the stack.
 */
final readonly class SealedRows
{
    /**
     * The shortest a declared value may be, in bytes.
     *
     * A sealed column holds bytes that are indistinguishable from random, so a short value is found in one
     * by chance rather than by leaking. Over a database file of some hundreds of kilobytes, three bytes turn
     * up about once every twelve runs and four about once in ten thousand, which is a test that fails for
     * nothing; five bytes turn up about once in two million, which is never. Hence the floor, and hence a
     * fixture value that reads a little longer than life: `family_name` is King-Noel, which Ada's was.
     */
    public const int SHORTEST_VALUE = 5;

    /**
     * One value each sealed column holds, by the table and the column it lands in.
     *
     * One value and not the whole of what the column holds: `claims` is a JSON document, `created_from` is a
     * whole request context, and `parameters` is a pushed request. What those carry besides is declared in
     * {@see ALSO_WRITTEN}. What this map is for is the other guarantee, that every column the classification
     * declares sealed has a value written into it, which is checked per table by the tests that read one.
     *
     * @var array<string, array<string, string>>
     */
    public const array VALUES = [
        'beffroi_user' => [
            'username' => 'ada-lovelace',
            'email' => 'ada@example.org',
            'phone_number' => '+441632960541',
            'address' => '12 Grand Rue, Saint-Germain',
            // The thirteen claims of a profile share one column and one type, so one of them exercises the
            // path all thirteen take; the other twelve left with the columns they had (issue #440).
            'profile' => 'Augusta Ada King-Noel',
            // the upstream provider that created her, the one her linked identity names (decision 0002)
            'source' => 'login.acme-federation.example',
        ],
        'beffroi_linked_identity' => [
            'provider' => 'login.acme-federation.example',
            'subject' => '110169484474386276334',
            'claims' => 'ada@example.org',
        ],
        'beffroi_passkey_credential' => [
            'name' => 'The key Ada keeps on her keyring',
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
        // the provenance of one act of the journal (issue #454), which is what the request carried of a
        // person and what a dump must not give away either
        'beffroi_journal' => [
            'context' => self::IP_ADDRESS,
        ],
        // the archive a person asked for (issue #453): the one column in which everything the other
        // families seal stands in clear at once, so what is searched for in the dump is the document and
        // the two values of this fixture it holds
        'beffroi_personal_archive' => [
            'content' => '{"profile":[{"name":"Augusta Ada King-Noel","email":"ada@example.org"}]}',
        ],
        // what a claim of a person used to say, and what they made it say (issue #482): two values of
        // that person and the provenance of the request that changed them
        'beffroi_claim_change' => [
            'was' => 'Ada-of-the-notes',
            'became' => 'the-enchantress-of-numbers',
            'context' => self::USER_AGENT,
        ],
        // what a client was given of a person at one act (issue #590): the scopes it may now obtain, what
        // it had asked for by name and what it was given beyond them, which a dump of one row per act must
        // not give away either
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
        // the metadata a service provider of the tenant published (beffroi/saml, issue #729), whose
        // md:ContactPerson names the person who answers for it
        'beffroi_saml_service_provider' => [
            'document' => 'grace.hopper@sp.example.org',
        ],
        // the metadata an upstream identity provider of the tenant published (beffroi/saml, issue #779), whose
        // md:ContactPerson names the person who answers for it
        'beffroi_saml_upstream_identity_provider' => [
            'document' => 'katherine.johnson@idp.example.org',
        ],
        'beffroi_client' => [
            'metadata' => 'The Difference Engine',
            'assigned_metadata' => 'urn:example:scope:assigned-by-the-policy',
            'secret' => 'a-shared-secret-this-provider-handed-over',
        ],
    ];

    /**
     * What the fixture writes inside a column that holds more than one value, which a dump must not hold
     * either.
     *
     * @var list<string>
     */
    public const array ALSO_WRITTEN = [
        'Augusta Ada King-Noel',
        'ada@example.org',
        self::IP_ADDRESS,
        self::USER_AGENT,
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZGEtc3ViamVjdCJ9.sig',
    ];

    /**
     * The provenance every session, device request and backchannel request of the suite is written from.
     *
     * Public because {@see \Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase::context()} builds
     * the context of the whole suite from these two, so that a row written by any test carries a value the
     * search of the dump knows about by construction and not by coincidence.
     */
    public const string IP_ADDRESS = '203.0.113.10';

    public const string USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0';

    /**
     * The snapshot the upstream provider returned, which is what the claims column holds whole.
     */
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
     * Every value the fixture writes into a sealed column, each once.
     *
     * @return list<string>
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

    /**
     * One row of every family, in the order the foreign keys need: the user first, the client of the
     * configuration being there already.
     */
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
        $this->client(new SharedClientSecret(self::VALUES['beffroi_client']['secret']));
        $this->act($user);
        $this->archive($user);
        $this->change($user);
        $this->disclosure($user, $client);
        $this->serviceProviderMetadata();
        $this->identityProviderMetadata();
    }

    /**
     * The metadata document accepted for a service provider (beffroi/saml, issue #729), sealed in a scope of its
     * own: the one a SimpleSAMLphp service provider published, with the technical contact a deployment of it
     * declares.
     */
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

    /**
     * The metadata document accepted for an upstream identity provider (beffroi/saml, issue #779), sealed in a scope
     * of its own: the one the SimpleSAMLphp identity provider of the judge publishes, with the technical contact a
     * deployment of it declares.
     */
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

    /**
     * What one client was given of a person at one act (issue #590), sealed in a scope of its own: one row
     * per act is what an application obtained of somebody day by day, which a dump must not read.
     */
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

    /**
     * One act of the journal (issue #454), whose provenance is sealed in a scope of its own: it is what
     * the request carried of a person, which a dump must not give away either.
     */
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

    /**
     * The archive a person asked for and that was built (issue #453), whose document is sealed in a scope
     * of its own: it is the one file in which everything this provider knows of somebody stands in clear
     * at once, so a dump that gave it away would give away all of it.
     */
    public function archive(User $user): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), $user, $this->now);
        $archive->fill(self::VALUES['beffroi_personal_archive']['content'], $this->now);
        $this->service('test.beffroi.archives', PersonalArchiveRepositoryInterface::class)->save($archive);

        return $archive;
    }

    /**
     * One change of a claim of a person (issue #482), whose two values are sealed in a scope of their own:
     * what that person used to be called is a personal datum as much as what they are called now.
     */
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
     * A client of the tenant, with the secret it was given or none.
     *
     * None by default, because a sealed column that accepts a null holds a null and not the envelope of an
     * empty value, and a test says so. {@see all()} gives it one, the dump having to be searched for it.
     */
    public function client(?ClientSecretInterface $secret = null): ClientRecord
    {
        $values = self::VALUES['beffroi_client'];
        $record = new ClientRecord(
            Uuid::v7(),
            $this->tenant,
            'the-engine',
            [
                'client_name' => $values['metadata'],
                'contacts' => [self::VALUES['beffroi_user']['email']],
                'redirect_uris' => ['https://engine.example.org/callback'],
                'token_endpoint_auth_method' => $secret instanceof SharedClientSecret ? 'client_secret_jwt' : 'client_secret_basic',
            ],
            [
                'scope' => [$values['assigned_metadata']],
            ],
            $secret,
            DrawnSecret::digestOf('the-registration-access-token'),
            $this->now,
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
