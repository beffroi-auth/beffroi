<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Group\MembershipAlreadyHeldException;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Application\Identity\IdentityAlreadyLinkedException;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusalReason;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusedException;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Uid\FixedUuidGenerator;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Event\PersonProvisioned;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #781, decision 0002: the person an upstream provider names at a sign-in through it, created at the
 * first one with its provenance and its linked identity, and found again at the next ones by that identity.
 * What the provider writes of a person keeps to its domains and to an address nobody else holds (decision
 * 0029), and no existing account is linked on its own (spike 12, beffroi-auth/beffroi#85).
 */
final class JustInTimeProvisioningTest extends TestCase
{
    private const string PROVIDER = 'https://idp.acme.example/saml';

    private const string SUBJECT = 'a7f3c2e1-alice';

    private const string ADDRESS = 'alice@acme.example';

    private Tenant $tenant;

    private UpstreamProvider $provider;

    private InMemoryUserRepository $users;

    private InMemoryLinkedIdentityRepository $identities;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private WritesAsTheyCome $writes;

    private UserProvisioner $provisioner;

    private IdentityLinker $linker;

    private JustInTimeProvisioning $provisioning;

    private InMemoryGroupMembershipRepository $memberships;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->provider = new UpstreamProvider(self::PROVIDER, [new EmailDomain('acme.example')], ['given_name', 'family_name', 'birthdate']);
        $this->users = new InMemoryUserRepository();
        $this->identities = new InMemoryLinkedIdentityRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-10-22T09:00:00+00:00');
        $this->writes = new WritesAsTheyCome();
        $credentials = new InMemoryCredentialRepository();
        $this->provisioner = new UserProvisioner(
            $this->users,
            $credentials,
            new ActivePassword(new ActiveCredentials($credentials)),
            new NativePasswordHasher(),
            new BreachedPasswordRefusal(BreachedPasswordsOfARecord::holding([])),
            new EnrolmentRefusal(new FederatedDomains(new InMemoryUpstreamProviders())),
            new SymfonyUuidGenerator(),
            $this->clock,
        );
        $this->linker = new IdentityLinker($this->identities, new SymfonyUuidGenerator(), $this->clock);
        $this->memberships = new InMemoryGroupMembershipRepository();
        $this->provisioning = $this->provisioningDrawing(new SymfonyUuidGenerator());
    }

    /**
     * The acceptance of the issue, its first half: one person, named by its address, whose source is the
     * provider and holds what that provider fills and said, its address verified, the provider answering
     * for its domain.
     */
    #[Test]
    public function aFirstSignInCreatesThePersonTheProviderNames(): void
    {
        // When
        $alice = $this->signIn();

        // Then
        static::assertSame($alice, $this->users->find($alice->id));
        static::assertSame($this->tenant, $alice->tenant);
        static::assertSame(self::ADDRESS, $alice->username);
        static::assertSame(self::ADDRESS, $alice->email?->value);
        static::assertTrue($alice->emailVerified);
        static::assertEquals(new Profile(givenName: 'Alice', familyName: 'Liddell'), $alice->profile);
        static::assertEquals(UserSource::upstream(self::PROVIDER, ['email', 'given_name', 'family_name']), $alice->source);
        static::assertEquals($this->clock->now(), $alice->createdAt);
    }

    /**
     * The acceptance of the issue, its second half: one linked identity, which names the person created and
     * holds the snapshot of what the provider said.
     */
    #[Test]
    public function aFirstSignInLinksThePersonToTheSubjectTheProviderGave(): void
    {
        // When
        $alice = $this->signIn();

        // Then
        $identities = $this->identities->of($alice);
        static::assertCount(1, $identities);
        static::assertSame($identities[0], $this->identities->find($this->tenant, self::PROVIDER, self::SUBJECT));
        static::assertSame(
            [
                'given_name' => 'Alice',
                'family_name' => 'Liddell',
                'email' => self::ADDRESS,
            ],
            $identities[0]->claims,
        );
    }

    /**
     * The act of the account: the subject of the person and the name of the provider, and nothing the
     * provider said of them.
     */
    #[Test]
    public function aFirstSignInAnnouncesThePersonCreated(): void
    {
        // Given
        $context = Fixtures::context();

        // When
        $alice = $this->signIn(context: $context);

        // Then
        $announced = $this->events->of(PersonProvisioned::class);
        static::assertCount(1, $announced);
        static::assertSame($this->tenant, $announced[0]->tenant);
        static::assertSame($alice->subject, $announced[0]->person);
        static::assertSame(self::PROVIDER, $announced[0]->provider);
        static::assertEquals($this->clock->now(), $announced[0]->occurredAt);
        static::assertSame($context, $announced[0]->context);
    }

    /**
     * The person, its source and its linked identity are one unit, kept all or none; the refusals come before
     * it, so a refused creation opens none.
     */
    #[Test]
    public function aFirstSignInWritesThePersonAndItsLinkedIdentityAsOneUnit(): void
    {
        // When
        $this->signIn();

        // Then
        static::assertSame(1, $this->writes->units);
    }

    /**
     * The source holds what the provider fills and said: the birthdate it fills and did not say, it does not
     * hold, and a manual description may say it.
     */
    #[Test]
    public function aFirstSignInHoldsWhatTheProviderFillsAndSaid(): void
    {
        // When
        $alice = $this->signIn();

        // Then
        static::assertFalse($alice->source->holds('birthdate'));
    }

    /**
     * The acceptance of the issue: the person found again by its linked identity, and nothing created or
     * announced a second time.
     */
    #[Test]
    public function aSecondSignInCreatesNothing(): void
    {
        // Given
        $alice = $this->signIn();

        // When
        $again = $this->signIn();

        // Then
        static::assertSame($alice, $again);
        static::assertCount(1, $this->identities->of($alice));
        static::assertCount(1, $this->events->of(PersonProvisioned::class));
    }

    /**
     * The acceptance of the issue: what the source holds is written as the provider says it now, and the
     * snapshot is the last thing it said.
     */
    #[Test]
    public function aSecondSignInWritesWhatTheProviderSaysNow(): void
    {
        // Given
        $alice = $this->signIn();
        $this->clock->sleep(3600);

        // When
        $this->signIn('alice.liddell@acme.example', [
            'given_name' => 'Alicia',
            'family_name' => 'Liddell-Hargreaves',
        ]);

        // Then
        static::assertSame('alice.liddell@acme.example', $alice->email?->value);
        static::assertTrue($alice->emailVerified);
        static::assertEquals(new Profile(givenName: 'Alicia', familyName: 'Liddell-Hargreaves'), $alice->profile);
        static::assertEquals($this->clock->now(), $alice->updatedAt);
        static::assertSame(
            [
                'given_name' => 'Alicia',
                'family_name' => 'Liddell-Hargreaves',
                'email' => 'alice.liddell@acme.example',
            ],
            $this->identities->of($alice)[0]->claims,
        );
    }

    /**
     * No source holds a claim for ever: one its provider stops sending, or stops filling because its
     * declaration no longer names it, is released, keeping the value the provider wrote last.
     *
     * @param array<string, string> $claims
     */
    #[Test]
    #[DataProvider('provideClaimsTheProviderLetsGo')]
    public function aClaimTheProviderNoLongerFillsOrSaysIsReleased(UpstreamProvider $provider, array $claims): void
    {
        // Given
        $alice = $this->signIn();

        // When
        $this->signIn(claims: $claims, provider: $provider);

        // Then
        static::assertEquals(UserSource::upstream(self::PROVIDER, ['email', 'family_name']), $alice->source);
        static::assertEquals(new Profile(givenName: 'Alice', familyName: 'Hargreaves'), $alice->profile);
    }

    /**
     * @return iterable<string, array{UpstreamProvider, array<string, string>}>
     */
    public static function provideClaimsTheProviderLetsGo(): iterable
    {
        $declared = new UpstreamProvider(self::PROVIDER, [new EmailDomain('acme.example')], ['given_name', 'family_name', 'birthdate']);
        yield 'a claim it no longer sends' => [
            $declared,
            [
                'family_name' => 'Hargreaves',
            ],
        ];
        yield 'a claim its declaration no longer names' => [
            new UpstreamProvider(self::PROVIDER, [new EmailDomain('acme.example')], ['family_name']),
            [
                'given_name' => 'Alicia',
                'family_name' => 'Hargreaves',
            ],
        ];
    }

    /**
     * A claim released is the person's again: a manual description says it, which it refused while the
     * provider held it.
     */
    #[Test]
    public function aReleasedClaimCanBeDescribedByHand(): void
    {
        // Given
        $alice = $this->signIn();
        $this->signIn(claims: [
            'family_name' => 'Liddell',
        ]);

        // When
        $this->provisioner->setProfile($alice, new Profile(givenName: 'Ali', familyName: 'Liddell'));

        // Then
        static::assertEquals(new Profile(givenName: 'Ali', familyName: 'Liddell'), $alice->profile);
    }

    /**
     * What another source holds is not this provider's to write: a person a console created, and whom an
     * import linked to this provider, keeps what they are, and only the snapshot of the identity moves.
     */
    #[Test]
    public function aSignInThroughAProviderThatIsNotTheSourceOfThePersonRefreshesTheSnapshotOnly(): void
    {
        // Given
        $alice = $this->provisioner->create($this->tenant, 'alice', new EmailAddress('alice@home.example'));
        $this->linker->link($alice, self::PROVIDER, self::SUBJECT);

        // When
        $this->signIn();

        // Then
        static::assertSame('alice@home.example', $alice->email?->value);
        static::assertFalse($alice->emailVerified);
        static::assertEquals(Profile::empty(), $alice->profile);
        static::assertSame(
            [
                'given_name' => 'Alice',
                'family_name' => 'Liddell',
                'email' => self::ADDRESS,
            ],
            $this->identities->of($alice)[0]->claims,
        );
    }

    /**
     * The acceptance of the issue, decision 0029: a provider never creates a person of a domain it does not
     * answer for.
     */
    #[Test]
    public function anAddressOutsideTheDomainsOfTheProviderIsRefused(): void
    {
        // When
        $refusal = $this->failToSignIn('alice@initech.example');

        // Then
        static::assertSame(UpstreamProvisioningRefusalReason::OutsideItsDomains, $refusal->reason);
    }

    /**
     * The acceptance of the issue: no existing account is linked on its own, linking one being spike 12's,
     * after a local re-authentication. The mailbox is matched as its blind index matches it, folded whole,
     * so that a second person never holds the mailbox of a first under another spelling.
     */
    #[Test]
    #[DataProvider('provideAddressesBobHolds')]
    public function anAddressAnotherPersonHoldsIsRefused(string $address): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);

        // When
        $refusal = $this->failToSignIn($address);

        // Then
        static::assertSame(UpstreamProvisioningRefusalReason::AddressHeld, $refusal->reason);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddressesBobHolds(): iterable
    {
        yield 'as it was written' => ['bob@acme.example'];
        yield 'its domain in another case' => ['bob@ACME.example'];
        yield 'its local part in another case' => ['Bob@acme.example'];
    }

    /**
     * The username of the person is its address, so a local person already named by that address holds it
     * too: no existing account is linked on its own, and the same refusal says nothing of which.
     */
    #[Test]
    public function anAddressAnotherPersonIsNamedByIsRefused(): void
    {
        // Given
        $this->provisioner->create($this->tenant, self::ADDRESS);

        // When
        $refusal = $this->failToSignIn(self::ADDRESS);

        // Then
        static::assertSame(UpstreamProvisioningRefusalReason::AddressHeld, $refusal->reason);
    }

    /**
     * The subject drawn for the person is checked before the unit like every other collision, so that
     * nothing raised inside it names anybody.
     */
    #[Test]
    public function aDrawnSubjectAPersonAlreadyHasIsRefused(): void
    {
        // Given
        $drawn = Uuid::fromString('5f0c7a5e-9b0e-4c8e-9a51-0d4b8d3c2a11');
        $this->provisioner->create($this->tenant, 'bob', subject: new Subject($drawn->toRfc4122()));
        $this->provisioning = $this->provisioningDrawing(new FixedUuidGenerator([$drawn]));

        // When
        $refusal = $this->failToSignIn(self::ADDRESS);

        // Then
        static::assertSame(UpstreamProvisioningRefusalReason::DrawnSubjectTaken, $refusal->reason);
    }

    /**
     * Another sign-in links the same subject between the lookup and the unit: the same refusal, which does
     * not say whom the identity is, and nothing of what the linker said carried along.
     */
    #[Test]
    public function anIdentityLinkedMeanwhileIsRefusedWithoutNamingItsPerson(): void
    {
        // Given
        $bob = $this->provisioner->create($this->tenant, 'bob');
        $this->linker->link($bob, self::PROVIDER, self::SUBJECT);
        $this->provisioning = $this->provisioningDrawing(new SymfonyUuidGenerator(), new class implements LinkedIdentityRepositoryInterface {
            public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
            {
                return null;
            }

            public function save(LinkedIdentity $identity): void
            {
            }
        });

        // When
        $refusal = $this->failToSignIn(self::ADDRESS);

        // Then
        static::assertSame(UpstreamProvisioningRefusalReason::IdentityLinkedMeanwhile, $refusal->reason);
        static::assertNull($refusal->getPrevious());
    }

    /**
     * A refusal is raised before the first write: nobody is created, nothing is linked, nothing announced.
     *
     * @param array<string, string> $claims
     */
    #[Test]
    #[DataProvider('provideRefusedFirstSignIns')]
    public function aRefusedFirstSignInCreatesNobody(string $address, array $claims): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);
        $this->provisioner->create($this->tenant, 'carol@acme.example');

        // When
        try {
            $this->signIn($address, $claims);
        } catch (InvalidArgumentException|UpstreamProvisioningRefusedException) {
        }

        // Then
        static::assertNull($this->identities->find($this->tenant, self::PROVIDER, self::SUBJECT));
        static::assertSame([], $this->events->events);
        static::assertSame(0, $this->writes->units);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideRefusedFirstSignIns(): iterable
    {
        yield 'outside the domains of the provider' => ['alice@initech.example', []];
        yield 'held by another person' => ['bob@acme.example', []];
        yield 'the username of another person' => ['carol@acme.example', []];
        yield 'a claim the profile refuses' => [
            self::ADDRESS,
            [
                'given_name' => 'Alice',
                'family_name' => 'Liddell',
                'birthdate' => 'the first of May',
            ],
        ];
    }

    /**
     * Refused before the lookup: an empty subject matches no row, and a person created for it would be left
     * without the linked identity that refuses it.
     */
    #[Test]
    public function anEmptySubjectIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A person an upstream provider names carries the subject it gave.');

        // When
        $this->provisioning->personNamedBy($this->tenant, $this->provider, '', new EmailAddress(self::ADDRESS), [], Fixtures::context());
    }

    /**
     * Decision 0029 at the next sign-ins too: what the provider writes of a person keeps to its domains and
     * to an address nobody else holds, and a refusal writes nothing, the snapshot included.
     */
    #[Test]
    #[DataProvider('provideAddressesASecondSignInCannotWrite')]
    public function aSecondSignInThatWouldWriteAnAddressTheProviderCannotWriteIsRefused(string $address, UpstreamProvisioningRefusalReason $reason): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);
        $this->provisioner->create($this->tenant, 'carol@acme.example');
        $this->signIn();

        // When
        $refusal = $this->failToSignIn($address);

        // Then
        static::assertSame($reason, $refusal->reason);
    }

    /**
     * @return iterable<string, array{string, UpstreamProvisioningRefusalReason}>
     */
    public static function provideAddressesASecondSignInCannotWrite(): iterable
    {
        yield 'outside the domains of the provider' => ['alice@initech.example', UpstreamProvisioningRefusalReason::OutsideItsDomains];
        yield 'held by another person' => ['bob@acme.example', UpstreamProvisioningRefusalReason::AddressHeld];
        yield 'held by another person under another spelling' => ['Bob@acme.example', UpstreamProvisioningRefusalReason::AddressHeld];
        // the username follows the address, so a new address another person is named by is refused too
        yield 'the username of another person' => ['carol@acme.example', UpstreamProvisioningRefusalReason::AddressHeld];
    }

    /**
     * Both refusals come before the unit, the contract of the port: the one the first sign-in spent is the
     * only one, and the person, its source and its snapshot are what they were.
     */
    #[Test]
    #[DataProvider('provideRefusedSecondSignIns')]
    public function aRefusedSecondSignInWritesNothing(string $address): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);
        $this->provisioner->create($this->tenant, 'carol@acme.example');
        $alice = $this->signIn();

        // When
        try {
            $this->signIn($address, [
                'given_name' => 'Alicia',
            ]);
        } catch (UpstreamProvisioningRefusedException) {
        }

        // Then
        static::assertSame(1, $this->writes->units);
        static::assertSame(self::ADDRESS, $alice->email?->value);
        static::assertSame(self::ADDRESS, $alice->username);
        static::assertEquals(new Profile(givenName: 'Alice', familyName: 'Liddell'), $alice->profile);
        static::assertEquals(UserSource::upstream(self::PROVIDER, ['email', 'given_name', 'family_name']), $alice->source);
        static::assertSame(self::ADDRESS, $this->identities->of($alice)[0]->claims['email']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedSecondSignIns(): iterable
    {
        yield 'outside the domains of the provider' => ['alice@initech.example'];
        yield 'held by another person' => ['bob@acme.example'];
        yield 'the username of another person' => ['carol@acme.example'];
    }

    /**
     * beffroi/saml S-56: a person an administrator disabled is refused, whatever the provider says of them now.
     */
    #[Test]
    public function aDisabledPersonIsRefused(): void
    {
        // Given
        $this->signIn()->disable($this->clock->now());

        // When
        $refusal = $this->failToSignIn(self::ADDRESS);

        // Then
        static::assertSame(UpstreamProvisioningRefusalReason::PersonDisabled, $refusal->reason);
    }

    /**
     * beffroi/saml S-56: the refusal of a disabled person comes before the unit, so that a person disabled follows the
     * provider no more: its address, its name, its profile and its snapshot are what they were.
     */
    #[Test]
    public function aDisabledPersonIsWrittenNothing(): void
    {
        // Given
        $alice = $this->signIn();
        $alice->disable($this->clock->now());

        // When
        try {
            $this->signIn('alicia@acme.example', [
                'given_name' => 'Alicia',
            ]);
        } catch (UpstreamProvisioningRefusedException) {
        }

        // Then
        static::assertSame(1, $this->writes->units);
        static::assertSame(self::ADDRESS, $alice->email?->value);
        static::assertSame(self::ADDRESS, $alice->username);
        static::assertEquals(new Profile(givenName: 'Alice', familyName: 'Liddell'), $alice->profile);
        static::assertSame(self::ADDRESS, $this->identities->of($alice)[0]->claims['email']);
    }

    /**
     * beffroi/saml S-56: a disabled person the console linked to the provider, which is not their source, is refused
     * before the snapshot of the identity moves.
     */
    #[Test]
    public function aDisabledPersonTheConsoleLinkedKeepsTheirSnapshot(): void
    {
        // Given
        $alice = $this->provisioner->create($this->tenant, 'alice', new EmailAddress('alice@home.example'));
        $this->linker->link($alice, self::PROVIDER, self::SUBJECT);
        $alice->disable($this->clock->now());

        // When
        try {
            $this->signIn();
        } catch (UpstreamProvisioningRefusedException) {
        }

        // Then
        static::assertSame([0, []], [$this->writes->units, $this->identities->of($alice)[0]->claims]);
    }

    /**
     * The username follows the address: a provider that sends another one has the person renamed to it in
     * the same unit, so that the pages a person reads call them by the address they have.
     */
    #[Test]
    public function aNewAddressRenamesThePerson(): void
    {
        // Given
        $alice = $this->signIn();

        // When
        $this->signIn('alice.liddell@acme.example');

        // Then
        static::assertSame('alice.liddell@acme.example', $alice->username);
        static::assertSame($alice, $this->users->findByUsername($this->tenant, 'alice.liddell@acme.example'));
    }

    /**
     * The old address is nobody's any more, as a mailbox or as a username: the next person who holds it is
     * created, where a username that followed no change of address would have refused them for ever.
     */
    #[Test]
    public function theOldAddressOfARenamedPersonIsFreedForTheNextOne(): void
    {
        // Given
        $alice = $this->signIn();
        $this->signIn('alice.liddell@acme.example');

        // When
        $next = $this->signIn(subject: 'b81d4e02-the-next-alice');

        // Then
        static::assertFalse($next->id->equals($alice->id));
        static::assertSame(self::ADDRESS, $next->username);
    }

    /**
     * The person holds their own address, so somebody who shares it with them, which nothing forbids two
     * local persons, is not a reason to refuse them their own sign-in. Asked only of an address that changed.
     */
    #[Test]
    public function anAddressThePersonAlreadyHoldsIsNotAskedAgain(): void
    {
        // Given
        $alice = $this->signIn();
        $this->provisioner->create($this->tenant, 'alice-at-home', new EmailAddress(self::ADDRESS));

        // When
        $again = $this->signIn();

        // Then
        static::assertSame($alice, $again);
    }

    /**
     * The mailbox the person holds, spelt in another case, is still theirs, and it is not asked again: a
     * local person who shares it with them, which nothing forbids, is not a reason to refuse them.
     */
    #[Test]
    #[DataProvider('provideSpellingsOfAlicesMailbox')]
    public function theMailboxThePersonHoldsSpeltAnotherWayIsWritten(string $address): void
    {
        // Given
        $alice = $this->signIn();
        $this->provisioner->create($this->tenant, 'alice-at-home', new EmailAddress(self::ADDRESS));

        // When
        $this->signIn($address);

        // Then
        static::assertSame($address, $alice->email?->value);
        static::assertSame($address, $alice->username);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpellingsOfAlicesMailbox(): iterable
    {
        yield 'its domain in another case' => ['alice@ACME.example'];
        yield 'its local part in another case' => ['Alice@acme.example'];
    }

    /**
     * beffroi/saml S-56, issue #782: the groups the provider asserts are written in the unit of the person, so that
     * the person and its memberships are kept together or not at all.
     */
    #[Test]
    public function theGroupsTheProviderAssertsAreWrittenInTheUnitOfThePerson(): void
    {
        // Given
        $memberships = new class($this->memberships, $this->writes) implements GroupMembershipRepositoryInterface {
            /**
             * @var list<bool> whether each membership was written inside a unit
             */
            public private(set) array $inside = [];

            public function __construct(
                private readonly GroupMembershipRepositoryInterface $stored,
                private readonly WritesAsTheyCome $writes,
            ) {
            }

            public function save(GroupMembership $membership): void
            {
                $this->inside[] = $this->writes->open;
                $this->stored->save($membership);
            }

            public function remove(GroupMembership $membership): void
            {
                $this->stored->remove($membership);
            }
        };
        $provisioning = $this->provisioningDrawing(new SymfonyUuidGenerator(), memberships: $memberships);

        // When
        $alice = $provisioning->personNamedBy(
            $this->tenant,
            $this->provider,
            self::SUBJECT,
            new EmailAddress(self::ADDRESS),
            [],
            Fixtures::context(),
            null,
            $this->members(),
            ['staff'],
        );

        // Then
        static::assertSame([true], $memberships->inside);
        static::assertSame(1, $this->writes->units);
        static::assertSame('Staff', $this->memberships->of($alice)[0]->group->name);
    }

    /**
     * beffroi/saml S-56: a person whose memberships could not be written is not announced, the event coming once all
     * of the unit is kept.
     */
    #[Test]
    public function aPersonWhoseGroupsFailToBeWrittenIsNotAnnounced(): void
    {
        // Given
        $memberships = new class implements GroupMembershipRepositoryInterface {
            public function save(GroupMembership $membership): void
            {
                throw new RuntimeException('The membership could not be written.');
            }

            public function remove(GroupMembership $membership): void
            {
            }
        };
        $provisioning = $this->provisioningDrawing(new SymfonyUuidGenerator(), memberships: $memberships);

        // When
        try {
            $provisioning->personNamedBy(
                $this->tenant,
                $this->provider,
                self::SUBJECT,
                new EmailAddress(self::ADDRESS),
                [],
                Fixtures::context(),
                null,
                $this->members(),
                ['staff'],
            );
        } catch (RuntimeException) {
        }

        // Then
        static::assertSame([], $this->events->of(PersonProvisioned::class));
    }

    /**
     * beffroi/saml S-45, S-56: a telephone number the provider says is written unverified, being never verified by
     * being filled, and held by the source of the person as a claim it fills.
     */
    #[Test]
    public function theTelephoneNumberTheProviderSaysIsWrittenUnverifiedAndHeld(): void
    {
        // When
        $alice = $this->provisioning->personNamedBy(
            $this->tenant,
            $this->provider,
            self::SUBJECT,
            new EmailAddress(self::ADDRESS),
            [],
            Fixtures::context(),
            '+33 1 23 45 67 89',
        );

        // Then
        static::assertSame(['+33 1 23 45 67 89', false, true], [$alice->phoneNumber, $alice->phoneNumberVerified, $alice->source->holds('phone_number')]);
    }

    /**
     * beffroi/saml S-56: a telephone number the provider no longer says is released to a manual description, with the
     * value it wrote last, as a claim of the profile is.
     */
    #[Test]
    public function aTelephoneNumberTheProviderNoLongerSaysIsReleased(): void
    {
        // Given
        $this->provisioning->personNamedBy(
            $this->tenant,
            $this->provider,
            self::SUBJECT,
            new EmailAddress(self::ADDRESS),
            [],
            Fixtures::context(),
            '+33 1 23 45 67 89',
        );

        // When
        $alice = $this->provisioning->personNamedBy($this->tenant, $this->provider, self::SUBJECT, new EmailAddress(self::ADDRESS), [], Fixtures::context());

        // Then
        static::assertSame(['+33 1 23 45 67 89', false], [$alice->phoneNumber, $alice->source->holds('phone_number')]);
    }

    /**
     * beffroi/saml S-56: a first sign-in that loses a race at the store, the person or its linked identity written by
     * another sign-in between the checks and the unit, is refused as the collision the linker sees is, without what
     * the store said of whom.
     */
    #[Test]
    #[DataProvider('provideRacesLostAtTheStore')]
    public function aFirstSignInThatLosesARaceAtTheStoreIsRefused(bool $atTheLinkedIdentity): void
    {
        // Given
        $violation = new RuntimeException('The unique constraint refused the row.');
        $identities = new readonly class($this->identities, $atTheLinkedIdentity, $violation) implements LinkedIdentityRepositoryInterface {
            public function __construct(
                private LinkedIdentityRepositoryInterface $stored,
                private bool $refuses,
                private RuntimeException $violation,
            ) {
            }

            public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
            {
                return $this->stored->find($tenant, $provider, $subject);
            }

            public function save(LinkedIdentity $identity): void
            {
                if ($this->refuses) {
                    throw IdentityAlreadyLinkedException::linkedMeanwhile($this->violation);
                }
                $this->stored->save($identity);
            }
        };
        $users = new readonly class($this->users, ! $atTheLinkedIdentity, $violation) implements UserRepositoryInterface {
            public function __construct(
                private InMemoryUserRepository $stored,
                private bool $refuses,
                private RuntimeException $violation,
            ) {
            }

            public function find(Uuid $id): ?User
            {
                return $this->stored->find($id);
            }

            public function findBySubject(Tenant $tenant, Subject $subject): ?User
            {
                return $this->stored->findBySubject($tenant, $subject);
            }

            public function findByUsername(Tenant $tenant, string $username): ?User
            {
                return $this->stored->findByUsername($tenant, $username);
            }

            public function findAllByEmail(Tenant $tenant, EmailAddress $email): array
            {
                return $this->stored->findAllByEmail($tenant, $email);
            }

            public function save(User $user): void
            {
                if ($this->refuses) {
                    throw UserAlreadyExistsException::writtenMeanwhile($this->violation);
                }
                $this->stored->save($user);
            }
        };
        $this->linker = new IdentityLinker($identities, new SymfonyUuidGenerator(), $this->clock);
        $provisioning = $this->provisioningDrawing(new SymfonyUuidGenerator(), $identities, users: $users);

        // When
        try {
            $provisioning->personNamedBy($this->tenant, $this->provider, self::SUBJECT, new EmailAddress(self::ADDRESS), [], Fixtures::context());
            static::fail('The sign-in was not refused.');
        } catch (UpstreamProvisioningRefusedException $refusal) {
            // Then
            static::assertSame([UpstreamProvisioningRefusalReason::IdentityLinkedMeanwhile, null], [$refusal->reason, $refusal->getPrevious()]);
        }
    }

    /**
     * beffroi/saml S-56: a sign-in of a person that loses a race on a membership, another sign-in of the same person
     * having given it the same group meanwhile, is refused, the store refusing the second membership.
     */
    #[Test]
    public function aSignInThatLosesARaceOnAMembershipIsRefused(): void
    {
        // Given
        $this->provisioning->personNamedBy($this->tenant, $this->provider, self::SUBJECT, new EmailAddress(self::ADDRESS), [], Fixtures::context());
        $memberships = new class implements GroupMembershipRepositoryInterface {
            public function save(GroupMembership $membership): void
            {
                throw MembershipAlreadyHeldException::writtenMeanwhile(new RuntimeException('The unique constraint refused the row.'));
            }

            public function remove(GroupMembership $membership): void
            {
            }
        };
        $provisioning = $this->provisioningDrawing(new SymfonyUuidGenerator(), memberships: $memberships);

        // When
        try {
            $provisioning->personNamedBy(
                $this->tenant,
                $this->provider,
                self::SUBJECT,
                new EmailAddress(self::ADDRESS),
                [],
                Fixtures::context(),
                null,
                $this->members(),
                ['staff'],
            );
            static::fail('The sign-in was not refused.');
        } catch (UpstreamProvisioningRefusedException $refusal) {
            // Then
            static::assertSame([UpstreamProvisioningRefusalReason::MembershipWrittenMeanwhile, null], [$refusal->reason, $refusal->getPrevious()]);
        }
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideRacesLostAtTheStore(): iterable
    {
        yield 'the linked identity' => [true];
        yield 'the person' => [false];
    }

    /**
     * The use case on the adapters of the suite, the subject of a person it creates drawn from those
     * identifiers, and what it looks a linked identity up in, when a test says it.
     */
    private function provisioningDrawing(
        UuidGeneratorInterface $uuids,
        ?LinkedIdentityRepositoryInterface $identities = null,
        ?GroupMembershipRepositoryInterface $memberships = null,
        ?UserRepositoryInterface $users = null,
    ): JustInTimeProvisioning {
        return new JustInTimeProvisioning(
            $identities ?? $this->identities,
            $users ?? $this->users,
            $this->provisioner,
            $this->linker,
            $this->events,
            $this->clock,
            $this->writes,
            $uuids,
            new UpstreamMemberships($this->memberships, $memberships ?? $this->memberships, new SymfonyUuidGenerator(), $this->clock),
        );
    }

    /**
     * The groups of the tenant the provider of the suite asserts, by the values it sends.
     */
    private function members(): GroupMapping
    {
        return new GroupMapping([
            'staff' => new Group(Uuid::v7(), $this->tenant, 'Staff', GroupSource::Local, Fixtures::now()),
        ]);
    }

    /**
     * The refusal a sign-in through the provider of the suite raised, which a test reads the reason of, the
     * message being the same whatever it is.
     */
    private function failToSignIn(string $address): UpstreamProvisioningRefusedException
    {
        try {
            $this->signIn($address);
        } catch (UpstreamProvisioningRefusedException $refusal) {
            static::assertSame('The person an upstream provider named is not one this provider creates or writes.', $refusal->getMessage());

            return $refusal;
        }

        static::fail('The sign-in was not refused.');
    }

    /**
     * @param array<string, string> $claims
     */
    private function signIn(
        string $address = self::ADDRESS,
        array $claims = [
            'given_name' => 'Alice',
            'family_name' => 'Liddell',
        ],
        ?RequestContext $context = null,
        ?UpstreamProvider $provider = null,
        string $subject = self::SUBJECT,
    ): User {
        return $this->provisioning->personNamedBy(
            $this->tenant,
            $provider ?? $this->provider,
            $subject,
            new EmailAddress($address),
            $claims,
            $context ?? Fixtures::context(),
        );
    }
}
