<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Upstream;

use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use Beffroi\Saml\Application\Upstream\AssertionConsumerService;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\Upstream\GroupMapping;
use Beffroi\Saml\Domain\Upstream\ProfileAttribute;
use Beffroi\Saml\Domain\Upstream\UpstreamAssertion;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;
use Beffroi\Saml\Port\ResponseReceiverInterface;
use Beffroi\Saml\Tests\Fixture\DeclaredUpstreamProviders;
use Beffroi\Saml\Tests\Fixture\RecordingResponseReceiver;
use DateTimeImmutable;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-53 to S-57, section 6.14 steps 2 to 7: what the assertion consumer service makes of an assertion the
 * model accepted, the provider the request went to, an assertion in clear from a provider asked to encrypt, the
 * subject, the address, the claims, the telephone number, the groups and the methods, then the person, the core's
 * first sign-in on the adapters of its suite.
 */
final class AssertionConsumerServiceTest extends TestCase
{
    private const string PROVIDER = 'https://idp.acme.example/saml';

    private const string REQUEST = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    private const string SUBJECT_ATTRIBUTE = 'http://schemas.microsoft.com/identity/claims/objectidentifier';

    private Tenant $tenant;

    private MockClock $clock;

    private InMemoryUserRepository $users;

    private InMemoryGroupRepository $groups;

    private InMemoryGroupMembershipRepository $memberships;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-10-23T09:00:00+00:00');
        $this->users = new InMemoryUserRepository();
        $this->groups = new InMemoryGroupRepository();
        $this->memberships = new InMemoryGroupMembershipRepository();
    }

    /**
     * S-53: a provider the tenant no longer declares, since the request went to it, takes nothing, and the response is
     * not read.
     */
    #[Test]
    public function aProviderTheTenantNoLongerDeclaresIsRefused(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(), []);

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The identity provider the request went to is none this tenant declares (spec/saml.md S-53).');

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * S-53: the response is read for the provider the request went to and for that request, from the fields of the
     * form as they came.
     */
    #[Test]
    public function theResponseIsReadForTheProviderAndTheRequestRemembered(): void
    {
        // Given
        $receiver = new RecordingResponseReceiver(self::verified());
        $consumer = $this->consumer(self::verified(), [self::provider()], $receiver);

        // When
        $consumer->receive($this->tenant, ['SAMLResponse' => 'PHNhbWxwOlJlc3BvbnNlLz4='], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame([[self::PROVIDER, ['SAMLResponse' => 'PHNhbWxwOlJlc3BvbnNlLz4='], self::REQUEST]], $receiver->received);
    }

    /**
     * S-54, S-67, M-18: a provider asked to encrypt has its assertion in clear refused, whatever signatures held.
     */
    #[Test]
    public function aClearAssertionOfAProviderAskedToEncryptIsRefused(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(encrypted: false), [self::provider(requireEncryptedAssertions: true)]);

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The identity provider is required to encrypt its assertions and sent one in clear (spec/saml.md S-54, S-67).');

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * S-54: an encrypted assertion of a provider asked to encrypt, and either of a provider that is not, are taken.
     */
    #[Test]
    #[DataProvider('provideAssertionsTaken')]
    public function anAssertionThatArrivedAsItHadToIsTaken(bool $required, bool $encrypted): void
    {
        // Given
        $consumer = $this->consumer(self::verified(encrypted: $encrypted), [self::provider(requireEncryptedAssertions: $required)]);

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame('a7f3c2e1-persistent-alice', $assertion->subject);
    }

    /**
     * @return iterable<string, array{bool, bool}>
     */
    public static function provideAssertionsTaken(): iterable
    {
        yield 'encrypted, as required' => [true, true];
        yield 'in clear, not required' => [false, false];
        yield 'encrypted, not required' => [false, true];
    }

    /**
     * S-55, Core §8.3.7: the subject of a persistent NameID is its value, whatever attribute the declaration names.
     */
    #[Test]
    public function theSubjectOfAPersistentNameIdIsItsValue(): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(attributes: ['mail' => ['alice@acme.example'], self::SUBJECT_ATTRIBUTE => ['b2c1a8f0-object']]),
            [self::provider(subjectAttribute: self::SUBJECT_ATTRIBUTE)],
        );

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame('a7f3c2e1-persistent-alice', $assertion->subject);
    }

    /**
     * S-55: a NameID of another format names the person by the one value of the attribute the declaration names, as
     * Entra names one by its object identifier.
     */
    #[Test]
    public function theSubjectOfAnotherNameIdIsTheAttributeTheDeclarationNames(): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(nameId: 'alice@acme.example', persistent: false, attributes: [
                'mail' => ['alice@acme.example'],
                self::SUBJECT_ATTRIBUTE => ['b2c1a8f0-object'],
            ]),
            [self::provider(subjectAttribute: self::SUBJECT_ATTRIBUTE)],
        );

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame('b2c1a8f0-object', $assertion->subject);
    }

    /**
     * S-55: a NameID that is not persistent and an attribute of the subject that holds not one value name nobody.
     *
     * @param list<string> $values
     */
    #[Test]
    #[DataProvider('provideAttributesOfTheSubjectThatNameNobody')]
    public function anAttributeOfTheSubjectThatHoldsNotOneValueIsRefused(array $values): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(nameId: 'alice@acme.example', persistent: false, attributes: ['mail' => ['alice@acme.example'], self::SUBJECT_ATTRIBUTE => $values]),
            [self::provider(subjectAttribute: self::SUBJECT_ATTRIBUTE)],
        );

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The attribute of the subject holds not one value (spec/saml.md S-55).');

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function provideAttributesOfTheSubjectThatNameNobody(): iterable
    {
        yield 'absent' => [[]];
        yield 'two values' => [['b2c1a8f0-object', 'c3d2b9e1-object']];
        yield 'an empty value' => [['']];
    }

    /**
     * S-55: a NameID that is not persistent from a provider whose declaration names no attribute of the subject, the
     * address never standing for one, names nobody.
     */
    #[Test]
    public function aNameIdThatIsNotPersistentWithoutAnAttributeOfTheSubjectIsRefused(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(nameId: 'alice@acme.example', persistent: false), [self::provider()]);

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The NameID is not persistent and the declaration names no attribute of the subject (spec/saml.md S-55).');

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * S-55, decision 0029: a subject that is the address of the person, which a mailbox given again to another would
     * hand them, is refused whatever names it and however it is spelt.
     *
     * @param array<string, list<string>> $attributes
     */
    #[Test]
    #[DataProvider('provideSubjectsThatAreTheAddress')]
    public function aSubjectThatIsTheAddressIsRefused(string $nameId, bool $persistent, array $attributes): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(nameId: $nameId, persistent: $persistent, attributes: ['mail' => ['alice@acme.example'], ...$attributes]),
            [self::provider(subjectAttribute: self::SUBJECT_ATTRIBUTE)],
        );

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The subject is the address of the person, which is given again to another (spec/saml.md S-55).');

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * @return iterable<string, array{string, bool, array<string, list<string>>}>
     */
    public static function provideSubjectsThatAreTheAddress(): iterable
    {
        yield 'a persistent NameID' => ['alice@acme.example', true, []];
        yield 'a persistent NameID in capitals' => ['Alice@ACME.example', true, []];
        yield 'the attribute of the subject' => ['transient-4f2a', false, [self::SUBJECT_ATTRIBUTE => ['ALICE@acme.example']]];
    }

    /**
     * S-55: an address in a U-label the subject names is the same mailbox as the address in its A-label, and refused.
     */
    #[Test]
    public function aSubjectThatIsTheAddressInAULabelIsRefused(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(nameId: 'alice@Bücher.example', attributes: ['mail' => [
            'alice@xn--bcher-kva.example',
        ]]), [self::provider()]);

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The subject is the address of the person, which is given again to another (spec/saml.md S-55).');

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * S-55: a persistent NameID that holds an "@" and is another address than the person's is a subject as any other.
     */
    #[Test]
    public function aSubjectThatIsAnotherAddressIsTaken(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(nameId: 'alice-7f3c@idp.acme.example'), [self::provider()]);

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame('alice-7f3c@idp.acme.example', $assertion->subject);
    }

    /**
     * S-53, M-16: the refusal of an address the core refuses carries no exception of the core, whose message holds
     * the address, since what the firewall logs is the whole chain.
     */
    #[Test]
    public function theRefusalOfAnAddressCarriesNoValue(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(attributes: ['mail' => ['al ice@acme.example']]), [self::provider()]);

        // When
        try {
            $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
            static::fail('The address was not refused.');
        } catch (AssertionRefusedException $refusal) {
            // Then
            static::assertNull($refusal->getPrevious());
        }
    }

    /**
     * S-57, SAML Core §2.7.2: the SessionNotOnOrAfter of the authentication statement is handed on, the bound of the
     * session the login opens.
     */
    #[Test]
    public function theSessionNotOnOrAfterIsHandedOn(): void
    {
        // Given
        $bound = new DateTimeImmutable('2026-10-23T17:00:00+00:00');
        $consumer = $this->consumer(self::verified(sessionNotOnOrAfter: $bound), [self::provider()]);

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame($bound, $assertion->sessionNotOnOrAfter);
    }

    /**
     * S-56, S-60, UTS #46: the address is written with its domain as its A-label in lower case, which the core's
     * EmailAddress reads, the local part as the provider sent it.
     */
    #[Test]
    #[DataProvider('provideSpellingsOfAnAddress')]
    public function theAddressIsWrittenWithItsDomainAsItsALabel(string $sent, string $written): void
    {
        // Given
        $consumer = $this->consumer(self::verified(attributes: ['mail' => [$sent]]), [self::provider()]);

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertEquals(new EmailAddress($written), $assertion->email);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSpellingsOfAnAddress(): iterable
    {
        yield 'in ASCII' => ['alice@acme.example', 'alice@acme.example'];
        yield 'its domain in capitals' => ['Alice@ACME.example', 'Alice@acme.example'];
        yield 'its domain in a U-label' => ['alice@Bücher.example', 'alice@xn--bcher-kva.example'];
    }

    /**
     * S-56: an attribute of the e-mail that holds not one value, and an address whose domain the rule refuses, are
     * refused.
     *
     * @param list<string> $values
     */
    #[Test]
    #[DataProvider('provideAddressesRefused')]
    public function anAddressThatIsNotOneIsRefused(array $values, string $message): void
    {
        // Given
        $consumer = $this->consumer(self::verified(attributes: ['mail' => $values]), [self::provider()]);

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function provideAddressesRefused(): iterable
    {
        yield 'absent' => [[], 'The attribute of the e-mail holds not one value (spec/saml.md S-56).'];
        yield 'two values' => [['alice@acme.example', 'alice@other.example'], 'The attribute of the e-mail holds not one value (spec/saml.md S-56).'];
        yield 'no address' => [['alice'], 'The attribute of the e-mail is no address whose domain the rule reads (spec/saml.md S-56, S-60).'];
        yield 'a final dot' => [['alice@acme.example.'], 'The attribute of the e-mail is no address whose domain the rule reads (spec/saml.md S-56, S-60).'];
        yield 'a local part the core refuses' => [
            ['al ice@acme.example'],
            'The attribute of the e-mail is no address whose domain the rule reads (spec/saml.md S-56, S-60).',
        ];
    }

    /**
     * S-56, S-45: an attribute of the profile with one value fills its claim, one with several and one absent say
     * nothing of it.
     */
    #[Test]
    public function anAttributeOfTheProfileWithOneValueFillsItsClaim(): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(attributes: [
                'mail' => ['alice@acme.example'],
                'givenName' => ['Alice'],
                'sn' => ['Liddell', 'Hargreaves'],
            ]),
            [self::provider(profile: [
                new ProfileAttribute('givenName', 'given_name'),
                new ProfileAttribute('sn', 'family_name'),
                new ProfileAttribute('nickname', 'nickname'),
            ])],
        );

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame(['given_name' => 'Alice'], $assertion->claims);
    }

    /**
     * S-56, S-45, S-60: the telephone number an attribute fills is handed apart, and is none of the claims of the core's
     * provider.
     */
    #[Test]
    public function theTelephoneNumberIsHandedApartFromTheClaims(): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(attributes: [
                'mail' => ['alice@acme.example'],
                'telephoneNumber' => ['+33 1 23 45 67 89'],
            ]),
            [self::provider(profile: [new ProfileAttribute('telephoneNumber', 'phone_number')])],
        );

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame(['+33 1 23 45 67 89', []], [$assertion->phoneNumber, $assertion->claims]);
    }

    /**
     * S-56, S-45: the values of the groups attribute the declaration names, as the provider sent them; none when it
     * names none.
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideGroupsDeclared')]
    public function theValuesOfTheGroupsAttributeAreTheGroups(?GroupMapping $groups, array $expected): void
    {
        // Given
        $consumer = $this->consumer(
            self::verified(attributes: ['mail' => ['alice@acme.example'], 'memberOf' => ['staff', 'admins']]),
            [self::provider(groups: $groups)],
        );

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertSame($expected, $assertion->groups);
    }

    /**
     * @return iterable<string, array{GroupMapping|null, list<string>}>
     */
    public static function provideGroupsDeclared(): iterable
    {
        yield 'declared' => [new GroupMapping('memberOf', ['staff' => 'Staff']), ['staff', 'admins']];
        yield 'not declared' => [null, []];
    }

    /**
     * S-57, OIDC Core §2: the AuthnInstant is when the person was authenticated, and the class of the authentication
     * maps to the methods of RFC 8176 it names exactly.
     */
    #[Test]
    public function theAuthnInstantAndTheMethodsAreThoseOfTheAuthenticationStatement(): void
    {
        // Given
        $authenticatedAt = new DateTimeImmutable('2026-10-23T08:58:00+00:00');
        $consumer = $this->consumer(self::verified(authenticatedAt: $authenticatedAt), [self::provider()]);

        // When
        $assertion = $consumer->receive($this->tenant, [], self::PROVIDER, self::REQUEST);

        // Then
        static::assertEquals(
            [$authenticatedAt, ['fed', 'pwd']],
            [$assertion->authenticatedAt, array_map(static fn (AuthenticationMethod $method): string => $method->value, $assertion->methods)],
        );
    }

    /**
     * The acceptance of issue #784, S-56, issue #781: the person the assertion names is created at the first sign-in,
     * with what the provider said of it, its telephone number unverified.
     */
    #[Test]
    public function thePersonTheAssertionNamesIsCreated(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(), [self::provider()]);
        $assertion = $this->assertion(claims: ['given_name' => 'Alice'], phoneNumber: '+33 1 23 45 67 89');

        // When
        $alice = $consumer->personOf($this->tenant, $assertion, Fixtures::context());

        // Then
        static::assertEquals(
            ['alice@acme.example', new Profile(givenName: 'Alice'), '+33 1 23 45 67 89', false],
            [$alice->username, $alice->profile, $alice->phoneNumber, $alice->phoneNumberVerified],
        );
    }

    /**
     * S-56, S-45, issue #782: the groups the person joins are the groups of the tenant the declaration maps its values
     * to, found by their names; a value the map does not name, and a name the tenant holds no group of, are none, and
     * no group is created.
     */
    #[Test]
    public function thePersonJoinsTheGroupsTheDeclarationMapsAndNoOther(): void
    {
        // Given
        $staff = new Group(Uuid::v7(), $this->tenant, 'Staff', GroupSource::Local, Fixtures::now());
        $this->groups->save($staff);
        $consumer = $this->consumer(self::verified(), [self::provider()]);
        $assertion = $this->assertion(
            groups: ['staff', 'staff', 'admins', 'auditors'],
            mapping: new GroupMapping('memberOf', ['staff' => 'Staff', 'auditors' => 'Auditors']),
        );

        // When
        $alice = $consumer->personOf($this->tenant, $assertion, Fixtures::context());

        // Then
        static::assertSame(
            [[$staff], null],
            [
                array_map(static fn (GroupMembership $membership): Group => $membership->group, $this->memberships->of($alice)),
                $this->groups->findByName($this->tenant, 'Auditors'),
            ],
        );
    }

    /**
     * S-56: a provider whose declaration maps no group writes no membership, and leaves those the person holds.
     */
    #[Test]
    public function aProviderThatMapsNoGroupWritesNoMembership(): void
    {
        // Given
        $consumer = $this->consumer(self::verified(), [self::provider()]);

        // When
        $alice = $consumer->personOf($this->tenant, $this->assertion(groups: ['staff']), Fixtures::context());

        // Then
        static::assertSame([], $this->memberships->of($alice));
    }

    /**
     * @param list<UpstreamIdentityProvider> $declared
     */
    private function consumer(VerifiedAssertion $verified, array $declared, ?ResponseReceiverInterface $receiver = null): AssertionConsumerService
    {
        $credentials = new InMemoryCredentialRepository();
        $identities = new InMemoryLinkedIdentityRepository();

        return new AssertionConsumerService(
            new DeclaredUpstreamProviders($declared),
            $receiver ?? new RecordingResponseReceiver($verified),
            $this->groups,
            new JustInTimeProvisioning(
                $identities,
                $this->users,
                new UserProvisioner(
                    $this->users,
                    $credentials,
                    new ActivePassword(new ActiveCredentials($credentials)),
                    new NativePasswordHasher(),
                    new BreachedPasswordRefusal(BreachedPasswordsOfARecord::holding([])),
                    new EnrolmentRefusal(new FederatedDomains(new InMemoryUpstreamProviders())),
                    new SymfonyUuidGenerator(),
                    $this->clock,
                ),
                new IdentityLinker($identities, new SymfonyUuidGenerator(), $this->clock),
                new RecordingEventDispatcher(),
                $this->clock,
                new WritesAsTheyCome(),
                new SymfonyUuidGenerator(),
                new UpstreamMemberships($this->memberships, $this->memberships, new SymfonyUuidGenerator(), $this->clock),
            ),
        );
    }

    /**
     * What the service provider made of an assertion of the provider of the suite, for the person tests write.
     *
     * @param array<string, string> $claims
     * @param list<string> $groups
     */
    private function assertion(array $claims = [], ?string $phoneNumber = null, array $groups = [], ?GroupMapping $mapping = null): UpstreamAssertion
    {
        return new UpstreamAssertion(
            self::provider(profile: [
                new ProfileAttribute('givenName', 'given_name'),
                new ProfileAttribute('telephoneNumber', 'phone_number'),
            ], groups: $mapping),
            'a7f3c2e1-persistent-alice',
            new EmailAddress('alice@acme.example'),
            $claims,
            $phoneNumber,
            $groups,
            $this->clock->now(),
            [new AuthenticationMethod('fed')],
        );
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    private static function verified(
        string $nameId = 'a7f3c2e1-persistent-alice',
        bool $persistent = true,
        array $attributes = ['mail' => ['alice@acme.example']],
        ?DateTimeImmutable $authenticatedAt = null,
        bool $encrypted = false,
        ?DateTimeImmutable $sessionNotOnOrAfter = null,
    ): VerifiedAssertion {
        return new VerifiedAssertion(
            $nameId,
            $persistent,
            $attributes,
            $authenticatedAt ?? new DateTimeImmutable('2026-10-23T09:00:00+00:00'),
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            $encrypted,
            $sessionNotOnOrAfter,
        );
    }

    /**
     * @param list<ProfileAttribute> $profile
     */
    private static function provider(
        ?string $subjectAttribute = null,
        array $profile = [],
        ?GroupMapping $groups = null,
        bool $requireEncryptedAssertions = false,
    ): UpstreamIdentityProvider {
        return new UpstreamIdentityProvider(
            self::PROVIDER,
            new MetadataLocation('https://idp.acme.example/metadata'),
            [],
            [new EmailDomain('acme.example'), new EmailDomain('xn--bcher-kva.example')],
            'mail',
            $profile,
            $subjectAttribute,
            $groups,
            $requireEncryptedAssertions,
        );
    }
}
