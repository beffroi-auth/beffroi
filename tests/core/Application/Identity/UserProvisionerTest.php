<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\Claim\Locale;
use Beffroi\Core\Domain\Identity\Claim\Zoneinfo;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\PasswordRefusedException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\FixedClaims;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;

final class UserProvisionerTest extends TestCase
{
    private const string A_PASSWORD = 'correct horse battery staple';

    private const string ANOTHER_PASSWORD = 'nine lives of a quiet cat';

    private const string BREACHED = 'monkey business as usual';

    private const string PROVIDER = 'https://idp.acme.example/saml';

    private const array KNOWN_LOCALES = [
        'en-GB' => 'English (United Kingdom)',
    ];

    private Tenant $tenant;

    private InMemoryUserRepository $users;

    private InMemoryCredentialRepository $credentials;

    private NativePasswordHasher $hasher;

    private MockClock $clock;

    private UserProvisioner $provisioner;

    private InMemoryUpstreamProviders $upstreamProviders;

    private FixedClaims $claims;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->users = new InMemoryUserRepository();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new NativePasswordHasher();
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->claims = new FixedClaims([new Zoneinfo(), new Locale(self::KNOWN_LOCALES)]);
        $breaches = BreachedPasswordsOfARecord::holding([self::BREACHED]);
        $this->provisioner = $this->provisionerAsking($breaches);
    }

    #[Test]
    public function itCreatesAnEnabledUserOfTheTenantAndSavesIt(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, ' alice ', new EmailAddress('alice@example.com'), true);

        // Then
        static::assertSame($user, $this->users->find($user->id));
        static::assertSame($this->tenant, $user->tenant);
        static::assertSame('alice', $user->username);
        static::assertSame('alice@example.com', (string) $user->email);
        static::assertTrue($user->emailVerified);
        static::assertEquals($this->clock->now(), $user->createdAt);
        static::assertTrue($user->isEnabled());
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function itGeneratesARandomSubjectDistinctFromTheIdentifier(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        static::assertInstanceOf(UuidV4::class, Uuid::fromString($user->subject->value));
        static::assertNotSame($user->id->toRfc4122(), $user->subject->value);
    }

    #[Test]
    public function aNewUserHasNoCredential(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        static::assertSame([], $this->credentials->findByUser($user));
    }

    #[Test]
    public function itKeepsTheSubjectAnotherProviderGave(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice', subject: new Subject('f3a1-from-keycloak'));

        // Then
        static::assertSame('f3a1-from-keycloak', $user->subject->value);
        static::assertSame($user, $this->users->findBySubject($this->tenant, new Subject('f3a1-from-keycloak')));
    }

    #[Test]
    public function twoUsersOfATenantCannotShareAUsername(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(UserAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A user named "alice" already exists in this tenant.');

        // When
        $this->provisioner->create($this->tenant, 'alice ');
    }

    /**
     * RFC 8265 §3.3.4, RFC 7643 §4.1.1
     */
    #[Test]
    #[DataProvider('provideSpellingsOfAlice')]
    public function aSecondPersonWhoseUsernameComparesEqualToTheFirstIsRefused(string $spelling): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(UserAlreadyExistsException::class);

        // When
        $this->provisioner->create($this->tenant, $spelling);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpellingsOfAlice(): iterable
    {
        yield 'in capitals' => ['ALICE'];
        yield 'in fullwidth letters' => ["\u{FF41}\u{FF4C}\u{FF49}\u{FF43}\u{FF45}"];
    }

    #[Test]
    public function twoUsersOfATenantCannotShareASubject(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice', subject: new Subject('shared'));

        // Then
        $this->expectException(UserAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A user with the subject "shared" already exists in this tenant.');

        // When
        $this->provisioner->create($this->tenant, 'bob', subject: new Subject('shared'));
    }

    #[Test]
    public function aUserRefusedForItsSubjectIsNotSaved(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice', subject: new Subject('shared'));

        // When
        try {
            $this->provisioner->create($this->tenant, 'bob', subject: new Subject('shared'));
        } catch (UserAlreadyExistsException) {
        }

        // Then
        static::assertNull($this->users->findByUsername($this->tenant, 'bob'));
    }

    #[Test]
    public function anotherTenantMayHaveTheSameUsername(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice');

        // When
        $other = $this->provisioner->create(Fixtures::tenant('other', 'https://id.other.example'), 'alice');

        // Then
        static::assertSame('alice', $other->username);
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    public function theProfileThePhoneNumberAndTheAddressAreSetAtOnce(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->clock->modify('+1 day');
        $profile = new Profile('Alice Liddell', 'Alice', 'Liddell', locale: 'en-GB');
        $address = new Address('1 Wonderland Road\nOxford', '1 Wonderland Road', 'Oxford', 'Oxfordshire', 'OX1 1AA', 'GB');

        // When
        $described = $this->provisioner->setProfile($user, $profile, '+44 1865 000000', true, $address);

        // Then
        static::assertSame($user, $described);
        static::assertSame($user, $this->users->find($user->id));
        static::assertSame($profile, $user->profile);
        static::assertSame('+44 1865 000000', $user->phoneNumber);
        static::assertTrue($user->phoneNumberVerified);
        static::assertSame($address, $user->address);
        static::assertEquals($this->clock->now(), $user->updatedAt);
    }

    #[Test]
    public function aSecondProfileReplacesTheFirstInFull(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->provisioner->setProfile($user, new Profile('Alice Liddell'), '+44 1865 000000', true, new Address(locality: 'Oxford'));

        // When
        $this->provisioner->setProfile($user, new Profile(givenName: 'Alice'));

        // Then
        static::assertNull($user->profile->name);
        static::assertSame('Alice', $user->profile->givenName);
        static::assertNull($user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
        static::assertNull($user->address);
    }

    #[Test]
    public function anEmptyAddressIsNoAddress(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $this->provisioner->setProfile($user, Profile::empty(), address: new Address());

        // Then
        static::assertNull($user->address);
    }

    #[Test]
    #[DataProvider('provideValuesOutsideTheSetOfTheirClaim')]
    public function aValueOutsideTheSetOfItsClaimIsRefused(Profile $profile, string $value): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('The value "%s" is not one this claim may hold.', $value));

        // When
        $this->provisioner->setProfile($user, $profile);
    }

    /**
     * @return iterable<string, array{Profile, string}>
     */
    public static function provideValuesOutsideTheSetOfTheirClaim(): iterable
    {
        yield 'a zone the zoneinfo database does not carry' => [new Profile(zoneinfo: 'Europe/Atlantis'), 'Europe/Atlantis'];
        yield 'a language the deployment does not know' => [new Profile(locale: 'tlh'), 'tlh'];
    }

    #[Test]
    public function aValueOutsideTheSetOfItsClaimWritesNothing(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->provisioner->setProfile($user, new Profile('Alice Liddell', zoneinfo: 'Europe/London'), '+44 1865 000000', true);

        // When
        try {
            $this->provisioner->setProfile($user, new Profile(givenName: 'Alice', zoneinfo: 'Europe/Atlantis'));
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame('Alice Liddell', $user->profile->name);
        static::assertSame('Europe/London', $user->profile->zoneinfo);
        static::assertSame('+44 1865 000000', $user->phoneNumber);
    }

    #[Test]
    public function aClaimNothingWiresHoldsNoSet(): void
    {
        // Given
        $this->claims = new FixedClaims();
        $provisioner = $this->provisionerAsking(BreachedPasswordsOfARecord::holding([]));
        $user = $provisioner->create($this->tenant, 'alice');

        // When
        $provisioner->setProfile($user, new Profile(zoneinfo: 'Europe/Atlantis'));

        // Then
        static::assertSame('Europe/Atlantis', $user->profile->zoneinfo);
    }

    #[Test]
    public function anAbsentPhoneNumberCannotBeVerified(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An absent phone number cannot be verified.');

        // When
        $this->provisioner->setProfile($user, Profile::empty(), null, true);
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function aUserCreatedWithoutASourceIsLocal(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        static::assertTrue($user->source->isLocal());
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function aUserCreatedByAnUpstreamProviderNamesIt(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice', source: UserSource::upstream(self::PROVIDER, ['email', 'given_name']));

        // Then
        static::assertSame($user, $this->users->find($user->id));
        static::assertSame(self::PROVIDER, $user->source->provider);
        static::assertSame(['email', 'given_name'], $user->source->claims);
    }

    /**
     * Decision 0002
     */
    #[Test]
    #[DataProvider('provideDescriptionsOfWhatTheSourceHolds')]
    public function aDescriptionThatSaysOtherwiseAClaimTheSourceHoldsIsRefused(Profile $profile, ?string $phoneNumber, ?Address $address, string $claim): void
    {
        // Given
        $user = $this->createdBySource();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The upstream provider "%s" created this person and holds "%s": a manual description does not change what its source holds.',
            self::PROVIDER,
            $claim,
        ));

        // When
        $this->provisioner->setProfile($user, $profile, $phoneNumber, false, $address);
    }

    /**
     * @return iterable<string, array{Profile, string|null, Address|null, string}>
     */
    public static function provideDescriptionsOfWhatTheSourceHolds(): iterable
    {
        yield 'a claim of the profile' => [new Profile(givenName: 'Alicia'), null, null, 'given_name'];
        yield 'the phone number' => [Profile::empty(), '+44 1865 999999', null, 'phone_number'];
        yield 'the address' => [Profile::empty(), null, new Address(locality: 'London'), 'address'];
    }

    #[Test]
    public function aClaimTheSourceHoldsAndHasNotWrittenIsNotTheOperatorsToFill(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice', source: UserSource::upstream(self::PROVIDER, ['family_name']));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The upstream provider "%s" created this person and holds "family_name": a manual description does not change what its source holds.',
            self::PROVIDER,
        ));

        // When
        $this->provisioner->setProfile($user, new Profile(familyName: 'Liddell'));
    }

    #[Test]
    public function aPhoneNumberTheSourceHoldsSaidWithAnotherVerificationIsRefused(): void
    {
        // Given
        $user = $this->createdBySource();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The upstream provider "%s" created this person and holds "phone_number": a manual description does not change what its source holds.',
            self::PROVIDER,
        ));

        // When
        $this->provisioner->setProfile($user, Profile::empty(), '+44 1865 000000', false);
    }

    #[Test]
    public function aRefusedDescriptionWritesNothing(): void
    {
        // Given
        $user = $this->createdBySource();

        // When
        try {
            $this->provisioner->setProfile($user, new Profile(givenName: 'Alicia', nickname: 'Ali'));
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame('Alice', $user->profile->givenName);
        static::assertNull($user->profile->nickname);
    }

    #[Test]
    public function whatTheSourceHoldsStaysWhatItWroteWhenADescriptionDoesNotSayIt(): void
    {
        // Given
        $user = $this->createdBySource();

        // When
        $this->provisioner->setProfile($user, new Profile(nickname: 'Ali'));

        // Then
        static::assertSame('Ali', $user->profile->nickname);
        static::assertSame('Alice', $user->profile->givenName);
        static::assertSame('+44 1865 000000', $user->phoneNumber);
        static::assertTrue($user->phoneNumberVerified);
        static::assertSame('Oxford', $user->address?->locality);
    }

    #[Test]
    public function aClaimTheSourceHoldsMayBeSaidAsItIs(): void
    {
        // Given
        $user = $this->createdBySource();

        // When
        $this->provisioner->setProfile($user, new Profile(givenName: 'Alice', nickname: 'Ali'), '+44 1865 000000', true, new Address(locality: 'Oxford'));

        // Then
        static::assertSame('Ali', $user->profile->nickname);
    }

    #[Test]
    public function theFirstPasswordCreatesTheCredentialHashedByThePolicyOfTheCore(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $credential = $this->provisioner->setPassword($user, Fixtures::plainPassword(self::A_PASSWORD));

        // Then
        static::assertSame($credential, $this->credentials->findByUser($user, PasswordCredential::class)[0]);
        static::assertSame($user, $credential->user);
        static::assertSame(Argon2id::NAME, $credential->hash->algorithm->name());
        static::assertTrue($this->hasher->verify($credential->hash, self::A_PASSWORD));
        static::assertEquals($this->clock->now(), $credential->createdAt);
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
    }

    #[Test]
    public function theNextPasswordReplacesTheHashOfTheSameCredential(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $first = $this->provisioner->setPassword($user, Fixtures::plainPassword(self::A_PASSWORD));
        $this->clock->modify('+1 day');

        // When
        $second = $this->provisioner->setPassword($user, Fixtures::plainPassword(self::ANOTHER_PASSWORD));

        // Then
        static::assertSame($first, $second);
        static::assertCount(1, $this->credentials->findByUser($user));
        static::assertTrue($this->hasher->verify($second->hash, self::ANOTHER_PASSWORD));
        static::assertFalse($this->hasher->verify($second->hash, self::A_PASSWORD));
        static::assertEquals($this->clock->now(), $second->hashChangedAt);
        static::assertEquals($this->clock->now()->modify('-1 day'), $second->createdAt);
    }

    #[Test]
    public function aRefusedPasswordLeavesTheCurrentOneInPlace(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->provisioner->setPassword($user, Fixtures::plainPassword(self::A_PASSWORD));

        // When
        try {
            $this->provisioner->setPassword($user, Fixtures::plainPassword('seven77'));
        } catch (PasswordRefusedException) {
        }

        // Then
        static::assertTrue($this->hasher->verify(
            $this->credentials->findByUser($user, PasswordCredential::class)[0]->hash ?? static::fail('The credential is gone.'),
            self::A_PASSWORD,
        ));
    }

    /**
     * NIST SP 800-63B §3.1.1.2
     */
    #[Test]
    public function aPasswordAListCountsIsRefused(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        try {
            $this->provisioner->setPassword($user, Fixtures::plainPassword(self::BREACHED));
            static::fail('A password a list counts is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::Breached, $exception->refusal);
        }
    }

    #[Test]
    public function aPasswordAListCountsWritesNothing(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        try {
            $this->provisioner->setPassword($user, Fixtures::plainPassword(self::BREACHED));
        } catch (PasswordRefusedException) {
        }

        // Then
        static::assertSame([], $this->credentials->findByUser($user, PasswordCredential::class));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aPasswordNoListCouldBeAskedAboutIsRefused(): void
    {
        // Given
        $provisioner = $this->provisionerAsking(new BreachedPasswordsOfARecord(unreachable: true));
        $user = $provisioner->create($this->tenant, 'alice');

        // When
        try {
            $provisioner->setPassword($user, Fixtures::plainPassword(self::A_PASSWORD));
            static::fail('A password nobody could be asked about is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::NotChecked, $exception->refusal);
        }
    }

    #[Test]
    public function aPasswordAListWasAskedAboutIsMarkedAsLookedUp(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $credential = $this->provisioner->setPassword($user, Fixtures::plainPassword(self::A_PASSWORD));

        // Then
        static::assertEquals($this->clock->now(), $credential->breachCheckedAt);
        static::assertNull($credential->breachFoundAt);
        static::assertFalse($credential->dueForABreachLookup($this->clock->now()));
    }

    #[Test]
    public function aDeploymentThatNamesNoListWritesThePasswordAndMarksNothing(): void
    {
        // Given
        $provisioner = $this->provisionerAsking(new BreachedPasswordsOfARecord(looksUp: false));
        $user = $provisioner->create($this->tenant, 'alice');

        // When
        $credential = $provisioner->setPassword($user, Fixtures::plainPassword(self::BREACHED));

        // Then
        static::assertNull($credential->breachCheckedAt);
        static::assertTrue($credential->dueForABreachLookup($this->clock->now()));
    }

    #[Test]
    public function aTenantThatAdmitsNoPasswordPosesNone(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant());

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A password proves no login of the tenant "acme", whose logins prove "phishing_resistant" at the least: it is not enrolled here. What it would prove is pwd.');

        // When
        $this->provisioner->setPassword($carol, Fixtures::plainPassword('correct horse battery staple', $carol->tenant->loginFloor));
    }

    /**
     * Decision 0029, spec/saml.md S-63
     */
    #[Test]
    public function aPasswordIsSetForNobodyOfAFederatedDomain(): void
    {
        // Given
        $user = Fixtures::user($this->tenant);
        $this->upstreamProviders->declare($user->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A password is posed for nobody of an e-mail domain the tenant "acme" federates to an upstream provider, through which alone they sign in.');

        // When
        $this->provisioner->setPassword($user, Fixtures::plainPassword(self::A_PASSWORD));
    }

    private function createdBySource(): User
    {
        $user = $this->provisioner->create($this->tenant, 'alice', source: UserSource::upstream(self::PROVIDER, ['given_name', 'phone_number', 'address']));
        $now = $this->clock->now();
        $user->updateProfile(new Profile(givenName: 'Alice'), $now);
        $user->changePhoneNumber('+44 1865 000000', true, $now);
        $user->changeAddress(new Address(locality: 'Oxford'), $now);

        return $user;
    }

    private function provisionerAsking(BreachedPasswordsOfARecord $breaches): UserProvisioner
    {
        return new UserProvisioner(
            $this->users,
            $this->credentials,
            new ActivePassword(new ActiveCredentials($this->credentials)),
            $this->hasher,
            new BreachedPasswordRefusal($breaches),
            new EnrolmentRefusal(new FederatedDomains($this->upstreamProviders)),
            new SymfonyUuidGenerator(),
            $this->clock,
            $this->claims,
        );
    }
}
