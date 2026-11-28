<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasswordChangeRefusal;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Beffroi\Core\Exception\PasswordRefusedException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\FakeAttemptLimiter;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.1
 */
final class PasswordChangeTest extends TestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    private const string BREACHED = 'monkey business as usual';

    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasswordHasher $hasher;

    private RecordingEventDispatcher $events;

    private RecordingCredentialChangeNotifier $notifier;

    private MockClock $clock;

    private BreachedPasswordsOfARecord $breaches;

    private PasswordChange $change;

    private InMemoryUpstreamProviders $upstreamProviders;

    private FakeAttemptLimiter $attempts;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $this->notifier = new RecordingCredentialChangeNotifier();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->breaches = BreachedPasswordsOfARecord::holding([self::BREACHED]);
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->attempts = new FakeAttemptLimiter();
        $this->change = $this->changeAsking($this->breaches);
    }

    #[Test]
    public function thePasswordPosedIsTheOneHeldAfterwards(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::POSED));
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
    }

    #[Test]
    public function changingThePasswordAnnouncesTheAct(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        $announced = $this->events->of(PasswordChanged::class);
        static::assertCount(1, $announced);
        static::assertSame($credential, $announced[0]->credential);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function thePersonIsToldTheirPasswordWasChanged(): void
    {
        // Given
        $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertSame([[PasswordChanged::NAME, 'password']], $this->notifier->acts());
        static::assertEquals($this->clock->now(), $this->notifier->told[0]->occurredAt);
    }

    #[Test]
    public function aPasswordInUseThatWasNotTypedIsRefused(): void
    {
        // Given
        $this->passwordInUse();

        // Then
        $this->expectException(PasswordChangeRefusedException::class);
        $this->expectExceptionMessageIs('What was typed is not the password in use.');

        // When
        $this->change->change($this->alice, 'not the password', Fixtures::plainPassword(self::POSED), Fixtures::context());
    }

    #[Test]
    public function aPasswordThatWasNotReplacedLeavesTheOneHeldAndSaysNothing(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, 'not the password', Fixtures::plainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::IN_USE));
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aPasswordThatWasNotReplacedTellsThePersonNothing(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, 'not the password', Fixtures::plainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertSame([], $this->notifier->told);
    }

    #[Test]
    public function thePasswordPosedBeingTheOneHeldIsRefusedAsSuch(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::IN_USE), Fixtures::context());
            static::fail('The same password should have been refused.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::SameAsBefore, $exception->refusal);
        }
    }

    #[Test]
    public function aPersonWhoHoldsNoPasswordIsRefusedAsSuch(): void
    {
        // When
        try {
            $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());
            static::fail('A person holding no password should have been refused.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::NoPasswordHeld, $exception->refusal);
        }
    }

    /**
     * NIST SP 800-63B §3.1.1.2
     */
    #[Test]
    public function aPasswordAListCountsIsRefused(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::BREACHED), Fixtures::context());
            static::fail('A password a list counts is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::Breached, $exception->refusal);
        }
    }

    #[Test]
    public function aPasswordAListCountsLeavesTheOneHeldAndSaysNothing(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::BREACHED), Fixtures::context());
        } catch (PasswordRefusedException) {
        }

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::IN_USE));
        static::assertSame([], $this->events->events);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aPasswordNoListCouldBeAskedAboutIsRefused(): void
    {
        // Given
        $change = $this->changeAsking(new BreachedPasswordsOfARecord(unreachable: true));
        $this->passwordInUse();

        // When
        try {
            $change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());
            static::fail('A password nobody could be asked about is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::NotChecked, $exception->refusal);
        }
    }

    #[Test]
    public function aPasswordInUseThatWasNotTypedAsksNoList(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, 'not the password', Fixtures::plainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertSame([], $this->breaches->asked);
    }

    #[Test]
    public function thePasswordPosedIsMarkedAsLookedUp(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertEquals($this->clock->now(), $credential->breachCheckedAt);
        static::assertNull($credential->breachFoundAt);
    }

    #[Test]
    public function thePasswordPosedCarriesNoneOfWhatWasSaidOfTheOneBefore(): void
    {
        // Given
        $credential = $this->passwordInUse();
        $credential->foundInABreach(Fixtures::now());

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertFalse($credential->isBreached());
    }

    #[Test]
    public function aTenantThatAdmitsNoPasswordReplacesNone(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant());
        $this->credentials->save(Fixtures::password($carol));

        // Then
        $this->expectException(PasswordChangeRefusedException::class);
        $this->expectExceptionMessageIs('The tenant signs its users in without a password; there is nothing to replace.');

        // When
        $this->change->change(
            $carol,
            'correct horse battery staple',
            Fixtures::plainPassword('another horse battery staple', $carol->tenant->loginFloor),
            Fixtures::context(),
        );
    }

    /**
     * Decision 0029, spec/saml.md S-63
     */
    #[Test]
    public function aPasswordOfAPersonOfAFederatedDomainIsReplacedByNobody(): void
    {
        // Given
        $this->passwordInUse();
        $user = $this->alice;
        $this->upstreamProviders->declare($user->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        try {
            $this->change->change($user, self::IN_USE, Fixtures::plainPassword('another horse battery staple'), Fixtures::context());
            static::fail('The password was replaced.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::FederatedDomain, $exception->refusal);
        }
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function anAttemptAtThePasswordInUseIsCounted(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, 'not the password', Fixtures::plainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $this->attempts->attempts);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function thePasswordInUseTypedBeyondTheLimitIsRefusedAsSuch(): void
    {
        // Given
        $this->passwordInUse();
        $change = $this->changeAsking($this->breaches, new FakeAttemptLimiter(allowed: 0));

        // When
        try {
            $change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());
            static::fail('An attempt beyond the limit should have been refused.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::TooManyAttempts, $exception->refusal);
        }
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function thePasswordInUseTypedBeyondTheLimitLeavesTheOneHeld(): void
    {
        // Given
        $credential = $this->passwordInUse();
        $change = $this->changeAsking($this->breaches, new FakeAttemptLimiter(allowed: 0));

        // When
        try {
            $change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::IN_USE));
        static::assertSame([], $this->events->events);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function thePasswordInUseTypedRightForgetsTheAttemptsBefore(): void
    {
        // Given
        $this->passwordInUse();
        try {
            $this->change->change($this->alice, 'not the password', Fixtures::plainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertSame([], $this->attempts->attempts);
    }

    /**
     * RFC 8265 §4.2.3
     */
    #[Test]
    public function thePasswordInUseTypedInAnotherFormThanItWasSetInIsAccepted(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, "correct\u{00A0}horse battery staple", Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::POSED));
    }

    /**
     * RFC 8265 §6.2, decision 0065
     */
    #[Test]
    public function aPasswordInUseHashedAsItWasTypedBeforeTheProfileIsAcceptedTypedSo(): void
    {
        // Given
        $credential = Fixtures::hashedAsTyped($this->passwordInUse("correct\u{00A0}horse battery staple"));

        // When
        $this->change->change($this->alice, "correct\u{00A0}horse battery staple", Fixtures::plainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::POSED));
    }

    /**
     * RFC 8265 §4.1, §4.3
     */
    #[Test]
    public function aPasswordInUseTheProfileRefusesIsNotTheOneInUse(): void
    {
        // Given
        Fixtures::hashedAsTyped($this->passwordInUse("my cat is a \u{0009}by"));

        // When
        try {
            $this->change->change($this->alice, "my cat is a \u{0009}by", Fixtures::plainPassword(self::POSED), Fixtures::context());
            static::fail('A password the profile refuses was taken for the one in use.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::WrongPassword, $exception->refusal);
        }
    }

    /**
     * RFC 8265 §8.2
     */
    #[Test]
    public function thePasswordPosedIsHeldInTheFormTheProfileEnforces(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, Fixtures::plainPassword("a horse walks\u{3000}into a bar"), Fixtures::context());

        // Then
        static::assertSame($this->hasher->hash(self::POSED)->encoded, $credential->hash->encoded);
    }

    private function changeAsking(BreachedPasswordsOfARecord $breaches, ?FakeAttemptLimiter $attempts = null): PasswordChange
    {
        return new PasswordChange(
            $this->credentials,
            new ActivePassword(new ActiveCredentials($this->credentials)),
            $this->hasher,
            new BreachedPasswordRefusal($breaches),
            $this->clock,
            $this->events,
            new FederatedDomains($this->upstreamProviders),
            $this->notifier,
            $attempts ?? $this->attempts,
        );
    }

    private function passwordInUse(string $hashed = self::IN_USE): PasswordCredential
    {
        $credential = new PasswordCredential(Uuid::v7(), $this->alice, $this->hasher->hash($hashed), Fixtures::now());
        $this->credentials->save($credential);

        return $credential;
    }
}
