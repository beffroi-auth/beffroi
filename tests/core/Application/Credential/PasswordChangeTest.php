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
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.1: a person replaces their own password, from a session they already hold, by typing
 * the one in use first.
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

    private MockClock $clock;

    private BreachedPasswordsOfARecord $breaches;

    private PasswordChange $change;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->breaches = BreachedPasswordsOfARecord::holding([self::BREACHED]);
        $this->upstreamProviders = new InMemoryUpstreamProviders();
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

    /**
     * The journal of a person is read to recognise what they did, and replacing their password is one of
     * the things they did.
     */
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
     * A session somebody else took over does not get to replace the password it signed in with.
     */
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

    /**
     * The page reads which refusal it was, every one of them being the same answer otherwise: the
     * password did not change.
     */
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

    /**
     * Somebody who signs in by another means holds no password, and there is nothing to replace.
     */
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
     * The rule NIST SP 800-63B §3.1.1.2 puts first, on the page a person replaces their own password: it
     * refuses the two the console refuses, and says which.
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
     * Decision 0006: a list that could not be asked refuses the password rather than writing one nobody
     * checked.
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

    /**
     * A password the page refuses on its own is refused without a prefix of anything leaving: the list is
     * asked last.
     */
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

    /**
     * The answer is written on the credential, so that the first login does not ask again what was just
     * asked.
     */
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

    /**
     * What a list said of the password that is gone is forgotten with it: a credential found in a breach
     * and then replaced is not a credential found in a breach.
     */
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

    /**
     * Issue #327: a tenant that hardened holds none of its users' passwords any more, so a change answers
     * the one a store left behind rather than replacing it.
     */
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
     * Decision 0029, spec/saml.md S-63: a password a person held before their e-mail domain was federated is replaced
     * by nobody, posing a new one being posing a local credential for them.
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

    private function changeAsking(BreachedPasswordsOfARecord $breaches): PasswordChange
    {
        return new PasswordChange(
            $this->credentials,
            new ActivePassword(new ActiveCredentials($this->credentials)),
            $this->hasher,
            new BreachedPasswordRefusal($breaches),
            $this->clock,
            $this->events,
            new FederatedDomains($this->upstreamProviders),
        );
    }

    private function passwordInUse(): PasswordCredential
    {
        $credential = new PasswordCredential(Uuid::v7(), $this->alice, $this->hasher->hash(self::IN_USE), Fixtures::now());
        $this->credentials->save($credential);

        return $credential;
    }
}
