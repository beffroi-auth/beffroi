<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Passkey;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Passkey\PasskeyEnrolment;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Tests\Fixture\FakePasskeyRegistrar;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4: a passkey enrolled from a session the user already holds, WebAuthn Level 3 §7.1.
 */
final class PasskeyEnrolmentTest extends TestCase
{
    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasskeyRegistrar $registrar;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PasskeyEnrolment $enrolment;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->registrar = new FakePasskeyRegistrar();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-19T12:00:00+00:00');
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->enrolment = new PasskeyEnrolment(
            $this->credentials,
            new EnrolmentRefusal(new FederatedDomains($this->upstreamProviders)),
            new SymfonyUuidGenerator(),
            new PlatformRandomness(),
            $this->registrar,
            $this->clock,
            $this->events,
        );
    }

    #[Test]
    public function aFirstPasskeyGetsAFreshHandleAndExcludesNothing(): void
    {
        // When
        $options = $this->enrolment->begin($this->alice);

        // Then
        static::assertSame(PasskeyUserHandle::LENGTH, strlen($options->user->id));
        static::assertSame('alice', $options->user->name);
        static::assertSame([], $options->excludeCredentials);
    }

    /**
     * WebAuthn Level 3 §14.6.1: one handle per user, whatever the number of passkeys.
     */
    #[Test]
    public function aSecondPasskeyReusesTheHandleAndExcludesTheFirstEvenRevoked(): void
    {
        // Given
        $first = Fixtures::passkey($this->alice, credentialId: 'first');
        $first->revoke(Fixtures::now());
        $this->credentials->save($first);

        // When
        $options = $this->enrolment->begin($this->alice);

        // Then
        static::assertSame($first->userHandle->value, $options->user->id);
        static::assertCount(1, $options->excludeCredentials);
        static::assertSame('first', $options->excludeCredentials[0]->id);
    }

    #[Test]
    public function aVerifiedRecordBecomesAPasskeyOfTheUserAndIsAnnounced(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'new-credential', backupEligible: true, backedUp: true));
        $context = Fixtures::context($this->clock->now());

        // When
        $passkey = $this->enrolment->complete($this->alice, 'Pixel', $options, '{"id":"new-credential"}', $context);

        // Then
        static::assertSame($this->alice, $passkey->user);
        static::assertSame('Pixel', $passkey->name);
        static::assertSame('new-credential', $passkey->credentialId);
        static::assertSame($options->user->id, $passkey->userHandle->value);
        static::assertTrue($passkey->backupEligible);
        static::assertEquals($this->clock->now(), $passkey->createdAt);
        static::assertSame([$passkey], $this->credentials->findByUser($this->alice, PasskeyCredential::class));
        $events = $this->events->of(CredentialEnrolled::class);
        static::assertCount(1, $events);
        static::assertSame($passkey, $events[0]->credential);
        static::assertSame($context, $events[0]->context);
        static::assertSame($this->alice->tenant, $events[0]->tenant);
    }

    /**
     * WebAuthn Level 3 §6.1.3: the model refuses a record whose backup flags contradict each other, and
     * the enrolment refuses it as it refuses anything else, by the one exception its contract names.
     */
    #[Test]
    public function aRecordTheModelRefusesFailsTheEnrolment(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->returns(FakePasskeyRegistrar::record($options, backupEligible: false, backedUp: true));

        // When
        try {
            $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
            static::fail('The enrolment should have failed.');
        } catch (CredentialEnrolmentFailedException $exception) {
            // Then
            static::assertInstanceOf(InvalidArgumentException::class, $exception->getPrevious());
            static::assertSame([], $this->credentials->findByUser($this->alice));
        }
    }

    #[Test]
    public function aRefusedCeremonyFailsTheEnrolmentWithItsCause(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->refuses('The origin does not match.');

        // When
        try {
            $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
            static::fail('The enrolment should have failed.');
        } catch (CredentialEnrolmentFailedException $exception) {
            // Then
            static::assertSame('The origin does not match.', $exception->getMessage());
            static::assertInstanceOf(PasskeyCeremonyFailedException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function aRefusedCeremonyEnrolsNothing(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->refuses('The origin does not match.');

        // When
        try {
            $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
        } catch (CredentialEnrolmentFailedException) {
        }

        // Then
        static::assertSame([], $this->credentials->findByUser($this->alice));
        static::assertSame([], $this->events->events);
    }

    /**
     * WebAuthn Level 3 §7.1, step 26.
     */
    #[Test]
    public function aCredentialIdKnownInTheTenantIsRefused(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->credentials->save(Fixtures::passkey(Fixtures::user($this->alice->tenant, 'bob', 'bob-subject'), credentialId: 'taken'));
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'taken'));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('This passkey is enrolled already.');

        // When
        $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
    }

    #[Test]
    public function optionsDrawnForAnotherUserAreRefused(): void
    {
        // Given
        $this->credentials->save(Fixtures::passkey($this->alice, credentialId: 'first'));
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $options = $this->enrolment->begin($bob);

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The options were not drawn for this user.');

        // When
        $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
    }

    /**
     * Issue #327: a tenant whose floor asks for a key held in hardware refuses a synced passkey, which
     * proves "swk", and keeps the one bound to its authenticator, which proves "hwk". The question is asked
     * of what the ceremony answered, the kind alone not saying which of the two a passkey is.
     */
    #[Test]
    public function aSyncedPasskeyIsRefusedByATenantThatAsksForHardware(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::tenant('acme', 'https://id.acme.example', new PhishingResistantHardware()));
        $options = $this->enrolment->begin($carol);
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'synced', backupEligible: true, backedUp: true));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A passkey proves no login of the tenant "acme", whose logins prove "phishing_resistant_hardware" at the least: it is not enrolled here. What it would prove is swk, user.');

        // When
        $this->enrolment->complete($carol, 'The phone', $options, '{"id":"synced"}', Fixtures::context());
    }

    #[Test]
    public function aPasskeyBoundToItsAuthenticatorIsEnrolledByATenantThatAsksForHardware(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::tenant('acme', 'https://id.acme.example', new PhishingResistantHardware()));
        $options = $this->enrolment->begin($carol);
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'bound'));

        // When
        $passkey = $this->enrolment->complete($carol, 'YubiKey 5', $options, '{"id":"bound"}', Fixtures::context());

        // Then
        static::assertSame([$passkey], $this->credentials->findByUser($carol));
    }

    /**
     * Decision 0029, spec/saml.md S-63: no passkey is posed for a person of an e-mail domain the tenant federates to
     * an upstream provider, through which alone they sign in.
     */
    #[Test]
    public function aPasskeyIsPosedForNobodyOfAFederatedDomain(): void
    {
        // Given
        $user = $this->alice;
        $this->upstreamProviders->declare($user->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
        $options = $this->enrolment->begin($user);
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'bound'));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A passkey is posed for nobody of an e-mail domain the tenant "acme" federates to an upstream provider, through which alone they sign in.');

        // When
        $this->enrolment->complete($user, 'YubiKey 5', $options, '{"id":"bound"}', Fixtures::context());
    }
}
