<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Totp;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use function array_unique;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Application\Totp\BackupCodeSet;
use Beffroi\Core\Application\Totp\TotpCodeMatcher;
use Beffroi\Core\Application\Totp\TotpEnrolment;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\Totps;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function rawurlencode;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4: a TOTP enrolled in two steps from a session the user already holds, the credential
 * existing only once a first code was verified (RFC 6238 §5.2).
 */
final class TotpEnrolmentTest extends TestCase
{
    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasswordHasher $hasher;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private TotpEnrolment $enrolment;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-20T12:00:15+00:00');
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->enrolment = new TotpEnrolment(
            $this->credentials,
            new EnrolmentRefusal(new FederatedDomains($this->upstreamProviders)),
            new SymfonyUuidGenerator(),
            new PlatformRandomness(),
            new BackupCodeSet(new PlatformRandomness(), $this->hasher),
            new ActiveTotp(new ActiveCredentials($this->credentials)),
            Totps::algorithm(),
            new TotpCodeMatcher(Totps::algorithm()),
            Totps::sealer(),
            $this->clock,
            $this->events,
        );
    }

    /**
     * The Key Uri Format: the tenant is the issuer, the username the account, the secret the one of the
     * provisioning in base32.
     */
    #[Test]
    public function theProvisioningNamesTheTenantTheUserAndAFreshSecret(): void
    {
        // When
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        static::assertSame('otpauth://totp/Acme%3Aalice?issuer=Acme&secret=' . Base32::encodeUpperUnpadded($provisioning->secret->bytes), $provisioning->uri);
        static::assertNotSame($provisioning->secret->bytes, $this->enrolment->begin($this->alice)->secret->bytes);
    }

    #[Test]
    public function theProvisioningIssuesTenDistinctBackupCodes(): void
    {
        // When
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        static::assertCount(10, $provisioning->backupCodes);
        static::assertCount(10, array_unique($provisioning->backupCodes));
        foreach ($provisioning->backupCodes as $code) {
            static::assertSame(1, preg_match('/^[A-Z2-7]{5}-[A-Z2-7]{5}$/', $code));
        }
    }

    #[Test]
    public function anEnrolmentAbandonedAfterTheProvisioningLeavesNothing(): void
    {
        // When
        $this->enrolment->begin($this->alice);

        // Then
        static::assertSame([], $this->credentials->findByUser($this->alice));
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aUserWithAnActiveTotpGetsNoProvisioning(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, $this->hasher));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The user has a TOTP already; it is revoked before another is enrolled.');

        // When
        $this->enrolment->begin($this->alice);
    }

    #[Test]
    public function aUserWhoseTotpWasRevokedEnrolsAnother(): void
    {
        // Given
        $revoked = Totps::credential($this->alice, $this->hasher);
        $revoked->revoke(Fixtures::now());
        $this->credentials->save($revoked);

        // When
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        static::assertStringStartsWith('otpauth://totp/Acme%3Aalice?', $provisioning->uri);
        static::assertNotSame(Totps::SEED, $provisioning->secret->bytes);
    }

    #[Test]
    public function aFirstCodeThatHoldsCreatesTheCredentialSealedAndHashed(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $context = Fixtures::context($this->clock->now());

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now(), $provisioning->secret), $context);

        // Then
        static::assertSame($this->alice, $totp->user);
        static::assertSame($provisioning->secret->bytes, Totps::sealer()->unseal($this->alice->tenant, $totp->sealedSecret));
        static::assertSame(Totps::stepAt($this->clock->now()), $totp->lastAcceptedStep);
        static::assertEquals($this->clock->now(), $totp->createdAt);
        static::assertNull($totp->lastUsedAt);
        static::assertCount(10, $totp->backupCodes);
        foreach ($provisioning->backupCodes as $index => $code) {
            static::assertTrue($this->hasher->verify($totp->backupCodes[$index]->hash, BackupCode::normalize($code)));
            static::assertFalse($totp->backupCodes[$index]->isSpent());
        }
        static::assertSame([$totp], $this->credentials->findByUser($this->alice, TotpCredential::class));
    }

    #[Test]
    public function theFirstCodeIsSpentByTheEnrolment(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);

        // When
        $totp = $this->enrolment->complete(
            $this->alice,
            $provisioning,
            Totps::codeAt($this->clock->now(), $provisioning->secret),
            Fixtures::context($this->clock->now()),
        );

        // Then
        static::assertFalse($totp->acceptsStep(Totps::stepAt($this->clock->now())));
    }

    #[Test]
    public function aFirstCodeOnePeriodEarlyHolds(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $early = $this->clock->now()->modify('-30 seconds');

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($early, $provisioning->secret), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(Totps::stepAt($early), $totp->lastAcceptedStep);
    }

    #[Test]
    public function theEnrolmentIsAnnouncedWithItsContext(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $context = Fixtures::context($this->clock->now());

        // When
        $totp = $this->enrolment->complete($this->alice, $provisioning, Totps::codeAt($this->clock->now(), $provisioning->secret), $context);

        // Then
        static::assertCount(1, $this->events->events);
        $enrolled = $this->events->of(CredentialEnrolled::class)[0];
        static::assertSame($totp, $enrolled->credential);
        static::assertSame($context, $enrolled->context);
        static::assertEquals($this->clock->now(), $enrolled->occurredAt);
    }

    #[Test]
    public function aFirstCodeThatDoesNotHoldIsRefused(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The code does not match the secret.');

        // When
        $this->enrolment->complete(
            $this->alice,
            $provisioning,
            Totps::codeAt($this->clock->now()->modify('-2 minutes'), $provisioning->secret),
            Fixtures::context($this->clock->now()),
        );
    }

    #[Test]
    public function aRefusedFirstCodeLeavesNothing(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);

        // When
        try {
            $this->enrolment->complete($this->alice, $provisioning, '000000', Fixtures::context($this->clock->now()));
        } catch (CredentialEnrolmentFailedException) {
        }

        // Then
        static::assertSame([], $this->credentials->findByUser($this->alice));
        static::assertSame([], $this->events->events);
        static::assertSame(0, $this->hasher->hashed);
    }

    /**
     * Two enrolments begun side by side: the second one to complete finds the first one's credential.
     */
    #[Test]
    public function aSecondActiveTotpIsRefusedAtCompletion(): void
    {
        // Given
        $provisioning = $this->enrolment->begin($this->alice);
        $this->credentials->save(Totps::credential($this->alice, $this->hasher));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The user has a TOTP already; it is revoked before another is enrolled.');

        // When
        $this->enrolment->complete(
            $this->alice,
            $provisioning,
            Totps::codeAt($this->clock->now(), $provisioning->secret),
            Fixtures::context($this->clock->now()),
        );
    }

    #[Test]
    public function theAccountOfTheUriIsTheUsernameAsTyped(): void
    {
        // Given
        $bob = Fixtures::user(username: 'bob.o');

        // When
        $provisioning = $this->enrolment->begin($bob);

        // Then
        static::assertStringStartsWith('otpauth://totp/' . rawurlencode('Acme:bob.o') . '?', $provisioning->uri);
        static::assertCount(0, $this->credentials->findByUser($bob));
    }

    /**
     * Issue #327: a tenant that signs its users in by passkey admits no one-time code, and nothing of the
     * enrolment is drawn: a secret to scan that would prove no login here is not shown to anybody.
     */
    #[Test]
    public function aTenantThatAdmitsNoCodeShowsNoSecretToScan(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant());

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A one-time code proves no login of the tenant "acme", whose logins prove "phishing_resistant" at the least: it is not enrolled here. What it would prove is otp.');

        // When
        $this->enrolment->begin($carol);
    }

    /**
     * Decision 0029, spec/saml.md S-63: no secret is drawn for a person of an e-mail domain the tenant federates to an
     * upstream provider, through which alone they sign in.
     */
    #[Test]
    public function aPersonOfAFederatedDomainIsShownNoSecretToScan(): void
    {
        // Given
        $user = $this->alice;
        $this->upstreamProviders->declare($user->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A one-time code is posed for nobody of an e-mail domain the tenant "acme" federates to an upstream provider, through which alone they sign in.');

        // When
        $this->enrolment->begin($user);
    }
}
