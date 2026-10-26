<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Passkey;

use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use DateInterval;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Authentication\AuthenticationRefusal;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Application\Passkey\PasskeyAuthentication;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasskeyUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasskeyAuthenticator;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Architecture §3.2, §3.4: a session opened on what an assertion proved, WebAuthn Level 3 §7.2.
 */
final class PasskeyAuthenticationTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private PasskeyCredential $passkey;

    private InMemoryCredentialRepository $credentials;

    private InMemoryAuthenticationSessionRepository $sessions;

    private FakePasskeyAuthenticator $ceremony;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PasskeyAuthentication $authentication;

    private PublicKeyCredentialRequestOptions $options;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->passkey = Fixtures::passkey($this->alice, credentialId: 'alice-key');
        $this->credentials = new InMemoryCredentialRepository();
        $this->credentials->save($this->passkey);
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->ceremony = new FakePasskeyAuthenticator();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-19T12:00:00+00:00');
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->authentication = new PasskeyAuthentication(
            $this->credentials,
            new ActiveCredentials($this->credentials),
            $this->ceremony,
            new SessionOpener(
                $this->sessions,
                new SymfonyUuidGenerator(),
                $this->clock,
                $this->events,
                new AuthenticationRefusal($this->clock, $this->events),
                new DateInterval('PT8H'),
            ),
            new AuthenticationRefusal($this->clock, $this->events),
            $this->clock,
            $this->events,
            new FederatedDomains($this->upstreamProviders),
        );
        $this->options = $this->authentication->requestOptions($this->tenant);
    }

    #[Test]
    public function aDiscoverableCredentialIsAskedForWithoutAnAllowList(): void
    {
        // When
        $options = $this->authentication->requestOptions($this->tenant);

        // Then
        static::assertSame([], $options->allowCredentials);
    }

    #[Test]
    public function aUserWhoNamedThemselfIsAskedForTheirActivePasskeys(): void
    {
        // Given
        $revoked = Fixtures::passkey($this->alice, credentialId: 'old-key', createdAt: Fixtures::now()->modify('-1 day'));
        $revoked->revoke(Fixtures::now());
        $this->credentials->save($revoked);

        // When
        $options = $this->authentication->requestOptions($this->tenant, $this->alice);

        // Then
        static::assertCount(1, $options->allowCredentials);
        static::assertSame('alice-key', $options->allowCredentials[0]->id);
    }

    #[Test]
    public function aVerifiedAssertionOpensASessionOnWhatItProved(): void
    {
        // Given
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(userPresent: true, userVerified: true, signCount: 1));
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->authentication->authenticate($this->tenant, $this->options, '{}', $context);

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertSame(['hwk', 'user', 'mfa'], $session->methodReferences());
        static::assertSame('phrh', $session->authenticationContextClass()->value);
        static::assertSame($context, $session->createdFrom);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function aVerifiedAssertionRecordsTheUseOfThePasskey(): void
    {
        // Given
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(signCount: 3));

        // When
        $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(3, $this->passkey->signCount);
        static::assertEquals($this->clock->now(), $this->passkey->lastUsedAt);
    }

    #[Test]
    public function aVerifiedAssertionSavesThePasskey(): void
    {
        // Given
        $passkey = Fixtures::passkey($this->alice, credentialId: 'unsaved-key');
        $this->ceremony->verifies($passkey, Fixtures::authenticatorData(signCount: 3));

        // When
        $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($passkey, $this->credentials->find($passkey->id));
    }

    #[Test]
    public function aVerifiedAssertionAnnouncesTheUseThenTheAuthentication(): void
    {
        // Given
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(signCount: 3));
        $context = Fixtures::context($this->clock->now());

        // When
        $session = $this->authentication->authenticate($this->tenant, $this->options, '{}', $context);

        // Then
        static::assertCount(2, $this->events->events);
        $used = $this->events->of(PasskeyUsed::class)[0];
        static::assertSame($this->passkey, $used->credential);
        static::assertSame($context, $used->context);
        static::assertFalse($used->signCountRegressed);
        static::assertSame($session, $this->events->of(UserAuthenticated::class)[0]->session);
    }

    /**
     * WebAuthn Level 3 §6.1.1: a count that did not grow is told, never refused, a synced passkey keeps it at zero.
     */
    #[Test]
    public function aSignCountThatDidNotGrowIsToldNotRefused(): void
    {
        // Given
        $this->passkey->recordUse(Fixtures::authenticatorData(signCount: 5), Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData(signCount: 5));

        // When
        $session = $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($this->alice, $session->user);
        static::assertTrue($this->events->of(PasskeyUsed::class)[0]->signCountRegressed);
    }

    #[Test]
    public function aRefusedCeremonyFailsAndIsRecordedWithoutAUser(): void
    {
        // Given
        $this->ceremony->refuses('The signature is invalid.');
        $context = Fixtures::context($this->clock->now());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', $context);
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertNull($failed->method);
            static::assertNull($failed->identifier);
            static::assertNull($failed->user);
            static::assertSame($context, $failed->context);
            static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
        }
    }

    #[Test]
    public function aRevokedPasskeyIsRefusedAndRecordedWithItsUser(): void
    {
        // Given
        $this->passkey->revoke(Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::RevokedCredential, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertSame('hwk', $failed->method?->value);
            static::assertSame($this->alice, $failed->user);
            static::assertNull($this->passkey->lastUsedAt);
        }
    }

    /**
     * WebAuthn Level 3 §6.1.3: the BE flag of a credential never changes, so an assertion that claims
     * another one is refused after the signature was checked, with the key the passkey was enrolled as in
     * the trail and not the one the assertion claimed.
     */
    #[Test]
    public function anAssertionThatChangedItsBackupEligibilityIsRefused(): void
    {
        // Given
        $synced = Fixtures::passkey($this->alice, 'The phone', 'alice-phone', backupEligible: true, backedUp: true);
        $this->credentials->save($synced);
        $this->ceremony->verifies($synced, Fixtures::authenticatorData(signCount: 4));

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertSame('swk', $failed->method?->value);
            static::assertSame($this->alice, $failed->user);
            static::assertNull($synced->lastUsedAt);
            static::assertSame(0, $synced->signCount);
        }
    }

    #[Test]
    public function aDisabledUserIsRefused(): void
    {
        // Given
        $this->alice->disable(Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::DisabledUser, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertSame('hwk', $failed->method?->value);
            static::assertSame($this->alice, $failed->user);
        }
    }

    /**
     * Decision 0029, spec/saml.md S-63: a person of a domain the tenant federates signs in through its upstream
     * provider and through nothing else, a passkey refused after the signature, as a revoked one is.
     */
    #[Test]
    public function aPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $this->upstreamProviders->declare($this->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
        $this->ceremony->verifies($this->passkey, Fixtures::authenticatorData());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::FederatedDomain, $exception->reason);
            static::assertSame($this->alice, $this->events->of(AuthenticationFailed::class)[0]->user);
            static::assertSame([], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
        }
    }

    #[Test]
    public function aPasskeyOfAnotherTenantIsRefused(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->ceremony->verifies(Fixtures::passkey(Fixtures::user($other)), Fixtures::authenticatorData());

        // When
        try {
            $this->authentication->authenticate($this->tenant, $this->options, '{}', Fixtures::context($this->clock->now()));
            static::fail('Authentication should have failed.');
        } catch (AuthenticationFailedException $exception) {
            // Then
            static::assertSame(AuthenticationFailureReason::InvalidCredential, $exception->reason);
            $failed = $this->events->of(AuthenticationFailed::class)[0];
            static::assertSame('hwk', $failed->method?->value);
            static::assertNull($failed->user);
        }
    }
}
