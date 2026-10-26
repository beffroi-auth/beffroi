<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Totp;

use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use function array_map;
use function array_unique;
use Beffroi\Core\Application\Totp\BackupCodeSet;
use Beffroi\Core\Application\Totp\BackupCodesRenewal;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Event\BackupCodesRenewed;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.1: another set of backup codes for the second factor a person already holds, the ones
 * they had stopping at that instant.
 */
final class BackupCodesRenewalTest extends TestCase
{
    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasswordHasher $hasher;

    private RecordingEventDispatcher $events;

    private BackupCodesRenewal $renewal;

    private InMemoryUpstreamProviders $upstreamProviders;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $this->upstreamProviders = new InMemoryUpstreamProviders();
        $this->renewal = new BackupCodesRenewal(
            $this->credentials,
            new BackupCodeSet(new PlatformRandomness(), $this->hasher),
            new MockClock('2026-09-15T13:00:00+00:00'),
            $this->events,
            new EnrolmentRefusal(new FederatedDomains($this->upstreamProviders)),
        );
    }

    #[Test]
    public function itGivesBackAsManyCodesAsTheCredentialHolds(): void
    {
        // Given
        $totp = $this->totp();

        // When
        $spelled = $this->renewal->renew($totp, Fixtures::context());

        // Then
        static::assertCount(TotpCredential::BACKUP_CODES, $spelled);
        static::assertCount(TotpCredential::BACKUP_CODES, array_unique($spelled));
    }

    /**
     * What is stored is the hash of each one, as a password is, and the codes they had stop working at
     * that instant, spent or not.
     */
    #[Test]
    public function theCodesItGivesBackAreTheOnesTheCredentialHoldsAndTheOldOnesAreGone(): void
    {
        // Given
        $totp = $this->totp();
        $before = array_map(static fn (BackupCode $code): string => $code->hash->encoded, $totp->backupCodes);

        // When
        $spelled = $this->renewal->renew($totp, Fixtures::context());

        // Then
        $after = array_map(static fn (BackupCode $code): string => $code->hash->encoded, $totp->backupCodes);
        static::assertSame(
            array_map(fn (string $code): string => $this->hasher->hash(BackupCode::normalize($code))->encoded, $spelled),
            $after,
        );
        static::assertCount(TotpCredential::BACKUP_CODES * 2, array_unique([...$before, ...$after]));
    }

    /**
     * A code that was spent is replaced like the others: what asking for new ones means is that the list
     * somebody held is worth nothing now.
     */
    #[Test]
    public function aSpentCodeIsReplacedLikeTheOthers(): void
    {
        // Given
        $totp = $this->totp();
        $totp->spendBackupCode(0, Fixtures::now());

        // When
        $this->renewal->renew($totp, Fixtures::context());

        // Then
        static::assertCount(0, array_filter($totp->backupCodes, static fn (BackupCode $code): bool => $code->isSpent()));
    }

    /**
     * Somebody who finds an old list on paper is reading the one line of their journal that tells them
     * why it is refused.
     */
    #[Test]
    public function renewingAnnouncesTheAct(): void
    {
        // Given
        $totp = $this->totp();

        // When
        $this->renewal->renew($totp, Fixtures::context());

        // Then
        $announced = $this->events->of(BackupCodesRenewed::class);
        static::assertCount(1, $announced);
        static::assertSame($totp, $announced[0]->credential);
    }

    #[Test]
    public function aRevokedCredentialIsNotRenewed(): void
    {
        // Given
        $totp = $this->totp();
        $totp->revoke(Fixtures::now());

        // Then
        $this->expectException(LogicException::class);

        // When
        $this->renewal->renew($totp, Fixtures::context());
    }

    /**
     * Decision 0029, spec/saml.md S-63: a person whose e-mail domain the tenant federated since they enrolled a TOTP is
     * drawn no backup code, which would be a way in posed for them.
     */
    #[Test]
    public function noBackupCodeIsDrawnForAPersonOfAFederatedDomain(): void
    {
        // Given
        $totp = $this->totp();
        $this->upstreamProviders->declare($this->alice->tenant, new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]));
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A set of backup codes is posed for nobody of an e-mail domain the tenant "acme" federates to an upstream provider, through which alone they sign in.');

        // When
        $this->renewal->renew($totp, Fixtures::context());
    }

    private function totp(): TotpCredential
    {
        $totp = Totps::credential($this->alice, $this->hasher);
        $this->credentials->save($totp);

        return $totp;
    }
}
