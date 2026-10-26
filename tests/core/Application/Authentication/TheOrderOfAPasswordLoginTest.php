<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use function count;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Authentication\AuthenticationRefusal;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Authentication\PasswordVerification;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Authentication\PasswordAuthenticator;
use Beffroi\Core\Application\Authentication\SecondFactorRequirement;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakeAttemptLimiter;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\TheOrderOfAPasswordLogin;
use DateInterval;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #130: the order of a login by password, played by the use case of the core. The firewall of the
 * bundle asks the same of itself (TheOrderOfAPasswordLoginTest of the functional suite), and the two read
 * the same named steps (TheOrderOfAPasswordLogin), so a step this path gains and the other does not is a
 * case the other answers differently.
 *
 * This is the path that can be asked what a refusal cost, the hasher of the fixtures recording every
 * verification: what the firewall can be asked is what was announced.
 */
final class TheOrderOfAPasswordLoginTest extends TestCase
{
    private Tenant $tenant;

    private FakePasswordHasher $hasher;

    private RecordingEventDispatcher $events;

    private PasswordAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $clock = new MockClock(Fixtures::now());
        $users = new InMemoryUserRepository();
        $credentials = new InMemoryCredentialRepository();

        $alice = Fixtures::user($this->tenant, TheOrderOfAPasswordLogin::USERNAME, 'alice-subject');
        $users->save($alice);
        $credentials->save(new PasswordCredential(Uuid::v7(), $alice, $this->hasher->hash(TheOrderOfAPasswordLogin::PASSWORD), Fixtures::now()));
        // a person of the same tenant who holds no password at all
        $users->save(Fixtures::user($this->tenant, TheOrderOfAPasswordLogin::WITHOUT_A_PASSWORD, 'bob-subject'));
        $disabled = Fixtures::user($this->tenant, TheOrderOfAPasswordLogin::DISABLED, 'carol-subject');
        $disabled->disable(Fixtures::now());
        $users->save($disabled);
        $credentials->save(new PasswordCredential(Uuid::v7(), $disabled, $this->hasher->hash(TheOrderOfAPasswordLogin::PASSWORD), Fixtures::now()));

        $this->authenticator = new PasswordAuthenticator(
            new PasswordVerification(
                $users,
                $credentials,
                new ActivePassword(new ActiveCredentials($credentials)),
                $this->hasher,
                new DecoyHash($this->hasher, new SymfonyUuidGenerator()),
                new FakeAttemptLimiter(5),
                new AuthenticationRefusal($clock, $this->events),
                $clock,
                $this->events,
                new FederatedDomains(new InMemoryUpstreamProviders()),
            ),
            new SessionOpener(
                new InMemoryAuthenticationSessionRepository(),
                new SymfonyUuidGenerator(),
                $clock,
                $this->events,
                new AuthenticationRefusal($clock, $this->events),
                new DateInterval('PT8H'),
            ),
            new SecondFactorRequirement(new ActiveCredentials($credentials)),
            $clock,
        );
    }

    #[Test]
    #[DataProviderExternal(TheOrderOfAPasswordLogin::class, 'steps')]
    public function aLoginAnswersEachStepOfTheOrderAsTheOrderSaysItDoes(
        string $username,
        string $password,
        ?AuthenticationFailureReason $reason,
    ): void {
        // Given
        $verified = count($this->hasher->verifiedAgainst);

        // When
        try {
            $this->authenticator->authenticate($this->tenant, $username, $password, Fixtures::context());
        } catch (AuthenticationFailedException) {
        }

        // Then
        static::assertSame($reason, $this->events->of(AuthenticationFailed::class)[0]->reason ?? null);
        static::assertSame(
            1,
            count($this->hasher->verifiedAgainst) - $verified,
            'Every step pays one hash verification, the decoy of decision 0006 where the password of the user was never read.',
        );
    }

    /**
     * The last step of the order, read on its own because what it leaves behind is a session and not a
     * refusal: the password is announced as the act it is, and the session as the outcome.
     */
    #[Test]
    public function theRightPasswordOpensASessionAndSaysWhatProvedIt(): void
    {
        // When
        $this->authenticator->authenticate(
            $this->tenant,
            TheOrderOfAPasswordLogin::USERNAME,
            TheOrderOfAPasswordLogin::PASSWORD,
            Fixtures::context(),
        );

        // Then
        static::assertCount(1, $this->events->of(PasswordUsed::class));
        static::assertCount(1, $this->events->of(UserAuthenticated::class));
    }
}
