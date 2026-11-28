<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Tests\Fixture\FakeChannelChangeWindow;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Identity\PersonCreation;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Event\PersonCreated;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\FixedClaims;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class PersonCreationTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryUserRepository $users;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PersonCreation $creation;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->users = new InMemoryUserRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-11-17T12:00:00+00:00');
        $credentials = new InMemoryCredentialRepository();
        $this->creation = new PersonCreation(
            new UserProvisioner(
                $this->users,
                $credentials,
                new ActivePassword(new ActiveCredentials($credentials)),
                new NativePasswordHasher(),
                new BreachedPasswordRefusal(BreachedPasswordsOfARecord::holding([])),
                new EnrolmentRefusal(new FederatedDomains(new InMemoryUpstreamProviders())),
                new SymfonyUuidGenerator(),
                $this->clock,
                new FixedClaims([]),
                new ChannelChangeNotice(new FakeChannelChangeWindow(), new RecordingCredentialChangeNotifier()),
            ),
            $this->events,
        );
    }

    #[Test]
    public function thePersonIsCreatedWithWhatTheOperatorSaidOfThem(): void
    {
        // When
        $user = $this->creation->create(
            $this->tenant,
            'alice',
            Fixtures::context($this->clock->now()),
            new EmailAddress('alice@example.com'),
            true,
        );

        // Then
        static::assertSame($user, $this->users->findByUsername($this->tenant, 'alice'));
        static::assertSame('alice@example.com', (string) $user->email);
        static::assertTrue($user->emailVerified);
    }

    /**
     * Decision 0022.
     */
    #[Test]
    public function theCreationIsAnActOfTheirAccountThatNamesNoAuthorWhenTheOperatorDidIt(): void
    {
        // When
        $user = $this->creation->create($this->tenant, 'alice', Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(PersonCreated::class);
        static::assertCount(1, $acts);
        static::assertSame($user->subject, $acts[0]->subject());
        static::assertEquals($this->clock->now(), $acts[0]->occurredAt);
        static::assertNull($acts[0]->author());
    }

    /**
     * Decision 0038.
     */
    #[Test]
    public function theActOfAPersonAnAdministratorCreatedNamesThem(): void
    {
        // Given
        $administrator = new Subject('administrator-subject');

        // When
        $user = $this->creation->createByAnAdministrator($this->tenant, 'alice', $administrator, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(PersonCreated::class);
        static::assertCount(1, $acts);
        static::assertSame($user->subject, $acts[0]->subject());
        static::assertSame($administrator, $acts[0]->author());
    }

    #[Test]
    public function aUsernameTakenAlreadyCreatesNobodyAndWritesNoAct(): void
    {
        // Given
        $this->creation->create($this->tenant, 'alice', Fixtures::context($this->clock->now()));

        // When
        try {
            $this->creation->createByAnAdministrator($this->tenant, 'alice', new Subject('administrator-subject'), Fixtures::context($this->clock->now()));
            static::fail('A username taken already is refused.');
        } catch (UserAlreadyExistsException) {
        }

        // Then
        static::assertCount(1, $this->events->of(PersonCreated::class));
    }
}
