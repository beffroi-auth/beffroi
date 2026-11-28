<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateTimeImmutable;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\Registration\RegisteredClientRemoval;
use Beffroi\Oidc\Application\Client\Registration\UnusedClientRemoval;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientRetentionPolicyInterface;
use Beffroi\Oidc\Tests\Fixture\RegistrationPolicies;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0009
 */
final class UnusedClientRemovalTest extends TestCase
{
    private const string UNUSED_FOR = '+90 days';

    private const string NEVER_USED_FOR = '+7 days';

    private Tenant $tenant;

    private InMemoryClientStore $clients;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientStore();
        $this->events = new RecordingEventDispatcher();
    }

    #[Test]
    public function aClientUsedWithinTheDurationItsPolicyNamesIsThere(): void
    {
        // Given
        $this->register('used-lately', lastUsedAt: Fixtures::now());

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::UNUSED_FOR)->modify('-1 second'));

        // Then
        static::assertSame([], $removed);
    }

    #[Test]
    public function aClientNobodyUsedForLongerThanItsPolicyNamesIsGone(): void
    {
        // Given
        $this->register('used-long-ago', lastUsedAt: Fixtures::now());

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::UNUSED_FOR)->modify('+1 second'));

        // Then
        static::assertSame(['used-long-ago'], $removed);
        static::assertNull($this->clients->findRecord($this->tenant, 'used-long-ago'));
    }

    #[Test]
    public function aClientNobodyEverUsedGoesOnTheShorterDuration(): void
    {
        // Given
        $this->register('never-used');

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'));

        // Then
        static::assertSame(['never-used'], $removed);
    }

    #[Test]
    public function aClientNobodyEverUsedIsThereUntilThen(): void
    {
        // Given
        $this->register('never-used');

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('-1 second'));

        // Then
        static::assertSame([], $removed);
    }

    #[Test]
    public function eachClientRemovedIsAnnouncedByTheOneEventAClientGoingAwayEmits(): void
    {
        // Given
        $this->register('never-used');

        // When
        $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'));

        // Then
        $events = $this->events->of(RegisteredClientDeleted::class);
        static::assertCount(1, $events);
        static::assertSame('never-used', $events[0]->clientId);
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function aClientRemovedForGoingUnusedNamesTheHostAsTheAuthorOfItsRemoval(): void
    {
        // Given
        $this->register('never-used');

        // When
        $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'));

        // Then
        static::assertEquals(new TheHost(), $this->events->of(RegisteredClientDeleted::class)[0]->author());
    }

    #[Test]
    public function aRunRemovesAtMostWhatItIsBoundedTo(): void
    {
        // Given
        for ($drawn = 0; $drawn < 5; $drawn++) {
            $this->register(sprintf('never-used-%d', $drawn));
        }

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'), 2);

        // Then
        static::assertCount(2, $removed);
        static::assertCount(3, $this->clients->records);
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aTenantThatNoLongerRegistersStillDropsWhatItRegistered(): void
    {
        // Given
        $this->register('never-used');

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify('+1 year'), retentions: RegistrationPolicies::closed());

        // Then
        static::assertSame(['never-used'], $removed);
    }

    #[Test]
    public function aClientOfAnotherTenantIsNotDropped(): void
    {
        // Given
        $this->register('never-used', tenant: Fixtures::tenant('other', 'https://id.other.example'));

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify('+1 year'));

        // Then
        static::assertSame([], $removed);
    }

    private function register(string $clientId, ?DateTimeImmutable $lastUsedAt = null, ?Tenant $tenant = null): void
    {
        $record = new ClientRecord(
            Uuid::v7(),
            $tenant ?? $this->tenant,
            $clientId,
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
            DrawnSecret::digestOf(Secrets::draw()),
            Fixtures::now(),
        );
        if ($lastUsedAt !== null) {
            $record->recordUse($lastUsedAt);
        }
        $this->clients->save($record);
    }

    /**
     * @return list<string>
     */
    private function removeUnusedAt(
        DateTimeImmutable $now,
        int $perRun = UnusedClientRemoval::PER_RUN,
        ?ClientRetentionPolicyInterface $retentions = null,
    ): array {
        return new UnusedClientRemoval(
            [$this->clients],
            $retentions ?? RegistrationPolicies::controlled(),
            new RegisteredClientRemoval($this->clients, $this->events),
            new MockClock($now),
            $perRun,
        )->removeUnused($this->tenant, Fixtures::context($now));
    }
}
