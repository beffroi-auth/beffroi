<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Tenant;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Application\Tenant\TenantContactAdoption;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantRepository;
use Beffroi\Core\Domain\Event\TenantContactChanged;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Tenant\TenantContact;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class TenantContactAdoptionTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantRepository $tenants;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private Subject $administrator;

    private TenantContactAdoption $adoption;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->tenants = new InMemoryTenantRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-11-22T10:00:00+00:00');
        $this->administrator = new Subject('administrator-subject');
        $this->adoption = new TenantContactAdoption($this->tenants, $this->clock, $this->events);
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function theTenantHoldsTheContactItWasGiven(): void
    {
        // When
        $this->adoption->adoptByAnAdministrator($this->tenant, new TenantContact('security@acme.example'), $this->administrator, Fixtures::context());

        // Then
        static::assertSame('security@acme.example', $this->saved()?->contact?->value);
    }

    #[Test]
    public function aContactTakenBackLeavesTheTenantWithout(): void
    {
        // Given
        $this->tenant->adoptContact(new TenantContact('security@acme.example'));

        // When
        $this->adoption->adoptByAnAdministrator($this->tenant, null, $this->administrator, Fixtures::context());

        // Then
        static::assertSame([$this->tenant, null], [$this->saved(), $this->tenant->contact]);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theChangeIsAnActOfTheTenantThatNamesTheAdministrator(): void
    {
        // Given
        $context = Fixtures::context($this->clock->now());

        // When
        $this->adoption->adoptByAnAdministrator($this->tenant, new TenantContact('security@acme.example'), $this->administrator, $context);

        // Then
        $acts = $this->events->of(TenantContactChanged::class);
        static::assertCount(1, $acts);
        static::assertEquals([$this->tenant, new AnAdministrator($this->administrator), $context], [$acts[0]->tenant, $acts[0]->author(), $acts[0]->context]);
        static::assertEquals($this->clock->now(), $acts[0]->occurredAt);
    }

    #[Test]
    public function theContactTheTenantHoldsAlreadyChangesNothing(): void
    {
        // Given
        $this->tenant->adoptContact(new TenantContact('security@acme.example'));

        // When
        $this->adoption->adoptByAnAdministrator($this->tenant, new TenantContact('security@acme.example'), $this->administrator, Fixtures::context());

        // Then
        static::assertSame([null, []], [$this->saved(), $this->events->events]);
    }

    #[Test]
    public function noContactTakenFromATenantThatHeldNoneChangesNothing(): void
    {
        // When
        $this->adoption->adoptByAnAdministrator($this->tenant, null, $this->administrator, Fixtures::context());

        // Then
        static::assertSame([null, []], [$this->saved(), $this->events->events]);
    }

    private function saved(): ?Tenant
    {
        return $this->tenants->tenants[$this->tenant->id->toRfc4122()] ?? null;
    }
}
