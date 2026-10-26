<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Group;

use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002, issue #782: at each sign-in through an upstream provider, the memberships of source
 * `upstream_claims` are replaced by the groups the provider asserts, mapped to the groups of the tenant by its
 * declaration; the memberships of another source are left as they are.
 */
final class UpstreamMembershipsTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private Group $admins;

    private Group $sales;

    private GroupMapping $mapping;

    private InMemoryGroupMembershipRepository $memberships;

    private MockClock $clock;

    private UpstreamMemberships $upstream;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->admins = new Group(Uuid::v7(), $this->tenant, 'admins', GroupSource::Local, Fixtures::now());
        $this->sales = new Group(Uuid::v7(), $this->tenant, 'sales', GroupSource::Local, Fixtures::now());
        $this->mapping = new GroupMapping([
            'admins-guid' => $this->admins,
            'sales-guid' => $this->sales,
        ]);
        $this->memberships = new InMemoryGroupMembershipRepository();
        $this->clock = new MockClock('2026-10-22T12:00:00+00:00');
        $this->upstream = new UpstreamMemberships($this->memberships, $this->memberships, new SymfonyUuidGenerator(), $this->clock);
    }

    #[Test]
    public function aPersonWhoseProviderAssertsAMappedValueJoinsItsGroup(): void
    {
        // When
        $this->upstream->replace($this->user, ['sales-guid'], $this->mapping);

        // Then
        $memberships = $this->memberships->of($this->user);
        static::assertCount(1, $memberships);
        static::assertSame($this->sales, $memberships[0]->group);
        static::assertSame($this->user, $memberships[0]->user);
        static::assertSame(GroupSource::UpstreamClaims, $memberships[0]->source);
        static::assertEquals($this->clock->now(), $memberships[0]->addedAt);
    }

    #[Test]
    public function theValueGoneAtTheNextSignInTakesTheMembershipAway(): void
    {
        // Given
        $this->upstream->replace($this->user, ['admins-guid', 'sales-guid'], $this->mapping);

        // When
        $this->upstream->replace($this->user, ['admins-guid'], $this->mapping);

        // Then
        static::assertSame(['admins'], $this->groupsOfTheUser());
    }

    #[Test]
    #[DataProvider('provideSourcesASignInLeaves')]
    public function aMembershipOfAnotherSourceSurvivesASignIn(GroupSource $source): void
    {
        // Given
        $this->memberships->save(new GroupMembership(Uuid::v7(), $this->admins, $this->user, $source, Fixtures::now()));

        // When
        $this->upstream->replace($this->user, ['sales-guid'], $this->mapping);

        // Then
        static::assertSame(
            [
                'admins' => $source,
                'sales' => GroupSource::UpstreamClaims,
            ],
            $this->sourcesOfTheUser(),
        );
    }

    /**
     * @return iterable<string, array{GroupSource}>
     */
    public static function provideSourcesASignInLeaves(): iterable
    {
        yield 'local' => [GroupSource::Local];
        yield 'scim' => [GroupSource::Scim];
    }

    /**
     * A group is never created from what a provider sends, and neither is a membership.
     */
    #[Test]
    public function anUnmappedValueCreatesNothing(): void
    {
        // When
        $this->upstream->replace($this->user, ['interns-guid'], $this->mapping);

        // Then
        static::assertSame([], $this->memberships->of($this->user));
    }

    /**
     * The table holds one membership per group and person, and the one a hand gave is not the provider's to
     * take away later.
     */
    #[Test]
    public function aMappedGroupThePersonHoldsLocallyStaysLocal(): void
    {
        // Given
        $local = new GroupMembership(Uuid::v7(), $this->admins, $this->user, GroupSource::Local, Fixtures::now());
        $this->memberships->save($local);

        // When
        $this->upstream->replace($this->user, ['admins-guid'], $this->mapping);

        // Then
        static::assertSame([$local], $this->memberships->of($this->user));
    }

    #[Test]
    public function aMembershipStillAssertedIsKeptWithItsDate(): void
    {
        // Given
        $this->upstream->replace($this->user, ['admins-guid'], $this->mapping);
        $first = $this->memberships->of($this->user)[0];
        $this->clock->modify('+1 day');

        // When
        $this->upstream->replace($this->user, ['admins-guid'], $this->mapping);

        // Then
        static::assertSame([$first], $this->memberships->of($this->user));
    }

    #[Test]
    public function twoValuesThatNameOneGroupGiveOneMembership(): void
    {
        // Given
        $mapping = new GroupMapping([
            'engineering-guid' => $this->admins,
            'admins-guid' => $this->admins,
        ]);

        // When
        $this->upstream->replace($this->user, ['engineering-guid', 'admins-guid'], $mapping);

        // Then
        static::assertSame(['admins'], $this->groupsOfTheUser());
    }

    #[Test]
    public function theMembershipsOfAnotherPersonAreLeftAsTheyAre(): void
    {
        // Given
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->upstream->replace($bob, ['sales-guid'], $this->mapping);

        // When
        $this->upstream->replace($this->user, [], $this->mapping);

        // Then
        static::assertCount(1, $this->memberships->of($bob));
    }

    /**
     * GroupMembership refuses a group of another tenant, which a mapping wired for the wrong tenant leads to.
     */
    #[Test]
    public function aMappingLeadingToAGroupOfAnotherTenantIsRefused(): void
    {
        // Given
        $foreign = new Group(Uuid::v7(), Fixtures::tenant('other', 'https://id.other.example'), 'admins', GroupSource::Local, Fixtures::now());
        $mapping = new GroupMapping([
            'foreign-guid' => $foreign,
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A user can only belong to a group of their own tenant.');

        // When
        $this->upstream->replace($this->user, ['foreign-guid'], $mapping);
    }

    /**
     * The refusal comes before any write, so the person keeps what the last sign-in gave.
     */
    #[Test]
    public function aMappingLeadingToAGroupOfAnotherTenantWritesNothing(): void
    {
        // Given
        $this->upstream->replace($this->user, ['sales-guid'], $this->mapping);
        $foreign = new Group(Uuid::v7(), Fixtures::tenant('other', 'https://id.other.example'), 'admins', GroupSource::Local, Fixtures::now());
        $mapping = new GroupMapping([
            'foreign-guid' => $foreign,
        ]);

        // When
        try {
            $this->upstream->replace($this->user, ['foreign-guid'], $mapping);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame(['sales'], $this->groupsOfTheUser());
    }

    /**
     * @return list<string>
     */
    private function groupsOfTheUser(): array
    {
        return array_map(static fn (GroupMembership $membership): string => $membership->group->name, $this->memberships->of($this->user));
    }

    /**
     * @return array<string, GroupSource>
     */
    private function sourcesOfTheUser(): array
    {
        $sources = [];
        foreach ($this->memberships->of($this->user) as $membership) {
            $sources[$membership->group->name] = $membership->source;
        }

        return $sources;
    }
}
