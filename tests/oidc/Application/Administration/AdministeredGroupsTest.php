<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Administration;

use function array_map;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupRepository;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Administration\AdministeredGroups;
use Beffroi\Oidc\Application\Administration\PersonsDelivered;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\MembershipReadByAnAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Beffroi\Oidc\Tests\Fixture\FakePersonsBudget;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0022 and 0038, the members of a group read a page at a time; decision 0014, the budget of the persons an
 * administrator reads.
 */
final class AdministeredGroupsTest extends TestCase
{
    private Tenant $tenant;

    private Group $group;

    private InMemoryGroupMembershipRepository $memberships;

    private FakePersonsBudget $budget;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->group = new Group(Uuid::v7(), $this->tenant, 'staff', GroupSource::Local, Fixtures::now());
        $this->memberships = new InMemoryGroupMembershipRepository();
        for ($member = 1; $member <= 5; ++$member) {
            $this->memberships->save(new GroupMembership(
                Uuid::v7(),
                $this->group,
                Fixtures::user($this->tenant, sprintf('member-%d', $member), sprintf('member-%d-subject', $member)),
                GroupSource::Local,
                Fixtures::now()->modify(sprintf('+%d minutes', $member)),
            ));
        }
        $this->budget = new FakePersonsBudget(3);
        $this->events = new RecordingEventDispatcher();
    }

    #[Test]
    public function aPageHoldsTheMembersOfThatPageInTheOrderTheyWereAdded(): void
    {
        // When
        $page = $this->members(new Pagination(2, 2));

        // Then
        static::assertSame(
            [['member-3', 'member-4'], 5],
            [array_map(static fn (GroupMembership $membership): string => $membership->user->username, $page->rows ?? []), $page?->total],
        );
    }

    #[Test]
    public function aPageSpendsOnePersonOfTheBudgetForEachMember(): void
    {
        // When
        $this->members(new Pagination(1, 2));

        // Then
        static::assertSame(['administrator-subject' => 2], $this->budget->spent);
    }

    #[Test]
    public function eachMemberOfThePageIsAnActOfTheirsThatNamesTheAdministrator(): void
    {
        // When
        $this->members(new Pagination(1, 2));

        // Then
        static::assertSame(
            [
                ['member-1-subject', 'administrator-subject'],
                ['member-2-subject', 'administrator-subject'],
            ],
            array_map(
                static fn (MembershipReadByAnAdministrator $read): array => [$read->subject()->value, $read->administrator->value],
                $this->events->of(MembershipReadByAnAdministrator::class),
            ),
        );
    }

    #[Test]
    public function aPagePastTheLastOneDeliversNobody(): void
    {
        // When
        $page = $this->members(new Pagination(4, 2));

        // Then
        static::assertSame([[], 4, 5, [], []], [
            $page?->rows,
            $page?->pagination->number,
            $page?->total,
            $this->budget->spent,
            $this->events->events,
        ]);
    }

    #[Test]
    public function aPageLargerThanWhatTheBudgetHasLeftIsRefused(): void
    {
        // Then
        $this->expectException(PersonsBudgetSpentException::class);

        // When
        $this->members(new Pagination(1, 4));
    }

    #[Test]
    public function aRefusedPageWritesNoMemberAsRead(): void
    {
        // When
        try {
            $this->members(new Pagination(1, 4));
        } catch (PersonsBudgetSpentException) {
        }

        // Then
        static::assertSame([], $this->events->of(MembershipReadByAnAdministrator::class));
    }

    #[Test]
    public function aGroupTheTenantDoesNotHoldIsNobody(): void
    {
        // Given
        $groups = $this->administeredGroups();

        // When
        $members = $groups->members($this->administrator(), Uuid::v7(), new Pagination(1, 2), Fixtures::context());

        // Then
        static::assertNull($members);
    }

    /**
     * @return Listing<GroupMembership>|null
     */
    private function members(Pagination $page): ?Listing
    {
        return $this->administeredGroups()->members($this->administrator(), $this->group->id, $page, Fixtures::context());
    }

    private function administeredGroups(): AdministeredGroups
    {
        $groups = new InMemoryGroupRepository();
        $groups->save($this->group);

        return new AdministeredGroups(
            $groups,
            $this->memberships,
            new ConfigurationAdministratorGroups($this->tenant->slug),
            $this->events,
            new PersonsDelivered($this->budget, $this->events),
        );
    }

    private function administrator(): ActingAdministrator
    {
        return new ActingAdministrator($this->tenant, Fixtures::user($this->tenant, 'administrator', 'administrator-subject'), 'beffroi-tui', Uuid::v7());
    }
}
