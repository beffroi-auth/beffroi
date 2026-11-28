<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Group;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class GroupMembershipTest extends TestCase
{
    #[Test]
    public function aUserJoinsAGroupOfTheirOwnTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $group = new Group(Uuid::v7(), $tenant, 'admins', GroupSource::Local, Fixtures::now());

        // When
        $membership = new GroupMembership(Uuid::v7(), $group, Fixtures::user($tenant), GroupSource::Local, Fixtures::now());

        // Then
        static::assertSame($tenant, $membership->tenant);
    }

    #[Test]
    public function aMembershipFromUpstreamClaimsIsManaged(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $group = new Group(Uuid::v7(), $tenant, 'admins', GroupSource::Local, Fixtures::now());

        // When
        $membership = new GroupMembership(Uuid::v7(), $group, Fixtures::user($tenant), GroupSource::UpstreamClaims, Fixtures::now());

        // Then
        static::assertTrue($membership->source->isManaged());
    }

    #[Test]
    public function aLocalGroupIsNotManaged(): void
    {
        // When
        $group = new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());

        // Then
        static::assertFalse($group->source->isManaged());
    }

    #[Test]
    public function aUserCannotJoinAGroupOfAnotherTenant(): void
    {
        // Given
        $group = new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());
        $stranger = Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new GroupMembership(Uuid::v7(), $group, $stranger, GroupSource::Local, Fixtures::now());
    }

    #[Test]
    public function aGroupCanBeRenamed(): void
    {
        // Given
        $group = new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());

        // When
        $group->rename('administrators', Fixtures::now());

        // Then
        static::assertSame('administrators', $group->name);
    }

    #[Test]
    public function aGroupCannotBeRenamedToNothing(): void
    {
        // Given
        $group = new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $group->rename('', Fixtures::now());
    }

    #[Test]
    public function aGroupNameIsNeverEmpty(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Group(Uuid::v7(), Fixtures::tenant(), '', GroupSource::Local, Fixtures::now());
    }
}
