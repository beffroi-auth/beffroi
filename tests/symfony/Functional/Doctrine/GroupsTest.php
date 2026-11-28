<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Exception\GroupAlreadyExistsException;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfATenantInterface;
use function array_map;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002
 */
final class GroupsTest extends DatabaseTestCase
{
    #[Test]
    public function aGroupSavedIsFoundByItsName(): void
    {
        // Given
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now());
        self::groupsOfTheTenant()->save($group);
        self::reload();

        // When
        $found = self::groupsOfTheTenant()->findByName(self::tenant(), 'admins');

        // Then
        static::assertNotNull($found);
        static::assertTrue($found->id->equals($group->id));
        static::assertSame(GroupSource::Local, $found->source);
    }

    #[Test]
    #[DataProvider('provideOtherNames')]
    public function anotherNameFindsNothing(string $name): void
    {
        // Given
        self::groupsOfTheTenant()->save(new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now()));
        self::reload();

        // When / Then
        static::assertNull(self::groupsOfTheTenant()->findByName(self::tenant(), $name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherNames(): iterable
    {
        yield 'another case' => ['Admins'];
        yield 'another name' => ['sales'];
    }

    #[Test]
    public function aSecondGroupOfTheSameNameIsRefusedByTheTable(): void
    {
        // Given
        self::groupsOfTheTenant()->save(new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now()));

        // When
        try {
            self::groupsOfTheTenant()->save(new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now()));
            static::fail('A second group of the same name was written.');
        } catch (GroupAlreadyExistsException $exception) {
            // Then
            static::assertSame('A group named "admins" already exists in this tenant.', $exception->getMessage());
            static::assertInstanceOf(UniqueConstraintViolationException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function theGroupsOfATenantAreListedByName(): void
    {
        // Given
        self::groupsOfTheTenant()->save(new Group(Uuid::v7(), self::tenant(), 'staff', GroupSource::Local, self::now()));
        self::groupsOfTheTenant()->save(new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now()));
        self::reload();

        // When
        $groups = self::listedGroups()->of(self::tenant());

        // Then
        static::assertSame(['admins', 'staff'], array_map(static fn (Group $group): string => $group->name, $groups));
    }

    #[Test]
    public function aGroupIsFoundByItsIdentifierInItsTenant(): void
    {
        // Given
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now());
        self::groupsOfTheTenant()->save($group);
        self::reload();

        // When
        $found = self::listedGroups()->find(self::tenant(), $group->id);

        // Then
        static::assertTrue($found?->id->equals($group->id));
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §3.1
     */
    #[Test]
    public function theVersionAndTheLastChangeOfARenamingAreWrittenOnSave(): void
    {
        // Given
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now());
        self::groupsOfTheTenant()->save($group);
        $group->rename('administrators', self::now()->modify('+1 hour'));
        self::groupsOfTheTenant()->save($group);
        self::reload();

        // When
        $found = self::listedGroups()->find(self::tenant(), $group->id) ?? static::fail('The group was not stored.');

        // Then
        static::assertEquals([2, self::now()->modify('+1 hour')], [$found->version, $found->updatedAt]);
    }

    private static function listedGroups(): GroupsOfATenantInterface
    {
        return self::service('test.beffroi.groups_of_a_tenant', GroupsOfATenantInterface::class);
    }

    private static function groupsOfTheTenant(): GroupRepositoryInterface
    {
        return self::service('test.beffroi.groups', GroupRepositoryInterface::class);
    }
}
