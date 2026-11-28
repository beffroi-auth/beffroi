<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Group;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class GroupVersionTest extends TestCase
{
    /**
     * RFC 7643 §3.1
     */
    #[Test]
    public function aGroupCreatedIsAtTheFirstVersionLastChangedWhenCreated(): void
    {
        // When
        $group = self::admins();

        // Then
        static::assertSame([1, $group->createdAt], [$group->version, $group->updatedAt]);
    }

    /**
     * RFC 7644 §3.14, RFC 7232 §2.1, RFC 7643 §3.1 and §4.2
     *
     * @param Closure(Group, DateTimeImmutable): void $change
     */
    #[Test]
    #[DataProvider('provideChanges')]
    public function everyChangeOfAGroupRaisesItsVersionOnceAndDatesIt(Closure $change): void
    {
        // Given
        $group = self::admins();
        $later = Fixtures::now()->modify('+1 hour');

        // When
        $change($group, $later);

        // Then
        static::assertSame([2, $later], [$group->version, $group->updatedAt]);
    }

    /**
     * @return iterable<string, array{Closure(Group, DateTimeImmutable): void}>
     */
    public static function provideChanges(): iterable
    {
        yield 'renamed' => [static fn (Group $group, DateTimeImmutable $now) => $group->rename('administrators', $now)];
        yield 'a member joined or left' => [static fn (Group $group, DateTimeImmutable $now) => $group->membershipChanged($now)];
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §3.1
     */
    #[Test]
    public function aGroupRenamedToTheNameItBearsChangesNothing(): void
    {
        // Given
        $group = self::admins();

        // When
        $group->rename('admins', Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertSame([1, $group->createdAt], [$group->version, $group->updatedAt]);
    }

    private static function admins(): Group
    {
        return new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());
    }
}
