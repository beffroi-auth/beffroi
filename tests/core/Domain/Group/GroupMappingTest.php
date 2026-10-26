<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Group;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002, issue #782: what the declaration of an upstream provider makes of the values it asserts for
 * groups. A value leads to a group of the tenant only when the declaration names it.
 */
final class GroupMappingTest extends TestCase
{
    #[Test]
    public function theValuesItNamesLeadToTheirGroupsInTheOrderTheyAreAsserted(): void
    {
        // Given
        $admins = self::group('admins');
        $sales = self::group('sales');
        $mapping = new GroupMapping([
            'admins-guid' => $admins,
            'sales-guid' => $sales,
        ]);

        // When
        $groups = $mapping->groupsOf(['sales-guid', 'admins-guid']);

        // Then
        static::assertSame([$sales, $admins], $groups);
    }

    /**
     * A group is never created from what a provider sends: a value nobody declared is nothing.
     */
    #[Test]
    public function aValueItDoesNotNameIsIgnored(): void
    {
        // Given
        $admins = self::group('admins');
        $mapping = new GroupMapping([
            'admins-guid' => $admins,
        ]);

        // When
        $groups = $mapping->groupsOf(['interns-guid', 'admins-guid']);

        // Then
        static::assertSame([$admins], $groups);
    }

    #[Test]
    #[DataProvider('provideValuesThatAreNotTheDeclaredOne')]
    public function aValueIsComparedByteForByte(string $asserted): void
    {
        // Given
        $mapping = new GroupMapping([
            'admins-guid' => self::group('admins'),
        ]);

        // When / Then
        static::assertSame([], $mapping->groupsOf([$asserted]));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatAreNotTheDeclaredOne(): iterable
    {
        yield 'another case' => ['ADMINS-GUID'];
        yield 'a surrounding space' => [' admins-guid'];
        yield 'a prefix of it' => ['admins'];
    }

    /**
     * PHP keys the declared value "1" by the integer 1: what a provider sent is a value only when it is a
     * string, so nothing else reaches that key.
     */
    #[Test]
    #[DataProvider('provideAssertedValuesThatAreNotStrings')]
    public function anAssertedValueThatIsNotAStringIsIgnored(mixed $asserted): void
    {
        // Given
        $mapping = new GroupMapping([
            '1' => self::group('admins'),
        ]);

        // When / Then
        static::assertSame([], $mapping->groupsOf([$asserted]));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideAssertedValuesThatAreNotStrings(): iterable
    {
        yield 'true' => [true];
        yield 'the integer 1' => [1];
        yield 'the float 1.0' => [1.0];
        yield 'a list' => [['1']];
        yield 'null' => [null];
    }

    #[Test]
    public function aDeclaredValueOfDigitsIsFoundByTheStringItIs(): void
    {
        // Given
        $admins = self::group('admins');
        $mapping = new GroupMapping([
            '1' => $admins,
        ]);

        // When / Then
        static::assertSame([$admins], $mapping->groupsOf(['1']));
    }

    #[Test]
    public function twoValuesThatNameOneGroupLeadToItOnce(): void
    {
        // Given
        $staff = self::group('staff');
        $mapping = new GroupMapping([
            'engineering-guid' => $staff,
            'sales-guid' => $staff,
        ]);

        // When
        $groups = $mapping->groupsOf(['engineering-guid', 'sales-guid', 'engineering-guid']);

        // Then
        static::assertSame([$staff], $groups);
    }

    #[Test]
    public function anEmptyValueIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A value an upstream provider asserts for the group "admins" must not be empty.');

        // When
        new GroupMapping([
            '' => self::group('admins'),
        ]);
    }

    private static function group(string $name): Group
    {
        return new Group(Uuid::v7(), Fixtures::tenant(), $name, GroupSource::Local, Fixtures::now());
    }
}
