<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use function array_fill_keys;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Upstream\GroupMapping;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function str_repeat;

/**
 * spec/saml.md S-45: the attribute that carries the groups of a person at an upstream identity provider, and the name
 * of a group of the tenant each of its values stands for.
 */
final class GroupMappingTest extends TestCase
{
    private const string OBJECT_ID = '9f5c2a7e-1b3d-4e8f-a6c0-2d7b9e1f4a35';

    /**
     * S-45: a value the map names stands for its group of the tenant, compared exactly.
     */
    #[Test]
    public function aValueTheMapNamesStandsForItsGroup(): void
    {
        // Given
        $groups = new GroupMapping('http://schemas.microsoft.com/ws/2008/06/identity/claims/groups', [self::OBJECT_ID => 'Engineering']);

        // When / Then
        static::assertSame('Engineering', $groups->groupOf(self::OBJECT_ID));
    }

    /**
     * S-45: a value the map does not name is no group, its case included.
     */
    #[Test]
    #[DataProvider('provideValuesTheMapDoesNotName')]
    public function aValueTheMapDoesNotNameIsNoGroup(string $value): void
    {
        // Given
        $groups = new GroupMapping('groups', [self::OBJECT_ID => 'Engineering', 'member' => 'Members']);

        // When / Then
        static::assertNull($groups->groupOf($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesTheMapDoesNotName(): iterable
    {
        yield 'another value' => ['student'];
        yield 'another case' => ['Member'];
        yield 'a prefix' => ['mem'];
    }

    /**
     * S-45: a value of digits alone, which PHP keeps as an integer key, stands for its group as any other.
     */
    #[Test]
    public function aValueOfDigitsStandsForItsGroup(): void
    {
        // Given
        $groups = new GroupMapping('gidNumber', ['1001' => 'Staff']);

        // When / Then
        static::assertSame('Staff', $groups->groupOf('1001'));
    }

    /**
     * S-45: the name of the attribute of the groups is a name.
     */
    #[Test]
    public function anAttributeThatIsNoNameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The name of the attribute of the groups is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).');

        // When
        new GroupMapping('member of', ['member' => 'Members']);
    }

    /**
     * S-45: a value of the groups is not empty, holds no control character and is at most 1 024 characters.
     */
    #[Test]
    #[DataProvider('provideWhatIsNoValue')]
    public function aValueThatIsNoneIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A value of the groups is not empty, holds no control character and is at most 1024 characters (spec/saml.md S-45).');

        // When
        new GroupMapping('groups', [$value => 'Members']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoValue(): iterable
    {
        yield 'nothing' => [''];
        yield 'a NUL' => ["member\0"];
        yield 'a line feed' => ["member\n"];
        yield 'more than 1024 characters' => [str_repeat('a', 1025)];
        yield 'bytes that are not UTF-8' => ["member\xC3"];
    }

    /**
     * S-45: a value with a space, as a directory names a group, and a value of 1 024 characters are values.
     */
    #[Test]
    #[DataProvider('provideValues')]
    public function aValueIsMapped(string $value): void
    {
        // Given
        $groups = new GroupMapping('groups', [$value => 'Members']);

        // When / Then
        static::assertSame('Members', $groups->groupOf($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValues(): iterable
    {
        yield 'a space' => ['Domain Users'];
        yield '1024 characters' => [str_repeat('a', 1024)];
        yield 'a name outside ASCII' => ['Ingénierie'];
    }

    /**
     * S-45: a value names a group, never an empty name.
     */
    #[Test]
    public function aValueThatNamesNoGroupIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The value "member" of the groups names no group (spec/saml.md S-45).');

        // When
        new GroupMapping('groups', ['member' => '']);
    }

    /**
     * Section 7: the groups of an identity provider map 256 values at most.
     */
    #[Test]
    public function moreThan256ValuesAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The groups of an identity provider map 256 values at most (spec/saml.md section 7).');

        // When
        new GroupMapping('groups', array_fill_keys(range(1, 257), 'Members'));
    }

    /**
     * Section 7: 256 values are mapped.
     */
    #[Test]
    public function twoHundredAndFiftySixValuesAreMapped(): void
    {
        // Given
        $groups = new GroupMapping('groups', array_fill_keys(range(1, 256), 'Members'));

        // When / Then
        static::assertSame('Members', $groups->groupOf('256'));
    }
}
