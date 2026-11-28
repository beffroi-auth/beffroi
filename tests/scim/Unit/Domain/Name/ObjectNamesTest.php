<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Name;

use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Name\ObjectNames;
use Beffroi\Scim\Domain\Schema\EnterpriseUserSchema;
use Beffroi\Scim\Domain\Schema\UserSchema;
use Beffroi\Scim\Tests\Fixture\Refusals;
use Beffroi\Scim\Tests\Fixture\ServedSchemas;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/scim.md P-21
 */
final class ObjectNamesTest extends TestCase
{
    /**
     * P-21, RFC 7644 §3.10
     */
    #[Test]
    #[DataProvider('provideNamesOfOneAttribute')]
    public function twoNamesOfOneAttributeAreRefusedAsInvalidSyntax(string $first, string $second): void
    {
        // Given
        $names = self::holding($first);

        // When
        $error = Refusals::of(static fn () => $names->hold(ServedSchemas::all()->resolve($second, new UserSchema())));

        // Then
        static::assertSame(400, $error->status);
        static::assertSame(ScimType::InvalidSyntax, $error->scimType);
        static::assertSame(ObjectNames::DETAIL, $error->detail);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideNamesOfOneAttribute(): iterable
    {
        yield 'an attribute in two cases' => ['userName', 'USERNAME'];
        yield 'an attribute beside its URN form' => ['userName', 'urn:ietf:params:scim:schemas:core:2.0:User:userName'];
        yield 'an attribute, then one of its sub-attributes' => ['name', 'name.givenName'];
        yield 'a sub-attribute, then its attribute' => ['name.givenName', 'name'];
        yield 'a sub-attribute in two cases' => ['name.givenName', 'NAME.GIVENNAME'];
        yield 'the container of the extension, then an attribute of it' => [
            EnterpriseUserSchema::URN,
            'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber',
        ];
        yield 'an attribute of the extension, then its container' => [
            'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value',
            EnterpriseUserSchema::URN,
        ];
    }

    /**
     * P-21
     */
    #[Test]
    #[DataProvider('provideNamesOfTwoAttributes')]
    public function twoNamesOfTwoAttributesAreHeldTogether(string $first, string $second): void
    {
        // Given
        $names = self::holding($first);

        // Then
        $this->expectNotToPerformAssertions();

        // When
        $names->hold(ServedSchemas::all()->resolve($second, new UserSchema()));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideNamesOfTwoAttributes(): iterable
    {
        yield 'two attributes' => ['userName', 'name'];
        yield 'two sub-attributes of one attribute' => ['name.givenName', 'name.familyName'];
        yield 'one name in two schemas' => ['manager', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager'];
        yield 'a sub-attribute and another attribute' => ['name.givenName', 'nickName'];
    }

    private static function holding(string $name): ObjectNames
    {
        $names = new ObjectNames();
        $names->hold(ServedSchemas::all()->resolve($name, new UserSchema()));

        return $names;
    }
}
