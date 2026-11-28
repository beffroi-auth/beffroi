<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Name;

use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Name\Schemas;
use Beffroi\Scim\Domain\Schema\EnterpriseUserSchema;
use Beffroi\Scim\Domain\Schema\GroupSchema;
use Beffroi\Scim\Domain\Schema\UserSchema;
use Beffroi\Scim\Tests\Fixture\NamedSchema;
use Beffroi\Scim\Tests\Fixture\Refusals;
use Beffroi\Scim\Tests\Fixture\ServedSchemas;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/scim.md P-21, section 6.1 step 5
 */
final class SchemasTest extends TestCase
{
    /**
     * P-21, RFC 7643 §2.1, §2.3.7, RFC 7644 §3.10
     */
    #[Test]
    #[DataProvider('provideNames')]
    public function aNameResolvesToWhatItNamesFoldedByAscii(string $name, string $schema, ?string $attribute, ?string $subAttribute): void
    {
        // When
        $resolved = ServedSchemas::all()->resolve($name, new UserSchema());

        // Then
        static::assertSame([$schema, $attribute, $subAttribute], [$resolved->schema->urn(), $resolved->attribute, $resolved->subAttribute]);
    }

    /**
     * @return iterable<string, array{string, string, string|null, string|null}>
     */
    public static function provideNames(): iterable
    {
        yield 'an attribute' => ['userName', UserSchema::URN, 'username', null];
        yield 'an attribute in capitals' => ['USERNAME', UserSchema::URN, 'username', null];
        yield 'an attribute with every character a name takes' => ['a$b-c_1', UserSchema::URN, 'a$b-c_1', null];
        yield 'a sub-attribute' => ['name.givenName', UserSchema::URN, 'name', 'givenname'];
        yield 'the reference of a value' => ['$ref', UserSchema::URN, '$ref', null];
        yield 'the reference of a value in capitals' => ['$REF', UserSchema::URN, '$ref', null];
        yield 'the reference of an attribute' => ['manager.$ref', UserSchema::URN, 'manager', '$ref'];
        yield 'an attribute under its URN' => ['urn:ietf:params:scim:schemas:core:2.0:User:userName', UserSchema::URN, 'username', null];
        yield 'an attribute under its URN in capitals' => ['URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:userName', UserSchema::URN, 'username', null];
        yield 'a sub-attribute under its URN' => ['urn:ietf:params:scim:schemas:core:2.0:User:name.givenName', UserSchema::URN, 'name', 'givenname'];
        yield 'the container of the extension' => [EnterpriseUserSchema::URN, EnterpriseUserSchema::URN, null, null];
        yield 'an attribute of the extension' => [
            'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber',
            EnterpriseUserSchema::URN,
            'employeenumber',
            null,
        ];
    }

    /**
     * RFC 7644 §3.10
     */
    #[Test]
    public function aNameWithoutAUrnBelongsToTheBaseSchema(): void
    {
        // When
        $resolved = ServedSchemas::all()->resolve('displayName', new GroupSchema());

        // Then
        static::assertSame(GroupSchema::URN, $resolved->schema->urn());
    }

    /**
     * P-21
     */
    #[Test]
    public function aUrnResolvesBeforeAShorterOneItBeginsWith(): void
    {
        // Given
        $schemas = new Schemas([new NamedSchema('urn:ietf:params:scim:schemas:extension:enterprise:2.0'), new EnterpriseUserSchema()]);

        // When
        $resolved = $schemas->resolve(EnterpriseUserSchema::URN, new UserSchema());

        // Then
        static::assertSame([EnterpriseUserSchema::URN, null], [$resolved->schema->urn(), $resolved->attribute]);
    }

    /**
     * P-21, RFC 7643 §2.1
     */
    #[Test]
    #[DataProvider('provideWhatIsNoName')]
    public function whatIsNoNameOfAnAttributeIsRefusedAsInvalidSyntax(string $name): void
    {
        // When
        $error = Refusals::of(static fn () => ServedSchemas::all()->resolve($name, new UserSchema()));

        // Then
        static::assertSame(400, $error->status);
        static::assertSame(ScimType::InvalidSyntax, $error->scimType);
        static::assertSame(Schemas::NOT_A_NAME, $error->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoName(): iterable
    {
        yield 'a long s, which Unicode folds onto an s' => ["pa\u{17F}\u{17F}word"];
        yield 'a KELVIN SIGN, which Unicode folds onto a k' => ["nic\u{212A}Name"];
        yield 'a long s under the URN of its schema' => ["urn:ietf:params:scim:schemas:core:2.0:User:pa\u{17F}\u{17F}word"];
        yield 'a long s in a URN' => ["urn:example:pa\u{17F}\u{17F}word:userName"];
        yield 'nothing' => [''];
        yield 'a digit first' => ['1name'];
        yield 'a space' => ['user name'];
        yield 'a dot at the end' => ['name.'];
        yield 'a sub-attribute of a sub-attribute' => ['name.givenName.first'];
        yield 'a name that only begins with the reference' => ['$refs'];
        yield 'a sub-attribute of the reference' => ['$ref.value'];
        yield 'nothing after the URN of a schema' => ['urn:ietf:params:scim:schemas:core:2.0:User:'];
        yield 'a URN after the URN of a schema' => ['urn:ietf:params:scim:schemas:core:2.0:User:urn:x'];
    }

    /**
     * P-21, section 8
     */
    #[Test]
    #[DataProvider('provideUnservedUrns')]
    public function aNameUnderTheUrnOfASchemaTheProviderDoesNotServeIsRefusedAsInvalidValue(string $name): void
    {
        // When
        $error = Refusals::of(static fn () => ServedSchemas::all()->resolve($name, new UserSchema()));

        // Then
        static::assertSame(400, $error->status);
        static::assertSame(ScimType::InvalidValue, $error->scimType);
        static::assertSame(Schemas::UNSERVED_SCHEMA, $error->detail);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnservedUrns(): iterable
    {
        yield 'a custom extension' => ['urn:ietf:params:scim:schemas:extension:CustomExtension:2.0:User:costCode'];
        yield 'the URN of a schema the provider serves, longer' => ['urn:ietf:params:scim:schemas:core:2.0:Users'];
        yield 'another namespace' => ['urn:example:schema'];
    }
}
