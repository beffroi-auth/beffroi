<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Name;

use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Name\BodyNames;
use Beffroi\Scim\Domain\Name\ObjectNames;
use Beffroi\Scim\Domain\Name\Schemas;
use Beffroi\Scim\Domain\Schema\UserSchema;
use Beffroi\Scim\Tests\Fixture\Refusals;
use Beffroi\Scim\Tests\Fixture\ServedSchemas;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * spec/scim.md P-21, section 6.1 step 5
 */
final class BodyNamesTest extends TestCase
{
    /**
     * P-21, RFC 7643 §3.3, §8.3
     */
    #[Test]
    public function aBodyWhoseNamesEachNameOneAttributeIsLetThrough(): void
    {
        // Given
        $document = self::document('{"schemas":[],"userName":"bjensen","name":{"givenName":"Barbara"},"emails":[{"value":"b@example.com","type":"work"},{"value":"j@example.com","type":"home"}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"701984","manager":{"value":"26118915","$ref":"../Users/26118915"}}}');

        // Then
        $this->expectNotToPerformAssertions();

        // When
        self::names()->assertResolved($document, new UserSchema());
    }

    /**
     * P-21, RFC 7643 §2.1
     */
    #[Test]
    #[DataProvider('provideNamesThatAreNoName')]
    public function aNameThatIsNoNameIsRefusedWhereverItStands(string $body): void
    {
        // Given
        $document = self::document($body);

        // When
        $error = Refusals::of(static fn () => self::names()->assertResolved($document, new UserSchema()));

        // Then
        static::assertSame([400, ScimType::InvalidSyntax, Schemas::NOT_A_NAME], [$error->status, $error->scimType, $error->detail]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatAreNoName(): iterable
    {
        yield 'in the resource' => ['{"pa\\u017f\\u017fword":"x"}'];
        yield 'in a complex value' => ['{"name":{"given\\u212aame":"x"}}'];
        yield 'in a value of a multi-valued attribute' => ['{"emails":[{"value":"x"},{"v alue":"y"}]}'];
        yield 'in the container of the extension' => ['{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"1st":"x"}}'];
        yield 'made of digits' => ['{"0":"x"}'];
    }

    /**
     * P-21, RFC 7643 §3.3
     */
    #[Test]
    #[DataProvider('provideObjectsThatNameOneAttributeTwice')]
    public function anObjectThatNamesOneAttributeTwiceIsRefused(string $body): void
    {
        // Given
        $document = self::document($body);

        // When
        $error = Refusals::of(static fn () => self::names()->assertResolved($document, new UserSchema()));

        // Then
        static::assertSame([400, ScimType::InvalidSyntax, ObjectNames::DETAIL], [$error->status, $error->scimType, $error->detail]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideObjectsThatNameOneAttributeTwice(): iterable
    {
        yield 'the resource' => ['{"userName":"a","urn:ietf:params:scim:schemas:core:2.0:User:userName":"b"}'];
        yield 'a value of a multi-valued attribute' => ['{"emails":[{"value":"a","VALUE":"b"}]}'];
        yield 'the container of the extension, its names read under the extension' => [
            '{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"1","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber":"2"}}',
        ];
        yield 'the resource, beside the container of the extension' => [
            '{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"1"},"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber":"2"}',
        ];
    }

    private static function names(): BodyNames
    {
        return new BodyNames(ServedSchemas::all());
    }

    private static function document(string $body): stdClass
    {
        $document = json_decode($body, false, 512, JSON_THROW_ON_ERROR);

        return $document instanceof stdClass ? $document : static::fail('The body of the test is no object.');
    }
}
