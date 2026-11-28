<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Application\Request;

use Beffroi\Scim\Application\Request\RequestBody;
use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Domain\Name\BodyNames;
use Beffroi\Scim\Domain\Name\Schemas;
use Beffroi\Scim\Domain\Request\BodyLength;
use Beffroi\Scim\Domain\Request\JsonDocument;
use Beffroi\Scim\Domain\Request\JsonStructure;
use Beffroi\Scim\Domain\Request\MediaType;
use Beffroi\Scim\Domain\Schema\UserSchema;
use Beffroi\Scim\Tests\Fixture\Refusals;
use Beffroi\Scim\Tests\Fixture\ServedSchemas;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/scim.md section 6.1 steps 4 and 5, P-5
 */
final class RequestBodyTest extends TestCase
{
    private RequestBody $body;

    protected function setUp(): void
    {
        $this->body = new RequestBody(new BodyNames(ServedSchemas::all()));
    }

    /**
     * Section 6.1 steps 4 and 5
     */
    #[Test]
    public function aBodyIsReadIntoItsObject(): void
    {
        // When
        $document = $this->body->read('application/scim+json', '{"userName":"bjensen"}', new UserSchema());

        // Then
        static::assertSame('bjensen', $document->userName);
    }

    /**
     * Section 6.1 step 4
     */
    #[Test]
    public function theTypeIsReadBeforeTheBytesAreCounted(): void
    {
        // When
        $error = Refusals::of(fn () => $this->body->read('text/plain', str_repeat(' ', BodyLength::BYTES + 1), new UserSchema()));

        // Then
        static::assertSame([415, MediaType::DETAIL], [$error->status, $error->detail]);
    }

    /**
     * P-5, section 6.1 step 4
     */
    #[Test]
    public function theBytesAreCountedBeforeTheyAreRead(): void
    {
        // When
        $error = Refusals::of(fn () => $this->body->read(null, str_repeat('{', BodyLength::BYTES + 1), new UserSchema()));

        // Then
        static::assertSame([413, BodyLength::DETAIL], [$error->status, $error->detail]);
    }

    /**
     * P-5, RFC 7493 §2.3
     */
    #[Test]
    public function aNameHeldTwiceIsRefusedBeforeJsonDecodeKeepsTheLastOne(): void
    {
        // When
        $error = Refusals::of(fn () => $this->body->read(null, '{"userName":"a","\\u0075serName":"b"}', new UserSchema()));

        // Then
        static::assertSame([400, ScimType::InvalidSyntax, JsonStructure::NAME_TWICE], [$error->status, $error->scimType, $error->detail]);
    }

    /**
     * P-5, section 7
     */
    #[Test]
    public function aBodyPastABoundOfItsStructureIsRefusedBeforeItIsDecoded(): void
    {
        // When
        $error = Refusals::of(fn () => $this->body->read(null, str_repeat('[', 9) . str_repeat(']', 9), new UserSchema()));

        // Then
        static::assertSame([413, JsonStructure::TOO_DEEP], [$error->status, $error->detail]);
    }

    /**
     * Section 6.1 step 4
     */
    #[Test]
    public function aBodyThatIsNoObjectIsRefusedAsInvalidSyntax(): void
    {
        // When
        $error = Refusals::of(fn () => $this->body->read(null, '[]', new UserSchema()));

        // Then
        static::assertSame([400, ScimType::InvalidSyntax, JsonDocument::NOT_AN_OBJECT], [$error->status, $error->scimType, $error->detail]);
    }

    /**
     * P-21, section 6.1 step 5
     */
    #[Test]
    public function theNamesOfTheBodyAreResolved(): void
    {
        // When
        $error = Refusals::of(fn () => $this->body->read(null, '{"pa\\u017f\\u017fword":"x"}', new UserSchema()));

        // Then
        static::assertSame([400, ScimType::InvalidSyntax, Schemas::NOT_A_NAME], [$error->status, $error->scimType, $error->detail]);
    }
}
