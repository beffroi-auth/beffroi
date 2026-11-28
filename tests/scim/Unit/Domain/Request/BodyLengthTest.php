<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Request;

use Beffroi\Scim\Domain\Request\BodyLength;
use Beffroi\Scim\Tests\Fixture\Refusals;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/scim.md section 7, P-5
 */
final class BodyLengthTest extends TestCase
{
    /**
     * Section 7
     */
    #[Test]
    public function aBodyOfTheBoundIsRead(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        BodyLength::assertWithinBound(str_repeat(' ', 524_288));
    }

    /**
     * P-5, section 7, RFC 9110 §15.5.14
     */
    #[Test]
    public function aBodyPastTheBoundIsRefusedAsTooLarge(): void
    {
        // When
        $error = Refusals::of(static fn () => BodyLength::assertWithinBound(str_repeat(' ', 524_289)));

        // Then
        static::assertSame(413, $error->status);
        static::assertNull($error->scimType);
        static::assertSame(BodyLength::DETAIL, $error->detail);
    }
}
