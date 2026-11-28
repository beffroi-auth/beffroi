<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Answer;

use Beffroi\Scim\Domain\Answer\ScimAnswer;
use Beffroi\Scim\Domain\Error\ScimError;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/scim.md section 5.1
 */
final class ScimAnswerTest extends TestCase
{
    /**
     * Section 5.1, RFC 7644 §8.1, RFC 9111 §5.2.2.5
     */
    #[Test]
    public function anAnswerIsADocumentOfScimThatNoCacheKeeps(): void
    {
        // Given
        $answer = new ScimAnswer(
            200,
            [],
            [
                'Content-Type' => 'text/html',
                'Cache-Control' => 'public',
                'ETag' => 'W/"1"',
            ],
        );

        // When
        $headers = $answer->headers();

        // Then
        static::assertSame(
            [
                'Content-Type' => 'application/scim+json',
                'Cache-Control' => 'no-store',
                'ETag' => 'W/"1"',
            ],
            $headers,
        );
    }

    /**
     * P-19, RFC 7644 §3.12
     */
    #[Test]
    public function anErrorIsAnsweredWithItsStatusAndItsDocument(): void
    {
        // When
        $answer = ScimAnswer::error(new ScimError(501, null, 'The provider does not serve this operation.'));

        // Then
        static::assertSame(501, $answer->status);
        static::assertSame(
            '{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"501","detail":"The provider does not serve this operation."}',
            $answer->body(),
        );
    }
}
