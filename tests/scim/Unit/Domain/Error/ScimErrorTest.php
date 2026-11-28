<?php

declare(strict_types=1);

namespace Beffroi\Scim\Tests\Unit\Domain\Error;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Domain\Error\ScimType;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/scim.md P-19, section 6.12
 */
final class ScimErrorTest extends TestCase
{
    /**
     * P-19, RFC 7644 §3.12
     */
    #[Test]
    public function anErrorIsTheDocumentOfRfc7644WithItsStatusAsAString(): void
    {
        // Given
        $error = new ScimError(400, ScimType::InvalidSyntax, 'The rule refused.');

        // When
        $document = $error->toDocument();

        // Then
        static::assertSame(
            [
                'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
                'status' => '400',
                'scimType' => 'invalidSyntax',
                'detail' => 'The rule refused.',
            ],
            $document,
        );
    }

    /**
     * RFC 7644 §3.12, Table 9
     */
    #[Test]
    public function anErrorWithoutAKeywordOfTable9CarriesNone(): void
    {
        // Given
        $error = new ScimError(413, null, 'The rule refused.');

        // When
        $document = $error->toDocument();

        // Then
        static::assertArrayNotHasKey('scimType', $document);
    }
}
