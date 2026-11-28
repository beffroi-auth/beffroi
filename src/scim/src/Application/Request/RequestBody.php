<?php

declare(strict_types=1);

namespace Beffroi\Scim\Application\Request;

use Beffroi\Scim\Domain\Name\BodyNames;
use Beffroi\Scim\Domain\Request\BodyLength;
use Beffroi\Scim\Domain\Request\JsonDocument;
use Beffroi\Scim\Domain\Request\JsonStructure;
use Beffroi\Scim\Domain\Request\MediaType;
use Beffroi\Scim\Domain\Schema\SchemaInterface;
use Beffroi\Scim\Exception\ScimRefusedException;
use stdClass;

/**
 * Section 6.1, steps 4 and 5: the body of a request read as the module reads every body, its type first, its bytes
 * counted before they are read, then read by the reader of P-5 before json_decode() builds anything, then its names.
 */
final readonly class RequestBody
{
    public function __construct(
        private BodyNames $names,
    ) {
    }

    /**
     * @param string|null $contentType the Content-Type the request carries, null when it carries none
     * @param SchemaInterface $base the base schema of the endpoint (RFC 7644 §3.10)
     *
     * @throws ScimRefusedException
     */
    public function read(?string $contentType, string $bytes, SchemaInterface $base): stdClass
    {
        MediaType::assertReadable($contentType);
        BodyLength::assertWithinBound($bytes);
        JsonStructure::assertWithinBounds($bytes);
        $document = JsonDocument::decode($bytes);
        $this->names->assertResolved($document, $base);

        return $document;
    }
}
