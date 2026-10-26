<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use function array_keys;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-8, S-42: the document accepted for an upstream identity provider is sealed in the family of its own
 * table, the rest of its row classified as every peer's.
 */
final class AcceptedUpstreamMetadataTest extends TestCase
{
    /**
     * S-8, S-42: the document is sealed in the family of the table of the upstream identity providers.
     */
    #[Test]
    public function theDocumentIsSealedInTheFamilyOfItsTable(): void
    {
        // When
        $fields = AcceptedUpstreamMetadata::classifiedFields();

        // Then
        static::assertEquals(new Sealed('saml_upstream_identity_provider'), $fields['document']);
    }

    /**
     * S-8: every field of the row is classified, what every peer keeps and the document.
     */
    #[Test]
    public function everyFieldOfTheRowIsClassified(): void
    {
        // When / Then
        static::assertSame(
            ['id', 'tenant', 'entityId', 'validUntil', 'acceptedAt', 'document'],
            array_keys(AcceptedUpstreamMetadata::classifiedFields()),
        );
    }
}
