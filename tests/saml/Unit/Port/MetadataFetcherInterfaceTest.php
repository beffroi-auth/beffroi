<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Port;

use Beffroi\Saml\Port\MetadataFetcherInterface;
use Beffroi\Xml\Core\Limits;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 7: the fetch of a metadata document stops at the maxBytes of Core's Limits, which loads it.
 * The port cannot read the bound from Core, the layers of Deptrac keeping a port of this package off the classes of
 * xml-security, so the two numbers are held together here: a bound raised on one side and not on the other would
 * either hand the loader a document it refuses, or refuse at the fetch a document it reads.
 */
final class MetadataFetcherInterfaceTest extends TestCase
{
    #[Test]
    public function theFetchStopsAtTheMaxBytesOfCore(): void
    {
        // When / Then
        static::assertSame(MetadataFetcherInterface::MAX_BYTES, new Limits()->maxBytes);
    }
}
