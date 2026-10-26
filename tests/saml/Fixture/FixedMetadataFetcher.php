<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\MetadataFetcherInterface;
use Exception;

/**
 * The document each location of the test answers, changed by the test between two refreshes; a location it was given
 * nothing for cannot be read, and one it was given a fault for throws it, as a fetcher that fails rather than refuses.
 */
final class FixedMetadataFetcher implements MetadataFetcherInterface
{
    /**
     * @var array<string, string>
     */
    private array $documents = [];

    /**
     * @var array<string, Exception>
     */
    private array $faults = [];

    public function answer(string $location, string $document): void
    {
        $this->documents[$location] = $document;
    }

    public function fail(string $location, Exception $fault): void
    {
        $this->faults[$location] = $fault;
    }

    /**
     * @throws Exception the fault the test gave the location
     */
    public function fetch(MetadataLocation $location): string
    {
        if (isset($this->faults[$location->value])) {
            throw $this->faults[$location->value];
        }

        return $this->documents[$location->value] ?? throw new MetadataRefusedException('The location answers nothing.');
    }
}
