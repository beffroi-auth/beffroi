<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;
use Symfony\Component\KeyManagement\BlindIndexInterface;
use Symfony\Component\KeyManagement\DataKeyStoreInterface;
use Symfony\Component\KeyManagement\StoredKeyBlindIndex;

final readonly class BlindIndexedColumn
{
    /**
     * What a tenant keeps its index under, the tag when the column has one projection.
     */
    public string $name;

    /**
     * @param class-string $entity
     * @param string $value the property whose value is indexed
     * @param string $tag the property the tag is written to
     */
    public function __construct(
        public string $entity,
        public string $value,
        public string $tag,
        private ProjectionInterface $projection,
        ?string $name = null,
    ) {
        $this->name = $name ?? $tag;
    }

    /**
     * Named after its column, or two columns holding one value would share a tag under the tenant's one key.
     */
    public function index(DataKeyStoreInterface $store, string $reference): BlindIndexInterface
    {
        return new StoredKeyBlindIndex($store, $reference, $this->tag, $this->projection);
    }
}
