<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;

/**
 * The accepted documents in the memory of the test, counting what was written, so that a test can say nothing was,
 * and forgetting one when told. A test may have another process register a service provider between the reading and
 * the write of a refresh, as the unique index of the bundle sees two of them at the same minute.
 */
final class InMemoryAcceptedMetadata implements AcceptedMetadataRepositoryInterface, CanForgetAcceptedMetadataInterface
{
    public private(set) int $saves = 0;

    /**
     * @var array<string, AcceptedMetadata>
     */
    private array $rows = [];

    /**
     * What another process registers once a refresh has found nothing, by tenant and entity ID.
     *
     * @var array<string, AcceptedMetadata>
     */
    private array $meanwhile = [];

    /**
     * Another process registers this document as soon as a refresh of its service provider has found none.
     */
    public function registeredMeanwhile(AcceptedMetadata $metadata): void
    {
        $this->meanwhile[self::key($metadata->tenant, $metadata->entityId)] = $metadata;
    }

    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata
    {
        return $this->rows[self::key($tenant, $entityId)] ?? null;
    }

    public function register(AcceptedMetadata $metadata): bool
    {
        $key = self::key($metadata->tenant, $metadata->entityId);
        if (isset($this->meanwhile[$key])) {
            $this->rows[$key] = $this->meanwhile[$key];
            unset($this->meanwhile[$key]);
        }
        if (isset($this->rows[$key])) {
            return false;
        }
        ++$this->saves;
        $this->rows[$key] = $metadata;

        return true;
    }

    public function save(AcceptedMetadata $metadata): void
    {
        ++$this->saves;
        $this->rows[self::key($metadata->tenant, $metadata->entityId)] = $metadata;
    }

    public function forget(AcceptedMetadata $metadata): void
    {
        unset($this->rows[self::key($metadata->tenant, $metadata->entityId)]);
    }

    private static function key(Tenant $tenant, string $entityId): string
    {
        return $tenant->id->toRfc4122() . ' ' . $entityId;
    }
}
