<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\KeyManagement\DataKey;
use Symfony\Component\KeyManagement\DataKeyHandle;
use Symfony\Component\KeyManagement\RewrappableDataKeyStoreInterface;
use Symfony\Component\KeyManagement\StoredDataKey;

/**
 * The store of the deployment, showing one tenant's keys and no other (decision 0018).
 *
 * It exists for one caller: `key-management:rewrap-data-keys`, which walks `all()` and knows nothing of a
 * tenant. The rewrap of this provider is asked for one tenant at a time, because a master key belongs to
 * one tenant and moving a customer from one KMS to another is not moving every customer. Handing that
 * command a store filtered to one slug is what asks it for one tenant, and nothing of its loop, of its
 * unwrapping, of its re-wrapping or of its `--dry-run` is written a second time.
 *
 * It filters and never routes. Every other method goes straight through: a read resolves the client and
 * the master key from the row it reads, and what wraps is routed by the scope it is given, which already
 * carries the slug.
 */
final readonly class TenantScopedDataKeyStore implements RewrappableDataKeyStoreInterface
{
    public function __construct(
        private RewrappableDataKeyStoreInterface $store,
        private Tenant $tenant,
    ) {
    }

    public function all(?string $client = null): iterable
    {
        foreach ($this->store->all($client) as $stored) {
            if (TenantScopedEncrypter::slugOf($stored->scope) === $this->tenant->slug) {
                yield $stored;
            }
        }
    }

    public function current(string $scope): DataKeyHandle
    {
        return $this->store->current($scope);
    }

    public function rotate(string $scope): DataKeyHandle
    {
        return $this->store->rotate($scope);
    }

    public function get(string $reference): DataKeyHandle
    {
        return $this->store->get($reference);
    }

    public function rewrap(StoredDataKey $row, DataKey $rewrapped, string $client): void
    {
        $this->store->rewrap($row, $rewrapped, $client);
    }

    public function wrappingContextOf(StoredDataKey $row): string
    {
        return $this->store->wrappingContextOf($row);
    }
}
