<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AmbientTenantInterface;
use function is_resource;
use function is_string;
use SensitiveParameter;
use function sprintf;
use function stream_get_contents;
use Symfony\Component\KeyManagement\BlindIndexInterface;
use Symfony\Component\KeyManagement\DataKeyStoreInterface;
use Throwable;

final class TenantBlindIndexes
{
    /**
     * @var array<string, array<string, BlindIndexInterface>> by tenant slug, then by the name of the column
     */
    private array $indexes = [];

    /**
     * @param DataKeyStoreInterface $store one whose keys never retire
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly DataKeyStoreInterface $store,
        private readonly AmbientTenantInterface $tenants,
        private readonly string $table,
    ) {
    }

    /**
     * @throws RuntimeException when no tenant is ambient
     */
    public function of(BlindIndexedColumn $column): BlindIndexInterface
    {
        $slug = $this->slug($column);

        return $this->indexes[$slug][$column->name] ??= $this->build($slug, $column);
    }

    /**
     * Opens the key the tags of the tenant are derived under, and mints none: a tenant that indexed nothing has none.
     */
    public function open(Tenant $tenant): void
    {
        $reference = $this->reference(TenantScopedEncrypter::scope($tenant->slug, BlindIndexedColumns::SCOPE));
        if ($reference !== null) {
            $this->store->get($reference);
        }
    }

    private function build(string $slug, BlindIndexedColumn $column): BlindIndexInterface
    {
        $scope = TenantScopedEncrypter::scope($slug, BlindIndexedColumns::SCOPE);
        $reference = $this->reference($scope);

        if ($reference === null) {
            // The store mints the first key of a scope when asked for its current one.
            $this->store->current($scope);
            $reference = $this->reference($scope) ?? throw new RuntimeException(sprintf(
                'The data key store minted no row for the index scope "%s", so no blind index can be derived for that tenant.',
                $scope,
            ));
        }

        return $column->index($this->store, $reference);
    }

    /**
     * The first row of the scope, never current(), which may rotate: every tag written was derived under the first.
     */
    private function reference(string $scope): ?string
    {
        $reference = $this->connection
            ->createQueryBuilder()
            ->select('id')
            ->from($this->table)
            ->where('scope = :scope')
            ->setParameter('scope', $scope)
            ->orderBy('id', 'ASC')
            ->setMaxResults(1)
            ->fetchOne();

        return $reference === false ? null : self::bytes($reference);
    }

    /**
     * @throws RuntimeException when no tenant is ambient
     */
    private function slug(BlindIndexedColumn $column): string
    {
        try {
            return $this->tenants->provide()->slug;
        } catch (Throwable $exception) {
            throw new RuntimeException(
                sprintf(
                    'No tenant is ambient, so the blind index of "%s" cannot be derived: a tag derived under the index key of another tenant is a tag no search of either tenant matches.',
                    $column->tag,
                ),
                0,
                $exception,
            );
        }
    }

    /**
     * A binary column comes back as a string on some platforms and as a stream on others.
     */
    private static function bytes(#[SensitiveParameter] mixed $value): string
    {
        if (is_resource($value)) {
            return (string) stream_get_contents($value);
        }

        return is_string($value) ? $value : '';
    }
}
