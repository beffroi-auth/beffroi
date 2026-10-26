<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Key;

use function base64_decode;
use function base64_encode;
use function bin2hex;
use function chmod;
use DateTimeImmutable;
use DateTimeInterface;
use function file_get_contents;
use function file_put_contents;
use function glob;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\KeyAlgorithmsInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use function is_array;
use function is_dir;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use JsonException;
use const LOCK_EX;
use function mkdir;
use function preg_match;
use function random_bytes;
use function rename;
use function sort;
use function sprintf;
use function unlink;
use function usort;

/**
 * The keys of a tenant as files (architecture §3.3), one JSON document per key under
 * "<storage>/<tenant slug>/<kid>.json", written through a sibling file renamed into place. What the key
 * is published for is what its algorithm says, so the document names the algorithm and nothing else.
 *
 * A file whose algorithm is dormant, the key of a capability the deployment turned off after the tenant
 * drew it (DormantKeyAlgorithms), is read past: no method answers it, and it is read again as it was
 * once the capability is turned back on.
 *
 * One material is the key of one algorithm: the "kid" is the thumbprint of the public half, so the key of
 * another algorithm under the same "kid" is the same material, and it is refused rather than written over
 * the file that holds it. For the keys the upstream SAML identity providers encrypt for, one algorithm per
 * provider, that is what keeps the key of one provider from being the key of another (spec/saml.md S-64).
 */
final readonly class FileTenantKeyRepository implements TenantKeyRepositoryInterface
{
    /**
     * An RFC 7638 thumbprint, base64url: nothing else may name a file.
     */
    private const string KID_PATTERN = '/^[A-Za-z0-9_-]+$/D';

    public function __construct(
        private string $directory,
        private KeyAlgorithmsInterface $algorithms,
        private DormantKeyAlgorithms $dormant = new DormantKeyAlgorithms(),
    ) {
    }

    public function find(Tenant $tenant, string $kid): ?TenantKey
    {
        if (preg_match(self::KID_PATTERN, $kid) !== 1) {
            return null;
        }
        $path = $this->path($tenant, $kid);
        $json = @file_get_contents($path);
        if ($json === false) {
            return null;
        }

        return $this->read($tenant, $path, $json);
    }

    public function findActive(Tenant $tenant, KeyAlgorithmInterface $algorithm): ?TenantKey
    {
        foreach ($this->findAll($tenant) as $key) {
            if ($key->algorithm->name() === $algorithm->name() && $key->isActive()) {
                return $key;
            }
        }

        return null;
    }

    public function findInService(Tenant $tenant): array
    {
        $inService = [];
        foreach ($this->findAll($tenant) as $key) {
            if ($key->isInService()) {
                $inService[] = $key;
            }
        }

        return $inService;
    }

    public function save(TenantKey $key): void
    {
        if (preg_match(self::KID_PATTERN, $key->kid) !== 1) {
            throw new RuntimeException(sprintf('The key identifier "%s" cannot name a file.', $key->kid));
        }
        $directory = $this->tenantDirectory($key->tenant);
        if (! is_dir($directory) && ! @mkdir($directory, 0o700, true) && ! is_dir($directory)) {
            throw new RuntimeException(sprintf('The key storage "%s" cannot be created.', $directory));
        }
        $path = $this->path($key->tenant, $key->kid);
        $held = @file_get_contents($path);
        if ($held !== false && self::algorithmOf($held) !== $key->algorithm->name()) {
            throw new RuntimeException(sprintf(
                'The key "%s" of tenant "%s" is held already, and not as a key of %s: one material is the key of one algorithm.',
                $key->kid,
                $key->tenant->slug,
                $key->algorithm->name(),
            ));
        }
        $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        $json = json_encode(
            [
                'kid' => $key->kid,
                'tenant_id' => $key->tenant->id->toRfc4122(),
                'algorithm' => $key->algorithm->name(),
                'public_jwk' => $key->publicJwk,
                'sealed_private_jwk' => base64_encode($key->sealedPrivateJwk),
                'status' => $key->status->value,
                'created_at' => $key->createdAt->format(DateTimeInterface::RFC3339_EXTENDED),
                'activation_due_at' => $key->activationDueAt->format(DateTimeInterface::RFC3339_EXTENDED),
                'activated_at' => $key->activatedAt?->format(DateTimeInterface::RFC3339_EXTENDED),
                'retiring_at' => $key->retiringAt?->format(DateTimeInterface::RFC3339_EXTENDED),
                'retirement_due_at' => $key->retirementDueAt?->format(DateTimeInterface::RFC3339_EXTENDED),
                'retired_at' => $key->retiredAt?->format(DateTimeInterface::RFC3339_EXTENDED),
            ],
            JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
        );
        if (@file_put_contents($temporary, $json, LOCK_EX) === false || ! @chmod($temporary, 0o600) || ! @rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException(sprintf('The key "%s" cannot be written to "%s".', $key->kid, $path));
        }
    }

    /**
     * Oldest first, the order the port asks for.
     */
    public function findAll(Tenant $tenant): array
    {
        $paths = glob($this->tenantDirectory($tenant) . '/*.json');
        if ($paths === false || $paths === []) {
            return [];
        }
        sort($paths);
        $keys = [];
        foreach ($paths as $path) {
            $json = @file_get_contents($path);
            if ($json === false) {
                throw new RuntimeException(sprintf('The key file "%s" cannot be read.', $path));
            }
            $key = $this->read($tenant, $path, $json);
            if ($key !== null) {
                $keys[] = $key;
            }
        }
        usort($keys, static fn (TenantKey $a, TenantKey $b): int => [$a->createdAt, $a->kid] <=> [$b->createdAt, $b->kid]);

        return $keys;
    }

    /**
     * A file that is not what this repository writes is a fault of the storage, not a missing key. The
     * transitions are replayed in order with their dates: the file holds facts, the key holds the rules.
     *
     * @return TenantKey|null null for the key of a dormant algorithm, which is left as it is
     */
    private function read(Tenant $tenant, string $path, string $json): ?TenantKey
    {
        try {
            $document = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException(sprintf('The key file "%s" is not JSON.', $path), 0, $exception);
        }
        if (! is_array($document)) {
            throw self::corrupted($path);
        }
        $kid = $document['kid'] ?? null;
        $tenantId = $document['tenant_id'] ?? null;
        $algorithm = null;
        if (is_string($document['algorithm'] ?? null)) {
            try {
                $algorithm = $this->algorithms->named($document['algorithm']);
            } catch (UnsupportedAlgorithmException $exception) {
                if ($this->dormant->holds($document['algorithm'])) {
                    return null;
                }

                throw new RuntimeException(sprintf('The key file "%s" names an algorithm this provider is not wired with.', $path), 0, $exception);
            }
        }
        $status = is_string($document['status'] ?? null) ? KeyStatus::tryFrom($document['status']) : null;
        $sealed = is_string($document['sealed_private_jwk'] ?? null) ? base64_decode($document['sealed_private_jwk'], true) : false;
        $publicJwk = $document['public_jwk'] ?? null;
        if (! is_string($kid) || ! is_string($tenantId) || $algorithm === null || $status === null || $sealed === false || ! is_array($publicJwk)) {
            throw self::corrupted($path);
        }
        if ($tenantId !== $tenant->id->toRfc4122()) {
            throw new RuntimeException(sprintf('The key file "%s" belongs to another tenant.', $path));
        }
        $members = [];
        foreach ($publicJwk as $member => $value) {
            if (! is_string($member) || ! is_string($value)) {
                throw self::corrupted($path);
            }
            $members[$member] = $value;
        }

        try {
            $key = new TenantKey(
                $kid,
                $tenant,
                $algorithm,
                $members,
                $sealed,
                self::date($path, $document['created_at'] ?? null),
                self::date($path, $document['activation_due_at'] ?? null),
            );
            if ($status !== KeyStatus::Staged) {
                $key->activate(self::date($path, $document['activated_at'] ?? null));
            }
            if ($status === KeyStatus::Retiring || $status === KeyStatus::Retired) {
                $key->startRetiring(self::date($path, $document['retiring_at'] ?? null), self::date($path, $document['retirement_due_at'] ?? null));
            }
            if ($status === KeyStatus::Retired) {
                $key->retire(self::date($path, $document['retired_at'] ?? null));
            }
        } catch (InvalidArgumentException $exception) {
            throw new RuntimeException(sprintf('The key file "%s" does not describe a key.', $path), 0, $exception);
        }

        return $key;
    }

    /**
     * The algorithm a key file names, null when it names none or is not a key document.
     */
    private static function algorithmOf(string $json): ?string
    {
        try {
            $document = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
        $algorithm = is_array($document) ? $document['algorithm'] ?? null : null;

        return is_string($algorithm) ? $algorithm : null;
    }

    private static function date(string $path, mixed $value): DateTimeImmutable
    {
        $date = is_string($value) ? DateTimeImmutable::createFromFormat(DateTimeInterface::RFC3339_EXTENDED, $value) : false;
        if ($date === false) {
            throw self::corrupted($path);
        }

        return $date;
    }

    private static function corrupted(string $path): RuntimeException
    {
        return new RuntimeException(sprintf('The key file "%s" is not a key document.', $path));
    }

    private function tenantDirectory(Tenant $tenant): string
    {
        return $this->directory . '/' . $tenant->slug;
    }

    private function path(Tenant $tenant, string $kid): string
    {
        return $this->tenantDirectory($tenant) . '/' . $kid . '.json';
    }
}
