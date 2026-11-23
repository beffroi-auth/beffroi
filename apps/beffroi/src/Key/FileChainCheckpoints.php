<?php

declare(strict_types=1);

namespace App\Key;

use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\SignedCheckpointsInterface;
use function bin2hex;
use function chmod;
use function file_get_contents;
use function file_put_contents;
use function is_dir;
use function is_string;
use const LOCK_EX;
use function mkdir;
use function random_bytes;
use function rename;
use function sprintf;
use function trim;
use function unlink;

/**
 * Beside the keys of the tenant, in a directory the reader of the keys does not look into, one file per chain renamed
 * into place so that no reader sees half a signature.
 */
final readonly class FileChainCheckpoints implements SignedCheckpointsInterface
{
    public const string DIRECTORY = 'chains';

    public const string SUFFIX = '.jws';

    public function __construct(
        private string $directory,
    ) {
    }

    public function last(Tenant $tenant, ChainInterface $chain): ?string
    {
        $signed = @file_get_contents($this->path($tenant, $chain));
        if (! is_string($signed)) {
            return null;
        }
        $signed = trim($signed);

        return $signed === '' ? null : $signed;
    }

    public function keep(Tenant $tenant, ChainInterface $chain, string $compactJws): void
    {
        $directory = $this->directory . '/' . $tenant->slug . '/' . self::DIRECTORY;
        if (! is_dir($directory) && ! @mkdir($directory, 0o700, true) && ! is_dir($directory)) {
            throw new RuntimeException(sprintf('The storage of the signatures of the chains "%s" cannot be created.', $directory));
        }
        $path = $this->path($tenant, $chain);
        $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        if (@file_put_contents($temporary, $compactJws, LOCK_EX) === false || ! @chmod($temporary, 0o600) || ! @rename($temporary, $path)) {
            @unlink($temporary);

            throw new RuntimeException(sprintf(
                'The signature of the chain "%s" of the tenant "%s" cannot be written to "%s".',
                $chain->name(),
                $tenant->slug,
                $path,
            ));
        }
    }

    public function path(Tenant $tenant, ChainInterface $chain): string
    {
        return $this->directory . '/' . $tenant->slug . '/' . self::DIRECTORY . '/' . $chain->name() . self::SUFFIX;
    }
}
