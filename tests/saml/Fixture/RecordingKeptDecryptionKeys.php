<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeptEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeptDecryptionKeyProviderInterface;

/**
 * The keys the core opens to decrypt, each "kid" asked recorded: what a test of the key that is never asked reads
 * (spec/saml.md S-66).
 */
final class RecordingKeptDecryptionKeys implements KeptDecryptionKeyProviderInterface
{
    /**
     * @var list<string> the "kid" of each key asked, in order
     */
    public private(set) array $asked = [];

    public function __construct(
        private readonly KeptDecryptionKeyProviderInterface $keys,
    ) {
    }

    public function keptDecryptionKeys(Tenant $tenant, KeptEncryptionAlgorithmInterface $algorithm, array $kids): array
    {
        foreach ($kids as $kid) {
            $this->asked[] = $kid;
        }

        return $this->keys->keptDecryptionKeys($tenant, $algorithm, $kids);
    }
}
