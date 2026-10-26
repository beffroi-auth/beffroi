<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Tests\Fixture\Keys;
use SensitiveParameter;

/**
 * The KMS of the suite, counting the envelopes it is asked to open: what a test of what a process holds open reads.
 */
final class CountingKeySealer implements KeySealerInterface
{
    public private(set) int $unsealed = 0;

    public function seal(Tenant $tenant, #[SensitiveParameter] array $privateJwk): string
    {
        return Keys::sealer()->seal($tenant, $privateJwk);
    }

    public function unseal(Tenant $tenant, #[SensitiveParameter] string $sealed): array
    {
        ++$this->unsealed;

        return Keys::sealer()->unseal($tenant, $sealed);
    }
}
