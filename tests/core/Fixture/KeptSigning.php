<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeptSigningAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;

/**
 * An algorithm of a key the tenant signs with and keeps out of its JWK Set, as the SAML key of a tenant is: RSA, its
 * use "sig" unless a test names another to see it refused.
 */
final readonly class KeptSigning implements KeptSigningAlgorithmInterface
{
    public function __construct(
        private KeyUse $use = KeyUse::Signature,
    ) {
    }

    public function name(): string
    {
        return 'KEPT-SIGNING';
    }

    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return $this->use;
    }
}
