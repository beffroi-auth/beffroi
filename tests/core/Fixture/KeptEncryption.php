<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeptEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;

/**
 * An algorithm of a key the tenant is encrypted to and keeps out of its JWK Set, as the key a SAML identity provider
 * encrypts for is: RSA, named after the holder it belongs to, its use "enc" unless a test names another to see it
 * refused.
 */
final readonly class KeptEncryption implements KeptEncryptionAlgorithmInterface
{
    public function __construct(
        private string $holder = 'a',
        private KeyUse $use = KeyUse::Encryption,
    ) {
    }

    public function name(): string
    {
        return 'KEPT-ENCRYPTION:' . $this->holder;
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
