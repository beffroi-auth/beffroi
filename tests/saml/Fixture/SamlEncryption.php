<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;

/**
 * The algorithm of the key an upstream identity provider encrypts for, under test (spec/saml.md S-64): the bundle
 * wires one per provider under the same name, which draws its pairs with the generator of the core; here the pairs are
 * drawn once per process (SamlKeys).
 */
final readonly class SamlEncryption implements SamlEncryptionAlgorithmInterface
{
    public function __construct(
        private string $identityProvider,
    ) {
    }

    public function name(): string
    {
        return self::NAME_PREFIX . $this->identityProvider;
    }

    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Encryption;
    }

    public function identityProvider(): string
    {
        return $this->identityProvider;
    }
}
