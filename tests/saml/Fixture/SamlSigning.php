<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;

/**
 * The algorithm of the SAML signing key of a tenant under test: the bundle wires one under the same name, which draws
 * its pairs with the generator of the core; here the pairs are drawn once per process (SamlKeys).
 */
final readonly class SamlSigning implements SamlSigningAlgorithmInterface
{
    public function name(): string
    {
        return 'SAML-SIGNING';
    }

    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }
}
