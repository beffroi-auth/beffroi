<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * The SAML signing key of a tenant (beffroi/saml, spec/saml.md section 5.1, S-1): an RSA pair of the size the RSA
 * algorithms of the core share, drawn by the generator of the core, sealed by the KMS and rotated by the key commands
 * under this name, as every other key of the tenant, and published as a certificate in the metadata of its identity
 * provider rather than in its JWK Set.
 *
 * It is the bundle's because it is two things at once: an algorithm the generator of the core draws pairs for, which
 * is JOSE's, and a key of the SAML module, which the core does not know; only the bundle sees both. It is wired when
 * a deployment enables "beffroi.saml.identity_provider", and by nothing else, so that a deployment that serves no SAML
 * draws no such key.
 */
final readonly class SamlSigning implements JoseKeyAlgorithmInterface, SamlSigningAlgorithmInterface
{
    public const string NAME = 'SAML-SIGNING';

    public function __construct(
        private RsaKeyBits $keyBits = new RsaKeyBits(),
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    /**
     * RSA, the only key Dsig takes (D-16).
     */
    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function generateKey(): JWK
    {
        return JWKFactory::createRSAKey($this->keyBits->value, [
            'alg' => $this->name(),
            'use' => $this->keyUse()->value,
        ]);
    }
}
