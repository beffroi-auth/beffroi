<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * The key one upstream identity provider encrypts an assertion for (beffroi/saml, spec/saml.md S-64): an RSA pair of
 * the size the RSA algorithms of the core share, drawn by the generator of the core, sealed by the KMS and rotated by
 * the key commands under the name of that provider, "SAML-ENCRYPTION:" and its entity ID, as every other key of the
 * tenant, and published as a certificate in the metadata of the service provider given to that provider alone (S-65)
 * rather than in the JWK Set.
 *
 * One per provider: the core keeps one active key per algorithm, so that the key of one provider is rotated apart from
 * the others' and never answered for another (KeptDecryptionKeyProviderInterface). It is the bundle's for the reason
 * SamlSigning is: an algorithm the generator of the core draws pairs for, which is JOSE's, and a key of the SAML
 * module, which the core does not know.
 */
final readonly class SamlEncryption implements JoseKeyAlgorithmInterface, SamlEncryptionAlgorithmInterface
{
    /**
     * @param string $identityProvider the entity ID of the provider the key belongs to
     */
    public function __construct(
        private string $identityProvider,
        private RsaKeyBits $keyBits = new RsaKeyBits(),
    ) {
    }

    public function name(): string
    {
        return self::NAME_PREFIX . $this->identityProvider;
    }

    /**
     * RSA, the key RSA-OAEP transports a session key under (enc.md E-1).
     */
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

    public function generateKey(): JWK
    {
        return JWKFactory::createRSAKey($this->keyBits->value, [
            'alg' => $this->name(),
            'use' => $this->keyUse()->value,
        ]);
    }
}
