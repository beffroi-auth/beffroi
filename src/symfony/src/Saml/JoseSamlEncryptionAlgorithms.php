<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Bridge\Algorithm\WiredAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseAlgorithmRegistryInterface;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithmInterface;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;

/**
 * The family of the keys the upstream identity providers encrypt for (beffroi/saml, spec/saml.md S-64): one algorithm
 * per provider, each tagged by what declares the provider, under the schedule of the SAML signing key (S-12). What it
 * holds is what the key commands draw, rotate and read back; a key of a provider nothing tags any more is read past by
 * the key files (DormantKeyAlgorithms), neither served nor rotated.
 */
final readonly class JoseSamlEncryptionAlgorithms implements JoseAlgorithmRegistryInterface
{
    /**
     * The tag the algorithm of the key of an upstream identity provider is wired by.
     */
    public const string TAG = 'beffroi.saml_encryption_algorithm';

    /**
     * @var WiredAlgorithms<JoseKeyAlgorithmInterface&SamlEncryptionAlgorithmInterface>
     */
    private WiredAlgorithms $wired;

    /**
     * @param iterable<JoseKeyAlgorithmInterface&SamlEncryptionAlgorithmInterface> $algorithms in the order they are wired
     */
    public function __construct(iterable $algorithms)
    {
        $this->wired = new WiredAlgorithms($algorithms);
    }

    /**
     * @return list<JoseKeyAlgorithmInterface&SamlEncryptionAlgorithmInterface>
     */
    public function all(): array
    {
        return $this->wired->algorithms;
    }

    public function find(string $name): ?JoseKeyAlgorithmInterface
    {
        return $this->wired->named($name);
    }

    public function refusalOf(string $name): UnsupportedAlgorithmException
    {
        return $this->wired->refusalOf(
            $name,
            'No SAML identity provider encrypts for a key named "%s"; those that do encrypt for %s.',
            'No SAML identity provider encrypts for a key named "%s"; none is declared.',
        );
    }
}
