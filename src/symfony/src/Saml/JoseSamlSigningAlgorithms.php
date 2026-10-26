<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Bridge\Algorithm\WiredAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseAlgorithmRegistryInterface;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithmInterface;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;

/**
 * The algorithms of the keys a tenant signs its SAML messages with, as the wiring gave them: one more registry the
 * key commands and the key files read through JoseKeyAlgorithms, so that a SAML key is generated, stored, read back
 * and rotated as every other key of the tenant (spec/saml.md S-1, S-2). A deployment that serves no SAML wires none,
 * and an empty registry is then a deployment and not a mistake.
 */
final readonly class JoseSamlSigningAlgorithms implements JoseAlgorithmRegistryInterface
{
    /**
     * The tag an algorithm of a SAML signing key is wired by.
     */
    public const string TAG = 'beffroi.saml_signing_algorithm';

    /**
     * @var WiredAlgorithms<JoseKeyAlgorithmInterface&SamlSigningAlgorithmInterface>
     */
    private WiredAlgorithms $wired;

    /**
     * @param iterable<JoseKeyAlgorithmInterface&SamlSigningAlgorithmInterface> $algorithms in the order they are wired
     */
    public function __construct(iterable $algorithms)
    {
        $this->wired = new WiredAlgorithms($algorithms);
    }

    /**
     * @return list<JoseKeyAlgorithmInterface&SamlSigningAlgorithmInterface>
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
            'This provider signs no SAML message with a key named "%s"; it signs them with %s.',
            'This provider signs no SAML message with a key named "%s"; it serves no SAML.',
        );
    }
}
