<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\TenantSigning;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\Certificate;
use function array_map;
use DateTimeImmutable;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * SAML signing keys under test: RSA 2048, the floor of D-16, drawn once per process because RSA generation is slow,
 * and sealed by the local KMS of the core's suite as a tenant's keys are (S-1).
 */
final class SamlKeys
{
    private static ?GeneratedKeyPair $pair = null;

    private static ?GeneratedKeyPair $otherPair = null;

    private static ?GeneratedKeyPair $weakPair = null;

    /**
     * @var array<int, GeneratedKeyPair>
     */
    private static array $encryptionPairs = [];

    public static function algorithm(): SamlSigning
    {
        return new SamlSigning();
    }

    public static function pair(): GeneratedKeyPair
    {
        return self::$pair ??= self::generate();
    }

    /**
     * A second pair of the same family, which is what a rotation stages beside the first.
     */
    public static function otherPair(): GeneratedKeyPair
    {
        return self::$otherPair ??= self::generate();
    }

    /**
     * A pair of 1 024 bits, under the floor of D-16, which Dsig refuses to sign with.
     */
    public static function weakPair(): GeneratedKeyPair
    {
        return self::$weakPair ??= self::generate(1024);
    }

    /**
     * A key of the tenant on that pair, staged, sealed by the KMS of the suite.
     */
    public static function key(
        Tenant $tenant,
        ?GeneratedKeyPair $pair = null,
        ?DateTimeImmutable $createdAt = null,
        ?KeyAlgorithmInterface $algorithm = null,
    ): TenantKey {
        $pair ??= self::pair();
        $createdAt ??= Fixtures::now();
        $algorithm ??= $pair->algorithm;

        return new TenantKey(
            $pair->kid,
            $tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            $createdAt,
            $createdAt,
        );
    }

    /**
     * The same key, active: what a tenant signs with today.
     */
    public static function activeKey(Tenant $tenant, ?GeneratedKeyPair $pair = null, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        $key = self::key($tenant, $pair, $createdAt);
        $key->activate($createdAt ?? Fixtures::now());

        return $key;
    }

    /**
     * A pair of its own for the key an upstream identity provider encrypts for, never the material of another key of
     * the suite (S-64): the first of a provider, its next one, the first of another provider.
     */
    public static function encryptionPair(int $index = 0): GeneratedKeyPair
    {
        return self::$encryptionPairs[$index] ??= self::generate();
    }

    /**
     * The key an upstream identity provider encrypts for, on that pair, staged, sealed by the KMS of the suite: its
     * public JWK names the algorithm of that provider and the use "enc" (S-64).
     */
    public static function encryptionKey(
        Tenant $tenant,
        string $identityProvider,
        int $pair = 0,
        ?DateTimeImmutable $createdAt = null,
    ): TenantKey {
        $algorithm = new SamlEncryption($identityProvider);
        $generated = self::encryptionPair($pair);
        $createdAt ??= Fixtures::now();

        return new TenantKey(
            $generated->kid,
            $tenant,
            $algorithm,
            [
                ...$generated->publicJwk,
                'alg' => $algorithm->name(),
                'use' => $algorithm->keyUse()->value,
            ],
            Keys::sealer()->seal($tenant, $generated->privateJwk),
            $createdAt,
            $createdAt,
        );
    }

    /**
     * The key an upstream identity provider encrypts for, on the material of a PEM, active, sealed by the KMS of the
     * suite: what a ciphertext an outside tool made for that material is opened with (S-64).
     */
    public static function encryptionKeyOfPem(Tenant $tenant, string $identityProvider, string $pem): TenantKey
    {
        $algorithm = new SamlEncryption($identityProvider);
        $private = JWKFactory::createFromKey($pem);
        $kid = $private->thumbprint('sha256');
        $public = self::members($private->toPublic());
        $key = new TenantKey(
            $kid,
            $tenant,
            $algorithm,
            [
                ...$public,
                'kid' => $kid,
                'alg' => $algorithm->name(),
                'use' => $algorithm->keyUse()->value,
            ],
            Keys::sealer()->seal($tenant, self::members($private)),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());

        return $key;
    }

    /**
     * The key opened by the KMS of the suite, as the provider opens it to sign.
     */
    public static function opened(TenantKey $key): UnsealedKey
    {
        return new UnsealedKey($key, Keys::sealer()->unseal($key->tenant, $key->sealedPrivateJwk));
    }

    /**
     * What signs for the tenants whose keys the repository holds, as the bundle wires it: their active SAML key opened
     * by the KMS of the suite, and its certificate, the one the metadata publish (S-37).
     */
    public static function signing(TenantKeyRepositoryInterface $keys): TenantSigning
    {
        return new TenantSigning(
            new SealedKeyProvider($keys, Keys::opened()),
            self::algorithm(),
            new SigningCertificates($keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
        );
    }

    /**
     * The base64 of each certificate the metadata of the tenant publish, in the creation order of the keys (S-2, S-3).
     *
     * @return list<string>
     */
    public static function published(TenantKeyRepositoryInterface $keys, Tenant $tenant): array
    {
        return array_map(
            static fn (Certificate $certificate): string => $certificate->base64,
            new SigningCertificates($keys, Keys::sealer(), new SelfSignedCertificateIssuer())->of($tenant),
        );
    }

    private static function generate(int $bits = 2048): GeneratedKeyPair
    {
        $algorithm = self::algorithm();
        $private = JWKFactory::createRSAKey($bits, [
            'alg' => $algorithm->name(),
            'use' => $algorithm->keyUse()->value,
        ]);
        $kid = $private->thumbprint('sha256');
        $private = new JWK([
            ...$private->all(),
            'kid' => $kid,
        ]);

        return new GeneratedKeyPair($kid, $algorithm, self::members($private), self::members($private->toPublic()));
    }

    /**
     * @return array<string, string>
     */
    private static function members(JWK $jwk): array
    {
        $members = [];
        foreach ($jwk->all() as $member => $value) {
            if (is_string($member) && is_string($value)) {
                $members[$member] = $value;
            }
        }

        return $members;
    }
}
