<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\TenantSigning;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Port\CertificateIssuerInterface;
use Beffroi\Saml\Tests\Fixture\CountingKeySealer;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use function array_intersect_key;
use function array_map;
use function in_array;
use function is_array;
use function is_object;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 6.1 step 2, S-1, S-2, S-3: the certificate of each SAML key of a tenant in service, in creation
 * order, each key opened by the KMS at most once per process.
 */
final class SigningCertificatesTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
    }

    /**
     * S-2: the staged key, which signs nothing yet, has its certificate beside the active one's, in creation order.
     */
    #[Test]
    public function theNextCertificateIsListedBesideTheCurrentOne(): void
    {
        // Given
        $active = SamlKeys::activeKey($this->tenant);
        $staged = SamlKeys::key($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $this->keys->save($staged);
        $this->keys->save($active);

        // When
        $certificates = $this->certificates()->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$active, $staged]), self::base64($certificates));
    }

    /**
     * S-2: a key that has retired is out of the metadata.
     */
    #[Test]
    public function aRetiredKeyIsNotListed(): void
    {
        // Given
        $retired = SamlKeys::activeKey($this->tenant);
        $retired->startRetiring(Fixtures::now(), Fixtures::now());
        $retired->retire(Fixtures::now());
        $this->keys->save($retired);
        $active = SamlKeys::activeKey($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $this->keys->save($active);

        // When
        $certificates = $this->certificates()->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$active]), self::base64($certificates));
    }

    /**
     * Section 6.1 step 1, S-1: a key of any other algorithm of the tenant has no certificate in the metadata.
     */
    #[Test]
    public function aKeyOfAnotherAlgorithmIsNotListed(): void
    {
        // Given
        $this->keys->save(SamlKeys::key($this->tenant, Keys::pair(), algorithm: Algorithms::rs256()));

        // When
        $certificates = $this->certificates()->of($this->tenant);

        // Then
        static::assertSame([], $certificates);
    }

    /**
     * Section 6.1 step 2, S-3: a key is opened by the KMS once per process, whatever the number of times the metadata
     * is asked for.
     */
    #[Test]
    public function aKeyIsOpenedOncePerProcess(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::once())->method('unseal')->willReturn(SamlKeys::pair()->privateJwk);
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $certificates->of($this->tenant);

        // When
        $again = $certificates->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$key]), self::base64($again));
    }

    /**
     * S-1: what is kept of a key that has left service is forgotten with it, so that a key under that name in service
     * again is opened again rather than answered from memory.
     */
    #[Test]
    public function theCertificateOfAKeyThatLeftServiceIsForgotten(): void
    {
        // Given
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::exactly(2))->method('unseal')->willReturn(SamlKeys::pair()->privateJwk);
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);
        $certificates->of($this->tenant);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $certificates->of($this->tenant);
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $listed = $certificates->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$key]), self::base64($listed));
    }

    /**
     * S-1: forgetting the keys of one tenant leaves what was built for another as it was.
     */
    #[Test]
    public function forgettingTheKeysOfOneTenantLeavesAnotherOnesAlone(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->keys->save(SamlKeys::activeKey($other));
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::once())->method('unseal')->willReturn(SamlKeys::pair()->privateJwk);
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $certificates->of($other);

        // When
        $certificates->of($this->tenant);

        // Then
        static::assertCount(1, $certificates->of($other));
    }

    /**
     * S-1, S-3: the private half opened to build a certificate is dropped at once, the active key's as any other, so
     * that the memory of the core holds nothing once the metadata is served: the first signature of the process opens
     * the active key for itself.
     */
    #[Test]
    public function theCertificatesLeaveNoPrivateHalfOpen(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $sealer = new CountingKeySealer();
        $signingKeys = new SealedKeyProvider($this->keys, new OpenedKeys($sealer));
        new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer())->of($this->tenant);

        // When
        $signingKeys->activeKeptSigningKey($this->tenant, SamlKeys::algorithm());

        // Then
        static::assertSame(2, $sealer->unsealed);
    }

    /**
     * Section 5.3, S-3, S-37: a process that signs before it serves the metadata opens the active key once, the
     * certificate the metadata list built from the key the signature opened.
     */
    #[Test]
    public function aProcessThatSignsFirstOpensTheActiveKeyOnce(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $sealer = new CountingKeySealer();
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $signing = new TenantSigning(
            new SealedKeyProvider($this->keys, new OpenedKeys($sealer)),
            SamlKeys::algorithm(),
            $certificates,
        );
        $signing->of($this->tenant);

        // When
        $certificates->of($this->tenant);

        // Then
        static::assertSame(1, $sealer->unsealed);
    }

    /**
     * S-1, S-3: what SigningCertificates keeps between two calls is certificates. Once of() has built them, nothing it
     * holds, its collaborators aside, is a key the KMS opened or a private member of one (RFC 7518 section 6.3.2).
     */
    #[Test]
    public function theCertificatesKeepNoPrivateMember(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $sealer = Keys::sealer();
        $issuer = new SelfSignedCertificateIssuer();
        $certificates = new SigningCertificates($this->keys, $sealer, $issuer);

        // When
        $certificates->of($this->tenant);

        // Then
        static::assertSame([], self::privateHalvesIn($certificates, [$this->keys, $sealer, $issuer]));
    }

    /**
     * S-37: the certificate of a key already opened, the active one a signature is made with, is the one the metadata
     * list for it.
     */
    #[Test]
    public function theCertificateOfAnOpenedKeyIsTheOneListed(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);

        // When
        $certificate = $this->certificates()->ofOpened(SamlKeys::opened($key));

        // Then
        static::assertSame($this->base64Of([$key]), [$certificate->base64]);
    }

    /**
     * S-3, S-37: the certificate built for a key already opened is the one the metadata list afterwards, the KMS not
     * asked to open that key again.
     */
    #[Test]
    public function theCertificateOfAnOpenedKeyIsListedWithoutTheKms(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::never())->method('unseal');
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $certificates->ofOpened(SamlKeys::opened($key));

        // When
        $listed = $certificates->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$key]), self::base64($listed));
    }

    /**
     * S-3, S-37: the certificate of a key already opened is built once per process, whatever the number of signatures
     * that carry it.
     */
    #[Test]
    public function theCertificateOfAnOpenedKeyIsBuiltOnce(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $built = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($key));
        $issuer = self::createMock(CertificateIssuerInterface::class);
        $issuer->expects(static::once())->method('selfSigned')->willReturn($built);
        $certificates = new SigningCertificates($this->keys, Keys::sealer(), $issuer);
        $certificates->ofOpened(SamlKeys::opened($key));

        // When
        $again = $certificates->ofOpened(SamlKeys::opened($key));

        // Then
        static::assertSame($built, $again);
    }

    private function certificates(): SigningCertificates
    {
        return new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer());
    }

    /**
     * @param list<TenantKey> $keys
     *
     * @return list<string>
     */
    private function base64Of(array $keys): array
    {
        $issuer = new SelfSignedCertificateIssuer();

        return array_map(
            static fn (TenantKey $key): string => $issuer->selfSigned(SamlKeys::opened($key))->base64,
            $keys,
        );
    }

    /**
     * @param list<Certificate> $certificates
     *
     * @return list<string>
     */
    private static function base64(array $certificates): array
    {
        return array_map(static fn (Certificate $certificate): string => $certificate->base64, $certificates);
    }

    /**
     * What a value holds of the private half of the SAML pair: an opened key, or the value of one of its private
     * members, looked for through every property of every object, whatever its visibility, as an array cast reads
     * them, and through every array, the collaborators named left out.
     *
     * @param list<object> $collaborators
     *
     * @return list<string>
     */
    private static function privateHalvesIn(mixed $value, array $collaborators): array
    {
        if ($value instanceof UnsealedKey) {
            return ['a key the KMS opened'];
        }
        if (is_object($value) && in_array($value, $collaborators, true)) {
            return [];
        }
        if (is_object($value) || is_array($value)) {
            $found = [];
            foreach ((array) $value as $held) {
                $found = [...$found, ...self::privateHalvesIn($held, $collaborators)];
            }

            return $found;
        }
        $private = array_intersect_key(SamlKeys::pair()->privateJwk, ['d' => 0, 'p' => 0, 'q' => 0, 'dp' => 0, 'dq' => 0, 'qi' => 0]);

        return in_array($value, $private, true) ? ['a private member of the key'] : [];
    }
}
