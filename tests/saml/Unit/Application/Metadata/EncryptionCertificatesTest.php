<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Tests\Fixture\CountingKeySealer;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-65, section 6.12 step 2, S-1, S-3: the certificate of each key an upstream identity provider encrypts
 * for, the newest first, each key opened by the KMS at most once per process, those of another provider kept.
 */
final class EncryptionCertificatesTest extends TestCase
{
    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private CountingKeySealer $sealer;

    private EncryptionCertificates $certificates;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->sealer = new CountingKeySealer();
        $this->certificates = new EncryptionCertificates($this->keys, $this->sealer, new SelfSignedCertificateIssuer());
    }

    /**
     * S-65: the certificate of each key of the provider, the next one before the current one, and none of another.
     */
    #[Test]
    public function theCertificatesOfTheProviderComeNewestFirst(): void
    {
        // Given
        $current = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $current->activate(Fixtures::now());
        $next = SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 1, Fixtures::now()->modify('+1 day'));
        $this->keys->save($current);
        $this->keys->save($next);
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 2));

        // When
        $certificates = $this->certificates->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame(self::base64Of([$next, $current]), self::base64($certificates));
    }

    /**
     * S-65: a retiring key is no longer announced, so that no provider takes it in its last hour; the key that took
     * over is.
     */
    #[Test]
    public function aRetiringKeyIsNoLongerAnnounced(): void
    {
        // Given
        $previous = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $previous->activate(Fixtures::now());
        $previous->startRetiring(Fixtures::now(), Fixtures::now()->modify('+1 hour'));
        $current = SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 1, Fixtures::now()->modify('+1 day'));
        $current->activate(Fixtures::now());
        $this->keys->save($previous);
        $this->keys->save($current);

        // When
        $certificates = $this->certificates->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame(self::base64Of([$current]), self::base64($certificates));
    }

    /**
     * S-3: a key is opened by the KMS once per process for its certificate, whatever the number of times the metadata
     * are asked for.
     */
    #[Test]
    public function aKeyIsOpenedOncePerProcess(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $this->certificates->of($this->tenant, self::PROVIDER);

        // When
        $this->certificates->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame(1, $this->sealer->unsealed);
    }

    /**
     * S-3: the certificates built for one provider are kept while the metadata of another are served.
     */
    #[Test]
    public function theCertificatesOfAnotherProviderAreKept(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1));
        $this->certificates->of($this->tenant, self::PROVIDER);
        $this->certificates->of($this->tenant, self::OTHER_PROVIDER);

        // When
        $this->certificates->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame(2, $this->sealer->unsealed);
    }

    /**
     * S-1: what is kept of a key that has left service is forgotten with it, so that a key under that name in service
     * again is opened again rather than answered from memory.
     */
    #[Test]
    public function theCertificateOfAKeyThatLeftServiceIsForgotten(): void
    {
        // Given
        $key = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $key->activate(Fixtures::now());
        $this->keys->save($key);
        $this->certificates->of($this->tenant, self::PROVIDER);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->certificates->of($this->tenant, self::PROVIDER);
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::PROVIDER));

        // When
        $this->certificates->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame(2, $this->sealer->unsealed);
    }

    /**
     * Section 6.12 step 1: a provider for which the tenant holds no key in service has no certificate.
     */
    #[Test]
    public function aProviderWithoutAKeyHasNoCertificate(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER));

        // When
        $certificates = $this->certificates->of($this->tenant, self::PROVIDER);

        // Then
        static::assertSame([], $certificates);
    }

    /**
     * @param list<TenantKey> $keys
     *
     * @return list<string>
     */
    private static function base64Of(array $keys): array
    {
        return array_map(
            static fn (TenantKey $key): string => new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($key))->base64,
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
}
