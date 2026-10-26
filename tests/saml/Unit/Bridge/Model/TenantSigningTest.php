<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-15, S-37: what signs for a tenant, its active SAML key, and the certificate the metadata publish for
 * that key, which every signature of the provider carries in its KeyInfo.
 */
final class TenantSigningTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private TenantKey $key;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($this->key);
    }

    /**
     * S-37: the certificate a signature carries is the one the metadata publish for the active key, as a PEM.
     */
    #[Test]
    public function itCarriesTheCertificateOfTheActiveKey(): void
    {
        // When
        $signing = SamlKeys::signing($this->keys)->of($this->tenant);

        // Then
        static::assertSame(new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key))->pem(), $signing->certificatePem);
    }

    /**
     * S-2, S-37: the certificate of a key staged beside the active one, which the metadata list too, is carried by no
     * signature, since that key signs nothing yet.
     */
    #[Test]
    public function theCertificateOfAStagedKeyIsNotCarried(): void
    {
        // Given
        $this->keys->save(SamlKeys::key($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day')));

        // When
        $signing = SamlKeys::signing($this->keys)->of($this->tenant);

        // Then
        static::assertSame(new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key))->pem(), $signing->certificatePem);
    }
}
