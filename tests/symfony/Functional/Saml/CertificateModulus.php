<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Core\Domain\Key\TenantKey;
use function base64_decode;
use function chunk_split;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_x509_read;
use PHPUnit\Framework\Assert;
use function strtr;

/**
 * Whether a certificate the metadata of a tenant publish is around the public half of a SAML key of the tenant
 * (beffroi/saml, spec/saml.md S-3): the RSA modulus of the one, read by OpenSSL, and the "n" of the public JWK of the
 * other, as bytes.
 */
final class CertificateModulus
{
    /**
     * @param string $certificate the base64 of the DER, as an X509Certificate carries it
     */
    public static function ofCertificate(string $certificate): string
    {
        $x509 = openssl_x509_read("-----BEGIN CERTIFICATE-----\n" . chunk_split($certificate, 64, "\n") . "-----END CERTIFICATE-----\n");
        Assert::assertNotFalse($x509);
        $public = openssl_pkey_get_public($x509);
        Assert::assertNotFalse($public);
        $details = openssl_pkey_get_details($public);
        Assert::assertIsArray($details);
        Assert::assertIsArray($details['rsa'] ?? null);
        $modulus = $details['rsa']['n'] ?? null;
        Assert::assertIsString($modulus);

        return $modulus;
    }

    public static function ofKey(TenantKey $key): string
    {
        $n = $key->publicJwk['n'] ?? null;
        Assert::assertIsString($n);
        $modulus = base64_decode(strtr($n, '-_', '+/'), true);
        Assert::assertIsString($modulus);

        return $modulus;
    }
}
