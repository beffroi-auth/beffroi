<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Pki;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use function base64_decode;
use function bin2hex;
use function chunk_split;
use DateTimeImmutable;
use function hash;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_parse;
use function ord;
use function sprintf;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\Certificate\Certificate as X509Certificate;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use function str_split;
use function strtr;
use function substr;

/**
 * spec/saml.md section 6.1 step 2, S-3: the self-signed certificate around a SAML key of a tenant, built with
 * pki-framework, each of its fields a function of the key and of its tenant.
 */
final class SelfSignedCertificateIssuerTest extends TestCase
{
    private Tenant $tenant;

    private TenantKey $key;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme');
        $this->key = SamlKeys::key($this->tenant, createdAt: new DateTimeImmutable('2026-10-15T09:30:12.345678Z'));
    }

    /**
     * S-3: the certificate verifies under the public key it carries, openssl_verify() returning 1 and not a value PHP
     * would hold for true.
     */
    #[Test]
    public function itVerifiesUnderItsOwnPublicKey(): void
    {
        // When
        $certificate = $this->certificateOf($this->key);

        // Then
        static::assertSame(1, openssl_verify(
            $certificate->tbsCertificate()->toASN1()->toDER(),
            $certificate->signatureValue()->bitString()->string(),
            $certificate->tbsCertificate()->subjectPublicKeyInfo()->toPEM()->string(),
            OPENSSL_ALGO_SHA256,
        ));
    }

    /**
     * Section 6.1 step 2: the public key of the certificate is the modulus and the exponent of the key's public JWK.
     */
    #[Test]
    public function itIsAroundThePublicHalfOfTheKey(): void
    {
        // When
        $certificate = $this->certificateOf($this->key);

        // Then
        $public = openssl_pkey_get_public($certificate->tbsCertificate()->subjectPublicKeyInfo()->toPEM()->string());
        static::assertNotFalse($public);
        $details = openssl_pkey_get_details($public);
        static::assertIsArray($details);
        static::assertIsArray($details['rsa'] ?? null);
        static::assertSame(
            [self::base64url($this->key->publicJwk['n']), self::base64url($this->key->publicJwk['e'])],
            [$details['rsa']['n'] ?? null, $details['rsa']['e'] ?? null],
        );
    }

    /**
     * Section 6.1 step 2: version 3, its subject and its issuer the slug of the tenant, valid from the creation of the
     * key to the second for ten years, its serial number one more than the first seven bytes of the SHA-256 of the
     * kid, signed sha256WithRSAEncryption.
     */
    #[Test]
    public function itCarriesTheFieldsOfTheKeyAndOfItsTenant(): void
    {
        // When
        $tbs = $this->certificateOf($this->key)->tbsCertificate();

        // Then
        static::assertSame(
            [
                TBSCertificate::VERSION_3,
                (string) self::serialNumberOf($this->key->kid),
                'cn=acme',
                'cn=acme',
                '2026-10-15T09:30:12+00:00',
                '2036-10-15T09:30:12+00:00',
                '1.2.840.113549.1.1.11',
            ],
            [
                $tbs->version(),
                $tbs->serialNumber(),
                $tbs->subject()->toString(),
                $tbs->issuer()->toString(),
                $tbs->validity()->notBefore()->dateTime()->format(DATE_ATOM),
                $tbs->validity()->notAfter()->dateTime()->format(DATE_ATOM),
                $tbs->signature()->oid(),
            ],
        );
    }

    /**
     * Section 6.1 step 2: the certificate is valid ten years from the creation of its key, to the second, in UTC.
     */
    #[Test]
    #[DataProvider('provideCreations')]
    public function itIsValidTenYearsFromTheCreationOfItsKey(string $createdAt, string $notAfter): void
    {
        // Given
        $key = SamlKeys::key($this->tenant, createdAt: new DateTimeImmutable($createdAt));

        // When
        $validity = $this->certificateOf($key)->tbsCertificate()->validity();

        // Then
        static::assertSame($notAfter, $validity->notAfter()->dateTime()->format(DATE_ATOM));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCreations(): iterable
    {
        yield 'a key of 2026' => ['2026-10-15T09:30:12.345678Z', '2036-10-15T09:30:12+00:00'];
        yield 'a key created on a leap day' => ['2028-02-29T00:00:00Z', '2038-03-01T00:00:00+00:00'];
        yield 'a key created at another offset' => ['2031-01-01T00:30:00+02:00', '2040-12-31T22:30:00+00:00'];
    }

    /**
     * Section 6.1 step 2, RFC 5280 §4.1.2.5: the end of the validity is before 2050, so it is written as UTCTime, the
     * two digits of its year and its seconds, as OpenSSL reads it from the DER.
     */
    #[Test]
    public function itWritesTheEndOfItsValidityAsUtcTime(): void
    {
        // Given
        $base64 = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key))->base64;

        // When
        $parsed = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n" . chunk_split($base64, 64, "\n") . "-----END CERTIFICATE-----\n");

        // Then
        static::assertIsArray($parsed);
        static::assertSame('361015093012Z', $parsed['validTo'] ?? null);
    }

    /**
     * Section 6.1 step 2, RFC 4055 §5: the certificate is signed sha256WithRSAEncryption, its parameters NULL, which a
     * producer must write, in the certificate and in what it signed.
     */
    #[Test]
    public function itIsSignedSha256WithRsaEncryptionWithNullParameters(): void
    {
        // When
        $certificate = $this->certificateOf($this->key);

        // Then
        static::assertSame(
            ['300d06092a864886f70d01010b0500', '300d06092a864886f70d01010b0500'],
            [
                bin2hex($certificate->signatureAlgorithm()->toASN1()->toDER()),
                bin2hex($certificate->tbsCertificate()->signature()->toASN1()->toDER()),
            ],
        );
    }

    /**
     * Section 6.1 step 2, RFC 5280 §4.2.1.3: one extension, keyUsage with digitalSignature alone, critical.
     */
    #[Test]
    public function itMayOnlySign(): void
    {
        // When
        $extensions = $this->certificateOf($this->key)->tbsCertificate()->extensions();

        // Then
        $keyUsage = $extensions->keyUsage();
        static::assertSame(
            [1, true, true, false, false, false, false, false, false, false, false],
            [
                $extensions->count(),
                $keyUsage->isCritical(),
                $keyUsage->isDigitalSignature(),
                $keyUsage->isNonRepudiation(),
                $keyUsage->isKeyEncipherment(),
                $keyUsage->isDataEncipherment(),
                $keyUsage->isKeyAgreement(),
                $keyUsage->isKeyCertSign(),
                $keyUsage->isCRLSign(),
                $keyUsage->isEncipherOnly(),
                $keyUsage->isDecipherOnly(),
            ],
        );
    }

    /**
     * S-65, RFC 5280 §4.2.1.3: the certificate of the key an upstream identity provider encrypts for has one extension,
     * keyUsage with keyEncipherment alone, critical.
     */
    #[Test]
    public function itMayOnlyTransportKeysForTheKeyOfAnIdentityProvider(): void
    {
        // Given
        $key = SamlKeys::encryptionKey($this->tenant, 'https://idp.example/metadata');

        // When
        $extensions = $this->certificateOf($key)->tbsCertificate()->extensions();

        // Then
        $keyUsage = $extensions->keyUsage();
        static::assertSame(
            [1, true, false, false, true, false, false, false, false, false, false],
            [
                $extensions->count(),
                $keyUsage->isCritical(),
                $keyUsage->isDigitalSignature(),
                $keyUsage->isNonRepudiation(),
                $keyUsage->isKeyEncipherment(),
                $keyUsage->isDataEncipherment(),
                $keyUsage->isKeyAgreement(),
                $keyUsage->isKeyCertSign(),
                $keyUsage->isCRLSign(),
                $keyUsage->isEncipherOnly(),
                $keyUsage->isDecipherOnly(),
            ],
        );
    }

    /**
     * S-65, S-3: the certificate of the key an upstream identity provider encrypts for verifies under the public key it
     * carries, which is the modulus of the key's public JWK.
     */
    #[Test]
    public function theCertificateOfTheKeyOfAnIdentityProviderVerifiesUnderThatKey(): void
    {
        // Given
        $key = SamlKeys::encryptionKey($this->tenant, 'https://idp.example/metadata');

        // When
        $certificate = $this->certificateOf($key);

        // Then
        $public = openssl_pkey_get_public($certificate->tbsCertificate()->subjectPublicKeyInfo()->toPEM()->string());
        static::assertNotFalse($public);
        $details = openssl_pkey_get_details($public);
        static::assertIsArray($details);
        static::assertIsArray($details['rsa'] ?? null);
        static::assertSame(
            [1, self::base64url($key->publicJwk['n'])],
            [
                openssl_verify(
                    $certificate->tbsCertificate()->toASN1()->toDER(),
                    $certificate->signatureValue()->bitString()->string(),
                    $public,
                    OPENSSL_ALGO_SHA256,
                ),
                $details['rsa']['n'] ?? null,
            ],
        );
    }

    /**
     * S-3: built twice, the certificate is the same bytes, so that two processes publish the same one.
     */
    #[Test]
    public function itIsTheSameBytesWhenBuiltAgain(): void
    {
        // Given
        $issuer = new SelfSignedCertificateIssuer();
        $first = $issuer->selfSigned(SamlKeys::opened($this->key));

        // When
        $second = $issuer->selfSigned(SamlKeys::opened($this->key));

        // Then
        static::assertSame($first->base64, $second->base64);
    }

    /**
     * Section 6.1 step 2: a private half whose modulus is not the one of the public JWK is refused before anything is
     * signed.
     */
    #[Test]
    public function itRefusesAPrivateHalfThatIsNotTheKeys(): void
    {
        // Given
        $opened = new UnsealedKey($this->key, SamlKeys::otherPair()->privateJwk);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The private half of the key "%s" is not the one of its public JWK: its "n" differs (spec/saml.md section 6.1 step 2).',
            $this->key->kid,
        ));

        // When
        new SelfSignedCertificateIssuer()->selfSigned($opened);
    }

    /**
     * Section 5.1, S-1: the key of any other algorithm is not one whose certificate the metadata publishes, an RSA key
     * of the JWK Set among them.
     */
    #[Test]
    public function itRefusesAKeyThatIsNotASamlSigningKey(): void
    {
        // Given
        $pair = Keys::pair();
        $key = SamlKeys::key($this->tenant, $pair, algorithm: Algorithms::rs256());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The key "%s" is of RS256, not a SAML key: its certificate is not one the metadata publishes (spec/saml.md section 6.1 step 2).',
            $pair->kid,
        ));

        // When
        new SelfSignedCertificateIssuer()->selfSigned(new UnsealedKey($key, $pair->privateJwk));
    }

    /**
     * Section 6.1 step 2: every member of the private RSA JWK is a base64url integer of RFC 7518 §6.3.
     *
     * @param array<string, string> $privateJwk
     */
    #[Test]
    #[DataProvider('provideBrokenMembers')]
    public function itRefusesAMemberThatIsNotABase64UrlInteger(string $member, array $privateJwk): void
    {
        // Given
        $opened = new UnsealedKey($this->key, $privateJwk);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The member "%s" of the key "%s" is not a base64url integer of RFC 7518 section 6.3.',
            $member,
            $this->key->kid,
        ));

        // When
        new SelfSignedCertificateIssuer()->selfSigned($opened);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideBrokenMembers(): iterable
    {
        $private = SamlKeys::pair()->privateJwk;
        $without = $private;
        unset($without['qi']);

        yield 'a member missing' => ['qi', $without];
        yield 'an empty member' => ['d', [...$private, 'd' => '']];
        yield 'a member out of the alphabet' => ['p', [...$private, 'p' => 'not*base64']];
    }

    private function certificateOf(TenantKey $key): X509Certificate
    {
        $der = base64_decode(new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($key))->base64, true);
        static::assertIsString($der);

        return X509Certificate::fromDER($der);
    }

    private static function base64url(string $value): string
    {
        $bytes = base64_decode(strtr($value, '-_', '+/'), true);
        static::assertIsString($bytes);

        return $bytes;
    }

    /**
     * Written apart from the issuer, so that the test does not read the rule from the code it tests.
     */
    private static function serialNumberOf(string $kid): int
    {
        $serial = 0;
        foreach (str_split(substr(hash('sha256', $kid, true), 0, 7)) as $byte) {
            $serial = ($serial * 256) + ord($byte);
        }

        return $serial + 1;
    }
}
