<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\ServiceProvider;

use ArgumentCountError;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 5.2, S-9, S-11, S-19: what a reading of the metadata of a service provider returns, and what
 * it says of the key an assertion is encrypted for.
 */
final class ServiceProviderMetadataTest extends TestCase
{
    /**
     * S-9, S-11: whether the provider signs its requests and the keys that verify them are never defaulted, so that a
     * reading that leaves them out fails where it is written rather than reporting a provider that says nothing and
     * holds no key. PHPStan refuses the call below at level max, and the ignore it carries is itself refused once the
     * call is allowed again, PHPStan reporting an ignore that matches nothing.
     */
    #[Test]
    public function aReadingCannotLeaveOutWhatDecidesTheSignatureOfARequest(): void
    {
        // Then
        $this->expectException(ArgumentCountError::class);
        $this->expectExceptionMessageIsOrContains('3 passed');

        // When
        new ServiceProviderMetadata('https://sp.example.com/saml', null, []); // @phpstan-ignore arguments.count, new.resultUnused (the contract is broken on purpose)
    }

    /**
     * S-6: whether the document was read under the signers the declaration pins is said by the reading, which is the
     * one that knows it, and never defaulted, so that a reading that leaves it out fails where it is written rather
     * than reporting a document the rule against a rollback does not hold. PHPStan refuses the call below at level
     * max, as above.
     */
    #[Test]
    public function aReadingCannotLeaveOutWhetherItWasSigned(): void
    {
        // Then
        $this->expectException(ArgumentCountError::class);
        $this->expectExceptionMessageIsOrContains('5 passed');

        // When
        new ServiceProviderMetadata('https://sp.example.com/saml', null, [], false, []); // @phpstan-ignore arguments.count, new.resultUnused (the contract is broken on purpose)
    }

    /**
     * S-19: the key an assertion is encrypted for is the first certificate for encryption, in document order, the one
     * a SimpleSAMLphp identity provider takes; none without one.
     *
     * @param list<Certificate> $certificates
     */
    #[Test]
    #[DataProvider('provideEncryptionCertificates')]
    public function itEncryptsForTheFirstCertificateForEncryption(array $certificates, ?Certificate $expected): void
    {
        // Given
        $metadata = new ServiceProviderMetadata(ServiceProviderDocuments::SIGNED, null, $certificates, false, [], readSigned: false);

        // When / Then
        static::assertEquals($expected, $metadata->encryptionCertificate());
    }

    /**
     * @return iterable<string, array{list<Certificate>, ?Certificate}>
     */
    public static function provideEncryptionCertificates(): iterable
    {
        yield 'none' => [[], null];
        yield 'one' => [[ServiceProviderDocuments::signer('sp')], ServiceProviderDocuments::signer('sp')];
        yield 'two, during a rotation of the service provider' => [
            [ServiceProviderDocuments::signer('idp'), ServiceProviderDocuments::signer('sp')],
            ServiceProviderDocuments::signer('idp'),
        ];
    }
}
