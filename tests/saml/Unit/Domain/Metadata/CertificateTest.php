<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 5.1: a certificate is the base64 of its DER in the alphabet of RFC 4648 §4, so that what is
 * published is what was built.
 */
final class CertificateTest extends TestCase
{
    #[Test]
    public function itKeepsTheBase64ItIsGiven(): void
    {
        // When / Then
        static::assertSame('MIIBAA==', new Certificate('MIIBAA==')->base64);
    }

    /**
     * S-37, RFC 7468 §5: the certificate as a PEM, in lines of 64 characters, as OpenSSL writes it.
     */
    #[Test]
    public function itIsWrittenAsAPem(): void
    {
        // When / Then
        static::assertSame(MetadataFixtures::certificatePem('sp'), new Certificate(MetadataFixtures::certificate('sp'))->pem());
    }

    #[Test]
    #[DataProvider('provideValuesThatAreNotCanonicalBase64')]
    public function itRefusesWhatIsNotTheCanonicalBase64OfSomeBytes(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).');

        // When
        new Certificate($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatAreNotCanonicalBase64(): iterable
    {
        yield 'empty' => [''];
        yield 'out of the alphabet' => ['MIIB*A=='];
        yield 'the URL-safe alphabet' => ['MIIB_-=='];
        yield 'without its padding' => ['MIIBAA'];
        yield 'with a line break' => ["MIIB\nAA=="];
        yield 'with an unused bit set' => ['MIIBAB=='];
    }
}
