<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-5, section 6.2 step 1: the metadata of a service provider are read from an https URL or from the
 * absolute path of a file of the deployment, and nothing else.
 */
final class MetadataLocationTest extends TestCase
{
    #[Test]
    #[DataProvider('provideLocations')]
    public function itKeepsAnHttpsUrlOrAnAbsolutePath(string $location): void
    {
        // When / Then
        static::assertSame($location, new MetadataLocation($location)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLocations(): iterable
    {
        yield 'an https URL' => ['https://sp.example.com/saml/metadata'];
        yield 'an absolute path' => ['/srv/saml/sp-metadata.xml'];
    }

    #[Test]
    #[DataProvider('provideWhatIsNeither')]
    public function itRefusesWhatIsNeither(string $location): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).');

        // When
        new MetadataLocation($location);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNeither(): iterable
    {
        yield 'empty' => [''];
        yield 'a plain http URL' => ['http://sp.example.com/saml/metadata'];
        yield 'an https URL without a host' => ['https:///saml/metadata'];
        yield 'an https URL with credentials' => ['https://user@sp.example.com/saml/metadata'];
        yield 'an https URL with a space' => ['https://sp.example.com/saml metadata'];
        yield 'a relative path' => ['config/saml/sp-metadata.xml'];
        yield 'another scheme' => ['ftp://sp.example.com/metadata.xml'];
        yield 'a stream wrapper' => ['php://filter/resource=/etc/passwd'];
    }
}
