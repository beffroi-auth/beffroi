<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\ServiceProvider;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\ServiceProvider\AttributeMapping;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use function str_repeat;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 5.2, section 6.2 step 1: a claim of the provider sent as a SAML attribute (Core §2.7.3.1), its
 * name of the uri format unless declared otherwise (Core §8.2).
 */
final class AttributeMappingTest extends TestCase
{
    private const string MAIL = 'urn:oid:0.9.2342.19200300.100.1.3';

    #[Test]
    public function itIsAnAttributeOfTheUriFormatUnlessDeclaredOtherwise(): void
    {
        // When
        $mapping = new AttributeMapping('email', self::MAIL);

        // Then
        static::assertSame('email', $mapping->claim);
        static::assertSame(self::MAIL, $mapping->name);
        static::assertSame(AttributeNameFormat::Uri, $mapping->nameFormat);
        static::assertNull($mapping->friendlyName);
    }

    /**
     * Core §8.2.1: a name of the basic format is any name, which need not be a URI.
     */
    #[Test]
    public function aNameOfTheBasicFormatNeedNotBeAUri(): void
    {
        // When
        $mapping = new AttributeMapping('email', 'mail', AttributeNameFormat::Basic, 'mail');

        // Then
        static::assertSame(AttributeNameFormat::Basic, $mapping->nameFormat);
        static::assertSame('mail', $mapping->friendlyName);
    }

    #[Test]
    #[DataProvider('provideMappingsThatAreNotOne')]
    public function itRefusesAMappingThatIsNotOne(string $claim, string $name, AttributeNameFormat $format, ?string $friendlyName, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new AttributeMapping($claim, $name, $format, $friendlyName);
    }

    /**
     * @return iterable<string, array{string, string, AttributeNameFormat, ?string, string}>
     */
    public static function provideMappingsThatAreNotOne(): iterable
    {
        $claim = 'A claim name is not empty and holds no whitespace (spec/saml.md section 6.2 step 1).';
        $name = 'An attribute name is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md section 6.2 step 1).';
        $uri = 'An attribute name of the uri format is an absolute URI (Core section 8.2.2, spec/saml.md section 6.2 step 1).';
        yield 'an empty claim' => ['', self::MAIL, AttributeNameFormat::Uri, null, $claim];
        yield 'a claim with a space' => ['family name', self::MAIL, AttributeNameFormat::Uri, null, $claim];
        yield 'an empty name' => ['email', '', AttributeNameFormat::Basic, null, $name];
        yield 'a name with a trailing line feed' => ['email', "mail\n", AttributeNameFormat::Basic, null, $name];
        yield 'a name with a no-break space' => ['email', "mail\u{a0}address", AttributeNameFormat::Basic, null, $name];
        yield 'a name of 1025 characters' => ['email', 'urn:' . str_repeat('a', 1021), AttributeNameFormat::Uri, null, $name];
        yield 'a relative name of the uri format' => ['email', 'mail', AttributeNameFormat::Uri, null, $uri];
        yield 'a name of the uri format with a fragment only' => ['email', 'urn:#mail', AttributeNameFormat::Uri, null, $uri];
        yield 'an empty friendly name' => [
            'email',
            self::MAIL,
            AttributeNameFormat::Uri,
            '',
            'A friendly name, when given, is not empty (spec/saml.md section 6.2 step 1).',
        ];
    }

    /**
     * A name of 1024 characters is within the bound of a URI (model.md section 7).
     */
    #[Test]
    public function aNameOf1024CharactersIsAccepted(): void
    {
        // Given
        $name = 'urn:' . str_repeat('a', 1020);

        // When / Then
        static::assertSame($name, new AttributeMapping('email', $name)->name);
    }

    #[Test]
    #[DataProvider('provideFormatNames')]
    public function aFormatIsNamedByTheLastSegmentOfItsUri(string $name, ?AttributeNameFormat $format): void
    {
        // When / Then
        static::assertSame($format, AttributeNameFormat::named($name));
    }

    /**
     * @return iterable<string, array{string, ?AttributeNameFormat}>
     */
    public static function provideFormatNames(): iterable
    {
        yield 'uri' => ['uri', AttributeNameFormat::Uri];
        yield 'basic' => ['basic', AttributeNameFormat::Basic];
        yield 'unspecified' => ['unspecified', AttributeNameFormat::Unspecified];
        yield 'another case' => ['URI', null];
        yield 'the whole URI' => [AttributeNameFormat::Uri->value, null];
    }
}
