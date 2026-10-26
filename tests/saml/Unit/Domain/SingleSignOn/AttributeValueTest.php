<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleSignOn;

use function array_map;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-16, XML 1.0 §2.2: an attribute value holds the characters XML carries, in UTF-8, and is the text of a
 * claim.
 */
final class AttributeValueTest extends TestCase
{
    private const string REFUSED = 'An attribute value holds only the characters of XML 1.0, in UTF-8: no NUL, no other control character but the tab, the line feed and the carriage return, no surrogate, no U+FFFE or U+FFFF (spec/saml.md S-16).';

    /**
     * S-16: a character outside the Char production, or bytes that are not UTF-8, refused when the value is built,
     * rather than cut by the DOM or refused by the serializer once signed.
     */
    #[Test]
    #[DataProvider('provideValuesXmlDoesNotCarry')]
    public function aValueXmlDoesNotCarryIsRefused(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        new AttributeValue($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesXmlDoesNotCarry(): iterable
    {
        yield 'a NUL inside' => ["Ali\0ce"];
        yield 'a NUL at the end' => ["Alice\0"];
        yield 'a control character' => ["Ali\x01ce"];
        yield 'the last control character before the space' => ["Ali\x1Fce"];
        yield 'a vertical tab' => ["Ali\x0Bce"];
        yield 'a form feed' => ["Ali\x0Cce"];
        yield 'U+FFFE' => ["Ali\u{FFFE}ce"];
        yield 'U+FFFF' => ["Ali\u{FFFF}ce"];
        yield 'a surrogate, encoded as UTF-8 would not' => ["Ali\xED\xA0\x80ce"];
        yield 'bytes that are not UTF-8' => ["Ali\xC3ce"];
        yield 'Latin-1' => ["Andr\xE9"];
    }

    /**
     * S-16: the characters XML carries are kept as they are, the three whitespace control characters among them.
     */
    #[Test]
    #[DataProvider('provideValuesXmlCarries')]
    public function aValueXmlCarriesIsKept(string $value): void
    {
        // When / Then
        static::assertSame($value, new AttributeValue($value)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesXmlCarries(): iterable
    {
        yield 'a tab' => ["Ali\tce"];
        yield 'a line feed' => ["Ali\nce"];
        yield 'a carriage return' => ["Ali\rce"];
        yield 'an accented name' => ["Andr\u{E9}"];
        yield 'the last character before the surrogates' => ["\u{D7FF}"];
        yield 'the first character after the surrogates' => ["\u{E000}"];
        yield 'the last character before U+FFFE' => ["\u{FFFD}"];
        yield 'a character beyond the plane' => ["\u{1F600}"];
        yield 'nothing' => [''];
    }

    /**
     * S-16, XML Schema Part 2 §3.2.2.1: the text of a claim as the provider serves it.
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideClaims')]
    public function aClaimIsTurnedIntoItsValues(mixed $claim, array $expected): void
    {
        // When / Then
        static::assertSame($expected, array_map(static fn (AttributeValue $value): string => $value->value, AttributeValue::ofClaim($claim)));
    }

    /**
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function provideClaims(): iterable
    {
        yield 'a string' => ['alice@example.com', ['alice@example.com']];
        yield 'an integer' => [1_789_000_000, ['1789000000']];
        yield 'true' => [true, ['true']];
        yield 'false' => [false, ['false']];
        yield 'a list' => [
            ['admins', 7,   false],
            ['admins', '7', 'false'],
        ];
        yield 'an empty list' => [[], []];
    }

    /**
     * S-16: a claim that is not text is not sent rather than written as something else.
     */
    #[Test]
    #[DataProvider('provideClaimsThatAreNotText')]
    public function aClaimThatIsNotTextIsRefused(mixed $claim, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        AttributeValue::ofClaim($claim);
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideClaimsThatAreNotText(): iterable
    {
        yield 'a JSON object, the address' => [
            ['locality' => 'Lyon', 'country' => 'FR'],
            'A claim whose value is a JSON object is not the value of an attribute (spec/saml.md S-16).',
        ];
        yield 'a number with a fraction' => [
            1.5,
            'A value of a claim is a string, an integer or a boolean to be the value of an attribute (spec/saml.md S-16).',
        ];
        yield 'a list holding a list' => [
            [['admins']],
            'A value of a claim is a string, an integer or a boolean to be the value of an attribute (spec/saml.md S-16).',
        ];
        yield 'a list holding a value XML does not carry' => [["Ali\0ce"], self::REFUSED];
    }
}
