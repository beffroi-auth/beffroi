<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Upstream\ProfileAttribute;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/saml.md S-45: an attribute of an upstream identity provider that fills a claim of the profile of a person.
 */
final class ProfileAttributeTest extends TestCase
{
    /**
     * S-45: the name of the attribute and the claim it fills, as they are declared.
     */
    #[Test]
    public function anAttributeNamesTheClaimItFills(): void
    {
        // When
        $attribute = new ProfileAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'given_name');

        // Then
        static::assertSame('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', $attribute->name);
        static::assertSame('given_name', $attribute->claim);
    }

    /**
     * S-45, Core §2.7.3.1: the name of an attribute is a name, at most 1 024 characters with no whitespace.
     */
    #[Test]
    #[DataProvider('provideWhatIsNoName')]
    public function anAttributeThatIsNoNameIsRefused(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The name of an attribute is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).');

        // When
        new ProfileAttribute($name, 'given_name');
    }

    /**
     * S-45: the claim an attribute fills is a claim name.
     */
    #[Test]
    #[DataProvider('provideWhatIsNoName')]
    public function aClaimThatIsNoNameIsRefused(string $claim): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The claim an attribute fills is a claim name, not empty and with no whitespace (spec/saml.md S-45).');

        // When
        new ProfileAttribute('givenName', $claim);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoName(): iterable
    {
        yield 'nothing' => [''];
        yield 'a space' => ['given name'];
        yield 'more than 1024 characters' => [str_repeat('a', 1025)];
    }
}
