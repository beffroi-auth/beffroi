<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\DeclaredClaims;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Spec/saml.md S-16, section 6.2 step 1: the claims the declarations map, served as they are named while the container
 * is compiled, the claims of the provider being known to the running deployment only.
 */
final class DeclaredClaimsTest extends TestCase
{
    /**
     * S-16, section 6.2 step 1: the claim of every attribute mapping of every declaration is served, and nothing else.
     *
     * @param array<array-key, mixed> $declarations
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideDeclarations')]
    public function itServesTheClaimOfEveryMapping(array $declarations, array $expected): void
    {
        // When / Then
        static::assertSame($expected, DeclaredClaims::mappedBy($declarations)->names());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, list<string>}>
     */
    public static function provideDeclarations(): iterable
    {
        yield 'no declaration' => [[], []];
        yield 'a declaration without mappings' => [['https://sp.example.com/saml' => ['metadata' => '/srv/sp.xml']], []];
        yield 'two mappings' => [
            ['https://sp.example.com/saml' => ['attributes' => ['urn:a' => ['claim' => 'email'], 'urn:b' => ['claim' => 'name']]]],
            ['email', 'name'],
        ];
        yield 'a declaration without mappings before one with' => [
            [
                'https://a.example.com/saml' => ['metadata' => '/srv/a.xml'],
                'https://b.example.com/saml' => ['attributes' => ['urn:a' => ['claim' => 'email']]],
            ],
            ['email'],
        ];
        yield 'what is no mapping before a mapping' => [
            [
                'https://a.example.com/saml' => 'not a declaration',
                'https://b.example.com/saml' => ['attributes' => 'not a map'],
                'https://c.example.com/saml' => ['attributes' => ['urn:a' => 'not a mapping', 'urn:b' => ['claim' => 7], 'urn:c' => ['claim' => 'email']]],
            ],
            ['email'],
        ];
    }

    /**
     * S-45, section 6.10 step 1: the claim every attribute of the profile of every declaration of an upstream identity
     * provider fills is held, and nothing else.
     *
     * @param array<array-key, mixed> $declarations
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideUpstreamDeclarations')]
    public function itHoldsTheClaimEveryAttributeOfTheProfileFills(array $declarations, array $expected): void
    {
        // When / Then
        static::assertSame($expected, DeclaredClaims::filledBy($declarations)->names());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, list<string>}>
     */
    public static function provideUpstreamDeclarations(): iterable
    {
        yield 'no declaration' => [[], []];
        yield 'a declaration without a profile' => [['https://idp.example.com/saml' => ['metadata' => '/srv/idp.xml']], []];
        yield 'two attributes' => [
            ['https://idp.example.com/saml' => ['profile' => ['givenName' => 'given_name', 'sn' => 'family_name']]],
            ['given_name', 'family_name'],
        ];
        yield 'what is no attribute before an attribute' => [
            [
                'https://a.example.com/saml' => 'not a declaration',
                'https://b.example.com/saml' => ['profile' => 'not a map'],
                'https://c.example.com/saml' => ['profile' => ['givenName' => ['given_name'], 'sn' => 'family_name']],
            ],
            ['family_name'],
        ];
    }

    /**
     * S-16: no value is read through it, a container being compiled holding no user.
     */
    #[Test]
    public function itGivesNoValue(): void
    {
        // Given
        $claims = DeclaredClaims::mappedBy(['https://sp.example.com/saml' => ['attributes' => ['urn:a' => ['claim' => 'email']]]]);

        // When / Then
        static::assertSame([], $claims->of(Fixtures::user(), ['email']));
    }
}
