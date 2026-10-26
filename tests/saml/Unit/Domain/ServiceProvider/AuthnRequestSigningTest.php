<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\ServiceProvider;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-9, section 6.3 step 2: whether the requests of a service provider need a signature, read from its
 * declaration and its accepted metadata.
 */
final class AuthnRequestSigningTest extends TestCase
{
    private const string ENTITY_ID = 'https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/';

    /**
     * S-9, the table of section 6.3 step 2: a request is unsigned only where the declaration says the provider does
     * not sign and its metadata do not say it does, the provider's own statement winning towards safety.
     */
    #[Test]
    #[DataProvider('provideTheStatementsOfAProvider')]
    public function itRequiresASignatureUnlessTheProviderSaysItDoesNotSign(
        bool $signsAuthnRequests,
        bool $authnRequestsSigned,
        bool $required,
    ): void {
        // Given
        $declaration = new ServiceProvider(self::ENTITY_ID, new MetadataLocation('/etc/beffroi/entra.xml'), signsAuthnRequests: $signsAuthnRequests);
        $metadata = new ServiceProviderMetadata(self::ENTITY_ID, null, [], $authnRequestsSigned, [], readSigned: false);

        // When
        $signing = AuthnRequestSigning::of($declaration, $metadata);

        // Then
        static::assertSame($required, $signing->required);
        static::assertSame(self::ENTITY_ID, $signing->entityId);
    }

    /**
     * @return iterable<string, array{bool, bool, bool}>
     */
    public static function provideTheStatementsOfAProvider(): iterable
    {
        yield 'declared signing, metadata signing' => [true, true, true];
        yield 'declared signing, metadata silent' => [true, false, true];
        yield 'declared unsigned, metadata signing' => [false, true, true];
        yield 'declared unsigned, metadata silent' => [false, false, false];
    }

    /**
     * Section 6.3 step 2: the declaration and the metadata of two service providers say nothing of either.
     */
    #[Test]
    public function itRefusesTheDeclarationAndTheMetadataOfTwoEntities(): void
    {
        // Given
        $declaration = new ServiceProvider(self::ENTITY_ID, new MetadataLocation('/etc/beffroi/entra.xml'), signsAuthnRequests: false);
        $metadata = new ServiceProviderMetadata('https://sp.example.com/saml', null, [], false, [], readSigned: false);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The signature a request needs is read from the declaration and the metadata of one service provider (spec/saml.md section 6.3 step 2).');

        // When
        AuthnRequestSigning::of($declaration, $metadata);
    }
}
