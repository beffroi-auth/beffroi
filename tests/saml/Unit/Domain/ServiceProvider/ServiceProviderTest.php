<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\ServiceProvider;

use function array_fill;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\AttributeMapping;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use function range;
use function sprintf;
use function str_repeat;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-5, section 5.2, section 6.2 step 1: a service provider as the deployment declares it.
 */
final class ServiceProviderTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    /**
     * S-7 and issue #730: a declaration asks for no encryption and says its requests are signed unless it says
     * otherwise, and its metadata are trusted by their channel unless it pins a signer.
     */
    #[Test]
    public function aDeclarationAsksForNoEncryptionAndSignsItsRequestsUnlessItSaysOtherwise(): void
    {
        // When
        $serviceProvider = new ServiceProvider(self::ENTITY_ID, self::location());

        // Then
        static::assertFalse($serviceProvider->encryptAssertions);
        static::assertTrue($serviceProvider->signsAuthnRequests);
        static::assertFalse($serviceProvider->readsSigned());
        static::assertSame([], $serviceProvider->attributes);
    }

    /**
     * S-5: a declaration that pins a signer of its metadata has them verified, readSigned().
     */
    #[Test]
    public function aDeclarationThatPinsASignerReadsItsMetadataSigned(): void
    {
        // Given
        $serviceProvider = new ServiceProvider(self::ENTITY_ID, self::location(), [ServiceProviderDocuments::signer()]);

        // When / Then
        static::assertTrue($serviceProvider->readsSigned());
    }

    /**
     * Section 7: sixteen signers and 256 attributes are within the bounds.
     */
    #[Test]
    public function aDeclarationAtItsBoundsIsAccepted(): void
    {
        // When
        $serviceProvider = new ServiceProvider(self::ENTITY_ID, self::location(), self::signers(16), self::attributes(256));

        // Then
        static::assertCount(16, $serviceProvider->metadataSigners);
        static::assertCount(256, $serviceProvider->attributes);
    }

    /**
     * Section 6.2 step 1, Core §8.3.6, the entityIDType of Metadata §2.2.1: an entity ID is at most 1024 characters,
     * counted as characters and not as the bytes UTF-8 writes them in.
     */
    #[Test]
    #[DataProvider('provideEntityIdsOf1024Characters')]
    public function anEntityIdOf1024CharactersIsAccepted(string $entityId): void
    {
        // When
        $serviceProvider = new ServiceProvider($entityId, self::location());

        // Then
        static::assertSame($entityId, $serviceProvider->entityId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEntityIdsOf1024Characters(): iterable
    {
        yield 'ASCII' => ['https://' . str_repeat('a', 1016)];
        yield 'two bytes each in UTF-8' => [str_repeat('é', 1024)];
        yield 'three bytes each in UTF-8' => ['urn:' . str_repeat('€', 1020)];
    }

    /**
     * @param list<Certificate> $signers
     * @param list<AttributeMapping> $attributes
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatDoNotHoldTogether')]
    public function itRefusesADeclarationThatDoesNotHoldTogether(string $entityId, array $signers, array $attributes, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new ServiceProvider($entityId, self::location(), $signers, $attributes);
    }

    /**
     * @return iterable<string, array{string, list<Certificate>, list<AttributeMapping>, string}>
     */
    public static function provideDeclarationsThatDoNotHoldTogether(): iterable
    {
        $entityId = 'The entity ID of a service provider is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md section 6.2 step 1).';
        yield 'an empty entity ID' => ['', [], [], $entityId];
        yield 'an entity ID with a trailing space' => [self::ENTITY_ID . ' ', [], [], $entityId];
        yield 'an entity ID of 1025 characters' => ['https://' . str_repeat('a', 1017), [], [], $entityId];
        yield 'an entity ID of 1025 characters that are not ASCII' => [str_repeat('é', 1025), [], [], $entityId];
        yield 'an entity ID that is not UTF-8' => ["https://sp.example.com/\xC3", [], [], $entityId];
        yield 'seventeen signers' => [
            self::ENTITY_ID,
            self::signers(17),
            [],
            'A service provider pins at most 16 signers of its metadata (spec/saml.md section 7).',
        ];
        yield '257 attributes' => [self::ENTITY_ID, [], self::attributes(257), 'A service provider is sent at most 256 attributes (spec/saml.md section 7).'];
        yield 'two attributes of one name' => [
            self::ENTITY_ID,
            [],
            [new AttributeMapping('email', 'mail', AttributeNameFormat::Basic), new AttributeMapping('preferred_username', 'mail', AttributeNameFormat::Basic)],
            'Two attributes of a service provider share a name (spec/saml.md section 6.2 step 1).',
        ];
    }

    /**
     * One claim sent under two names is two attributes of distinct names.
     */
    #[Test]
    public function oneClaimMaySendTwoAttributes(): void
    {
        // When
        $serviceProvider = new ServiceProvider(
            self::ENTITY_ID,
            self::location(),
            [],
            [
                new AttributeMapping('email', 'urn:oid:0.9.2342.19200300.100.1.3'),
                new AttributeMapping('email', 'mail', AttributeNameFormat::Basic),
            ],
        );

        // Then
        static::assertCount(2, $serviceProvider->attributes);
    }

    private static function location(): MetadataLocation
    {
        return new MetadataLocation('https://sp.example.com/saml/metadata');
    }

    /**
     * @return list<Certificate>
     */
    private static function signers(int $count): array
    {
        return array_fill(0, $count, ServiceProviderDocuments::signer());
    }

    /**
     * @return list<AttributeMapping>
     */
    private static function attributes(int $count): array
    {
        $attributes = [];
        foreach (range(1, $count) as $index) {
            $attributes[] = new AttributeMapping('email', sprintf('urn:example:attribute:%d', $index));
        }

        return $attributes;
    }
}
