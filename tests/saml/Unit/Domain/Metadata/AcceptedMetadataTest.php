<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-6, S-8, section 6.2 step 6: the document read takes the place of the accepted one, an older one read
 * signed refused.
 */
final class AcceptedMetadataTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    private const string ACCEPTED = '<md:EntityDescriptor/>';

    private const string NEWER = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>';

    /**
     * S-8, section 6.2 step 6: the accepted document is the bytes that were read, so a refresh that reads them again
     * writes nothing.
     */
    #[Test]
    public function itHoldsTheBytesThatWereRead(): void
    {
        // Given
        $accepted = self::accepted(new DateTimeImmutable('2026-10-01T00:00:00Z'));

        // When / Then
        static::assertTrue($accepted->holds(self::ACCEPTED));
    }

    /**
     * S-8, section 6.2 step 6: bytes that differ by one are another document, compared as they were read and never
     * normalised.
     */
    #[Test]
    public function itDoesNotHoldOtherBytes(): void
    {
        // Given
        $accepted = self::accepted(null);

        // When / Then
        static::assertFalse($accepted->holds(self::ACCEPTED . "\n"));
    }

    /**
     * S-6, section 6.2 step 6: a document read signed that is not older than the accepted one takes its place, its
     * bytes, its validUntil and the instant of the clock; two without validUntil cannot be told apart, and the newer
     * reading replaces the older (section 12).
     */
    #[Test]
    #[DataProvider('provideNewerDocuments')]
    public function aSignedDocumentThatIsNotOlderTakesItsPlace(?DateTimeImmutable $accepted, ?DateTimeImmutable $newer): void
    {
        // Given
        $metadata = self::accepted($accepted);
        $at = Fixtures::now()->modify('+1 hour');

        // When
        $metadata->replaceWith(self::read($newer, readSigned: true), self::NEWER, $at);

        // Then
        static::assertSame(self::NEWER, $metadata->document);
        static::assertEquals($newer, $metadata->validUntil);
        static::assertSame($at, $metadata->acceptedAt);
    }

    /**
     * @return iterable<string, array{?DateTimeImmutable, ?DateTimeImmutable}>
     */
    public static function provideNewerDocuments(): iterable
    {
        yield 'a later validUntil' => [new DateTimeImmutable('2026-10-01T00:00:00Z'), new DateTimeImmutable('2026-10-01T00:00:01Z')];
        yield 'the same validUntil' => [new DateTimeImmutable('2026-10-01T00:00:00Z'), new DateTimeImmutable('2026-10-01T00:00:00Z')];
        yield 'a validUntil where the accepted one had none' => [null, new DateTimeImmutable('2026-10-01T00:00:00Z')];
        yield 'neither has one, the two cannot be told apart' => [null, null];
    }

    /**
     * S-6, the acceptance of issue #729: a document read signed that is older than the one accepted is refused, the
     * accepted one kept, an older document signed by the same key verifying as well.
     */
    #[Test]
    #[DataProvider('provideOlderDocuments')]
    public function anOlderSignedDocumentIsRefused(?DateTimeImmutable $older, string $message): void
    {
        // Given
        $metadata = self::accepted(new DateTimeImmutable('2026-10-01T00:00:00Z'));

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $metadata->replaceWith(self::read($older, readSigned: true), self::NEWER, Fixtures::now());
    }

    /**
     * @return iterable<string, array{?DateTimeImmutable, string}>
     */
    public static function provideOlderDocuments(): iterable
    {
        yield 'an earlier validUntil' => [
            new DateTimeImmutable('2026-09-30T23:59:59Z'),
            'The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).',
        ];
        yield 'no validUntil where the accepted one had one' => [
            null,
            'The metadata carry no validUntil where the document accepted carries one, so they cannot be shown not to be older (spec/saml.md S-6).',
        ];
    }

    /**
     * S-6, the security review of 20 October 2026 (finding B-1): a document its channel vouches for takes the place of
     * the accepted one whatever its validUntil, earlier, absent or later, so that a far validUntil written by whoever
     * held the channel once pins nothing.
     */
    #[Test]
    #[DataProvider('provideDocumentsTrustedByTheirChannel')]
    public function aDocumentTrustedByItsChannelTakesItsPlaceWhateverItsValidUntil(?DateTimeImmutable $read): void
    {
        // Given
        $metadata = self::accepted(new DateTimeImmutable('2099-01-01T00:00:00Z'));
        $at = Fixtures::now()->modify('+1 hour');

        // When
        $metadata->replaceWith(self::read($read, readSigned: false), self::NEWER, $at);

        // Then
        static::assertSame(self::NEWER, $metadata->document);
        static::assertEquals($read, $metadata->validUntil);
        static::assertSame($at, $metadata->acceptedAt);
    }

    /**
     * @return iterable<string, array{?DateTimeImmutable}>
     */
    public static function provideDocumentsTrustedByTheirChannel(): iterable
    {
        yield 'an earlier validUntil' => [new DateTimeImmutable('2026-10-01T00:00:00Z')];
        yield 'no validUntil where the accepted one had one' => [null];
        yield 'a later validUntil' => [new DateTimeImmutable('2099-01-01T00:00:01Z')];
    }

    /**
     * S-6, section 6.2 step 6: an older document refused leaves the accepted one as it was, its bytes, its validUntil
     * and the instant it was accepted.
     */
    #[Test]
    public function anOlderDocumentLeavesTheAcceptedOneAsItWas(): void
    {
        // Given
        $validUntil = new DateTimeImmutable('2026-10-01T00:00:00Z');
        $metadata = self::accepted($validUntil);

        // When
        try {
            $metadata->replaceWith(self::read($validUntil->modify('-1 day'), readSigned: true), self::NEWER, Fixtures::now()->modify('+1 hour'));
        } catch (MetadataRefusedException) {
        }

        // Then
        static::assertSame(self::ACCEPTED, $metadata->document);
        static::assertEquals($validUntil, $metadata->validUntil);
        static::assertEquals(Fixtures::now(), $metadata->acceptedAt);
    }

    /**
     * S-6: the validUntil is kept to the second, as its column keeps it.
     */
    #[Test]
    public function theValidUntilIsKeptToTheSecond(): void
    {
        // When
        $metadata = self::accepted(new DateTimeImmutable('2026-10-01T00:00:00.600000Z'));

        // Then
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * S-6: a document read signed whose validUntil is in the same second as the accepted one's is not older, whatever
     * their fractions, the column keeping neither.
     */
    #[Test]
    public function aValidUntilWithAFractionOfTheSameSecondIsNotOlder(): void
    {
        // Given
        $metadata = self::accepted(new DateTimeImmutable('2026-10-01T00:00:00.600000Z'));

        // When
        $metadata->replaceWith(self::read(new DateTimeImmutable('2026-10-01T00:00:00.300000Z'), readSigned: true), self::NEWER, Fixtures::now());

        // Then
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * Section 6.2 steps 4 and 6: the refresh compares the entity ID of the document to the declared one before it
     * replaces anything (S-5), so a document of another entity reaching the accepted one is a fault of the caller and
     * not a refusal.
     */
    #[Test]
    public function aDocumentOfAnotherEntityIsAProgrammingError(): void
    {
        // Given
        $metadata = self::accepted(null);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An accepted metadata document is replaced by a document of its own entity (spec/saml.md section 6.2 step 6).');

        // When
        $metadata->replaceWith(
            new ServiceProviderMetadata('https://other.example.com/saml', null, [], false, [], readSigned: false),
            self::NEWER,
            Fixtures::now(),
        );
    }

    /**
     * S-8: an accepted document holds the bytes that were read, which are never none.
     */
    #[Test]
    public function anEmptyDocumentIsNotAccepted(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An accepted metadata document holds the bytes that were read (spec/saml.md S-8).');

        // When
        new AcceptedServiceProviderMetadata(Uuid::v7(), Fixtures::tenant(), self::ENTITY_ID, '', null, Fixtures::now());
    }

    /**
     * S-8, section 6.2 step 6: an empty document replaces nothing, the accepted one holding the bytes that were read.
     */
    #[Test]
    public function anEmptyDocumentDoesNotReplaceTheAcceptedOne(): void
    {
        // Given
        $metadata = self::accepted(null);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An accepted metadata document holds the bytes that were read (spec/saml.md S-8).');

        // When
        $metadata->replaceWith(self::read(null, readSigned: false), '', Fixtures::now());
    }

    /**
     * S-8: the document is sealed in the family of its own table.
     */
    #[Test]
    public function theDocumentIsSealedInTheFamilyOfItsTable(): void
    {
        // When
        $fields = AcceptedServiceProviderMetadata::classifiedFields();

        // Then
        static::assertEquals(new Sealed('saml_service_provider'), $fields['document']);
    }

    private static function accepted(?DateTimeImmutable $validUntil): AcceptedMetadata
    {
        return new AcceptedServiceProviderMetadata(Uuid::v7(), Fixtures::tenant(), self::ENTITY_ID, self::ACCEPTED, $validUntil, Fixtures::now());
    }

    /**
     * A reading of a document of the same entity, its validUntil given, read signed or by its channel.
     */
    private static function read(?DateTimeImmutable $validUntil, bool $readSigned): ServiceProviderMetadata
    {
        return new ServiceProviderMetadata(self::ENTITY_ID, $validUntil, [], false, [], $readSigned);
    }
}
