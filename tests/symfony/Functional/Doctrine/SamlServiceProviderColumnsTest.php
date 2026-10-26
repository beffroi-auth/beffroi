<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;

/**
 * beffroi/saml, spec/saml.md S-8, decision 0011: the metadata document accepted for a service provider is sealed under
 * the data key of its tenant, in the family of its own table, since its md:ContactPerson names people; the entity ID it
 * is found by stays in the clear.
 */
final class SamlServiceProviderColumnsTest extends DatabaseTestCase
{
    private const string CONTACT = SealedRows::VALUES['beffroi_saml_service_provider']['document'];

    #[Test]
    public function theDocumentIsReadBackAsTheBytesThatWereRead(): void
    {
        // Given
        $written = self::write();

        // When
        $read = self::repository()->find(self::tenant(), ServiceProviderDocuments::SIMPLESAMLPHP);

        // Then
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $read);
        static::assertSame($written->document, $read->document);
    }

    #[Test]
    public function theColumnDoesNotHoldTheDocument(): void
    {
        // Given
        self::write();

        // When
        $row = self::row();

        // Then
        static::assertStringNotContainsString(self::CONTACT, $row['document']);
        static::assertStringNotContainsString('EntityDescriptor', $row['document']);
    }

    #[Test]
    public function theEntityIdIsInTheClear(): void
    {
        // Given
        self::write();

        // When / Then
        static::assertSame(ServiceProviderDocuments::SIMPLESAMLPHP, self::row()['entity_id']);
    }

    private static function write(): AcceptedMetadata
    {
        $metadata = new SealedRows(self::getContainer(), self::tenant(), self::now())->serviceProviderMetadata();
        self::reload();

        return $metadata;
    }

    /**
     * @return array<string, string>
     */
    private static function row(): array
    {
        $rows = RawRows::of(self::connection(), 'beffroi_saml_service_provider', ['entity_id', 'document']);
        static::assertCount(1, $rows);

        $row = [];
        foreach ($rows[0] as $column => $value) {
            $row[$column] = $value ?? static::fail(sprintf('beffroi_saml_service_provider.%s holds nothing.', $column));
        }

        return $row;
    }

    private static function repository(): AcceptedMetadataRepositoryInterface
    {
        return self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
