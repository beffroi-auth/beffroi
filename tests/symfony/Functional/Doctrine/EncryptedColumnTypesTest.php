<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use function array_diff;
use function array_keys;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedType;

/**
 * The plumbing every sealed column of the spike needs (decisions 0011 and 0018): the encrypted types of
 * the bundle are declared in one place, registered while the bundles boot, and each one decorates the type
 * its column would otherwise have carried.
 *
 * What gives them their encrypter is the deployment, because that choice is what decides where the data
 * key of a scope comes from; this kernel gives them a store in the memory of the process
 * (tests/symfony/config/config_test.yml), so that what is measured here is the registration and the round
 * trip and not a table.
 */
final class EncryptedColumnTypesTest extends DatabaseTestCase
{
    /**
     * A table of this test alone: no mapping of the bundle names an encrypted type yet, and the bytes a
     * column holds are what the second test below reads.
     */
    private const string TABLE = 'test_sealed_column';

    /**
     * Sixteen families of columns, one data key per tenant each (decision 0018), and twenty-eight types
     * because a type seals one type: the count of keys is the count of families and not of types.
     */
    #[Test]
    public function theBundleDeclaresOneTypePerFamilyAndPerTypeThatFamilySeals(): void
    {
        // When / Then
        static::assertCount(16, EncryptedColumnTypes::FAMILIES);
        static::assertCount(28, EncryptedColumnTypes::declarations());
    }

    /**
     * The bridge asks for the registration to happen while the container is built, which in a Symfony
     * application means booting, and never on "loadClassMetadata", which does not fire when the metadata
     * comes from the cache (README of symfony/doctrine-dbal-key-management, "Where to register the types").
     */
    #[Test]
    public function everyDeclaredTypeIsRegisteredOnceTheKernelHasBooted(): void
    {
        // Given
        $registry = Type::getTypeRegistry();

        // When / Then
        foreach (EncryptedColumnTypes::names() as $name) {
            static::assertTrue($registry->has($name), $name . ' is declared by the bundle and not registered.');
            static::assertInstanceOf(EncryptedType::class, $registry->get($name));
        }
    }

    /**
     * A type seals the type the column carried, so the domain object a mapping hands over survives the
     * envelope: an electronic address goes in as one and comes back as one.
     */
    #[Test]
    public function aValueSealedByAnEncryptedTypeIsReadBackAsTheDomainObjectItWas(): void
    {
        // Given
        $type = Type::getTypeRegistry()->get(EncryptedColumnTypes::name('user', 'beffroi_email_address'));
        $platform = self::connection()->getDatabasePlatform();
        $address = new EmailAddress('alice@example.com');

        // When
        $sealed = $type->convertToDatabaseValue($address, $platform);
        $read = $type->convertToPHPValue($sealed, $platform);

        // Then
        static::assertInstanceOf(EmailAddress::class, $read);
        static::assertSame($address->value, $read->value);
    }

    /**
     * What the column holds is the envelope and not the value, which is the whole of what decision 0011
     * asks of a dump of the database.
     */
    #[Test]
    public function theBytesTheColumnHoldsAreNotThePlaintext(): void
    {
        // Given
        $connection = self::connection();
        $connection->executeStatement('CREATE TABLE ' . self::TABLE . ' (id INTEGER PRIMARY KEY, value BLOB)');
        $name = EncryptedColumnTypes::name('user', 'beffroi_email_address');

        // When
        $connection->insert(
            self::TABLE,
            [
                'id' => 1,
                'value' => new EmailAddress('alice@example.com'),
            ],
            [
                'value' => $name,
            ],
        );
        $stored = self::storedBytes($connection);

        // Then
        static::assertStringNotContainsString('alice@example.com', $stored, 'The column holds the address in the clear.');
        $read = Type::getTypeRegistry()->get($name)->convertToPHPValue($stored, $connection->getDatabasePlatform());
        static::assertInstanceOf(EmailAddress::class, $read);
        static::assertSame('alice@example.com', $read->value);
    }

    /**
     * The type registry is global and outlives the container, so a rebooted kernel registers names that
     * are taken and has to replace rather than refuse them; the functional suite reboots between two
     * requests of a browser (README of the bridge, "Where to register the types").
     */
    #[Test]
    public function aKernelBootedASecondTimeRegistersTheSameNamesAgain(): void
    {
        // Given
        $name = EncryptedColumnTypes::name('user', 'beffroi_email_address');
        $before = Type::getTypeRegistry()->get($name);

        // When
        self::ensureKernelShutdown();
        self::bootKernel();

        // Then
        $after = Type::getTypeRegistry()->get($name);
        static::assertInstanceOf(EncryptedType::class, $after);
        static::assertNotSame(
            $before,
            $after,
            'The second kernel left the type of the first one in place, pointing at an encrypter nothing else uses any more.',
        );
    }

    /**
     * The name is derived from the family and the type it seals and never listed beside them, so a mapping
     * that names anything else names a type no encrypter answers.
     */
    #[Test]
    #[DataProvider('provideNames')]
    public function theNameOfATypeIsTheFamilyAndTheTypeItSeals(string $family, string $type, string $expected): void
    {
        // When / Then
        static::assertSame($expected, EncryptedColumnTypes::name($family, $type));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideNames(): iterable
    {
        yield 'a type of the platform' => ['user', 'string', 'beffroi_encrypted_user_string'];
        yield 'a type of the bundle, whose prefix is dropped' => ['user', 'beffroi_address', 'beffroi_encrypted_user_address'];
        yield 'a family whose name is a sentence' => [
            'backchannel_authentication_request',
            'beffroi_request_context',
            'beffroi_encrypted_backchannel_authentication_request_request_context',
        ];
    }

    /**
     * A family seals the types its own columns carry and no others: asking for a type it does not seal is
     * a mapping about to name something nothing registers, and it is refused where it is composed.
     */
    #[Test]
    public function aTypeAFamilyDoesNotSealIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The family "interaction" seals no column of type "beffroi_address". The families are user, linked_identity, passkey_credential, push_subscription, authentication_session, interaction, pushed_authorization_request, device_authorization_request, backchannel_authentication_request, client, journal, personal_archive, claim_change, disclosure, saml_service_provider, saml_upstream_identity_provider.');

        // When
        EncryptedColumnTypes::name('interaction', 'beffroi_address');
    }

    /**
     * What the walk of the schema reads a column's family from is derived from the one declaration of the
     * types, and covers every one of them: a family read from a second list would be a second thing to be
     * wrong, and a type missing from it would be a sealed column the walk takes for a readable one.
     */
    #[Test]
    public function everySealingTypeSaysWhichFamilyItSealsUnder(): void
    {
        // When
        $families = EncryptedColumnTypes::familyByType();

        // Then
        static::assertSame(EncryptedColumnTypes::names(), array_keys($families));
        static::assertSame([], array_diff($families, EncryptedColumnTypes::families()));
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }

    /**
     * What a dump of the database holds, read without the type that would open it.
     */
    private static function storedBytes(Connection $connection): string
    {
        $stored = $connection->fetchOne('SELECT value FROM ' . self::TABLE . ' WHERE id = 1');
        static::assertIsString($stored);

        return $stored;
    }
}
