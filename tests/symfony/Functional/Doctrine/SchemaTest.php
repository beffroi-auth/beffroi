<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_map;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Schema\Name\OptionallyQualifiedName;
use Doctrine\DBAL\Schema\Table;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\ORM\Tools\SchemaValidator;
use App\Tests\Symfony\Fixture\DoctrineDeprecations;
use App\Tests\Symfony\Functional\Doctrine\Host\User as HostUser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function str_starts_with;

/**
 * Architecture §5.3, §7, Decision 0002
 */
final class SchemaTest extends DatabaseTestCase
{
    public const array TABLES = [
        'beffroi_tenant',
        'beffroi_user',
        'beffroi_password_credential',
        'beffroi_passkey_credential',
        'beffroi_totp_credential',
        'beffroi_linked_identity',
        'beffroi_push_subscription',
        'beffroi_enrolment_ticket',
        'beffroi_password_ticket',
        'beffroi_totp_ticket',
        'beffroi_email_confirmation',
        'beffroi_phone_number_confirmation',
        'beffroi_group',
        'beffroi_group_membership',
        'beffroi_authentication_session',
        'beffroi_interaction',
        'beffroi_authorization_code',
        'beffroi_pushed_authorization_request',
        'beffroi_device_authorization_request',
        'beffroi_backchannel_authentication_request',
        'beffroi_refresh_token',
        'beffroi_refresh_token_family',
        'beffroi_access_token',
        'beffroi_client_access_token',
        'beffroi_subject_access_token',
        'beffroi_consent',
        'beffroi_client',
        'beffroi_initial_access_token',
        'beffroi_pairwise_subject',
        'beffroi_journal',
        'beffroi_chain_head',
        'beffroi_chain_link',
        'beffroi_personal_archive',
        'beffroi_claim_change',
        'beffroi_disclosure',
        'beffroi_saml_service_provider',
        'beffroi_saml_upstream_identity_provider',
        'beffroi_saml_remembered_message',
        'beffroi_saml_session_participant',
        'beffroi_saml_logout_chain',
        // No mapping describes this table: the schema listener of the ORM bridge adds it for the data keys.
        'beffroi_data_key',
    ];

    /**
     * doctrine/orm 3.8 deprecates writing a schema without its schema editor API, which names the foreign keys the
     * migrations created unnamed: the one deprecation the schema is written with until a migration names them.
     */
    private const array DEPRECATION_OF_THE_SCHEMA_EDITOR_API = [
        'https://github.com/doctrine/orm/pull/12780' => 1,
    ];

    #[Test]
    public function theMappingsAreValid(): void
    {
        // Given
        $validator = new SchemaValidator(self::entityManager());

        // When / Then
        static::assertSame([], $validator->validateMapping());
    }

    #[Test]
    public function theSchemaIsInSyncWithTheMappings(): void
    {
        // Given
        $validator = new SchemaValidator(self::entityManager());

        // When / Then
        static::assertSame([], $validator->getUpdateSchemaList());
    }

    #[Test]
    #[DataProvider('providePlatforms')]
    public function theSchemaIsWrittenWithNoDeprecationOfDoctrineButTheSchemaEditorApi(AbstractPlatform $platform): void
    {
        // Given
        $entityManager = self::entityManager();
        $metadata = $entityManager->getMetadataFactory()->getAllMetadata();
        $platform->setTypeProvider(self::typesOfTheConnection());

        // When
        $deprecations = DoctrineDeprecations::raisedWhile(
            static fn (): array => new SchemaTool($entityManager)
                ->getSchemaFromMetadata($metadata)
                ->toSql($platform),
        );

        // Then
        static::assertSame(self::DEPRECATION_OF_THE_SCHEMA_EDITOR_API, $deprecations);
    }

    /**
     * @return iterable<string, array{AbstractPlatform}>
     */
    public static function providePlatforms(): iterable
    {
        yield 'PostgreSQL, the database of the application' => [new PostgreSQLPlatform()];
        yield 'SQLite, the database of this suite' => [new SQLitePlatform()];
    }

    /**
     * Architecture §5.3
     */
    #[Test]
    public function theProviderDeclaresItsThirtyPrefixedTables(): void
    {
        // When
        $tables = array_keys(self::tablesOfTheProvider());

        // Then
        $expected = self::TABLES;
        sort($tables);
        sort($expected);
        static::assertSame($expected, $tables);
        foreach ($tables as $name) {
            static::assertTrue(str_starts_with($name, 'beffroi_'), $name);
        }
    }

    /**
     * Architecture §5.3, Decision 0018
     */
    #[Test]
    public function everyTableButTheTenantOneAndTheDataKeysCarriesTheTenant(): void
    {
        // When
        $tables = self::tablesOfTheProvider();

        // Then
        unset($tables['beffroi_tenant'], $tables['beffroi_data_key']);
        static::assertNotSame([], $tables);
        foreach ($tables as $name => $table) {
            static::assertTrue($table->hasColumn('tenant_id'), $name);
            static::assertNotFalse($table->getColumn('tenant_id')->getNotnull(), $name);
        }
    }

    #[Test]
    public function theScopeOfTheDataKeyStoreIsWhatCarriesTheTenantThere(): void
    {
        // When
        $table = self::tablesOfTheProvider()['beffroi_data_key'] ?? null;

        // Then
        static::assertNotNull($table);
        static::assertFalse($table->hasColumn('tenant_id'));
        static::assertTrue($table->hasColumn('scope'));
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function theHostApplicationKeepsItsOwnUserNextToTheProvider(): void
    {
        // Given
        $host = new HostUser('host@example.com');
        self::entityManager()->persist($host);
        self::entityManager()->flush();
        self::reload();

        // When
        $tables = array_map(static fn (OptionallyQualifiedName $table): string => $table
            ->getUnqualifiedName()
            ->getValue(), self::entityManager()->getConnection()->createSchemaManager()->introspectTableNames());

        // Then
        static::assertContains('app_user', $tables);
        static::assertContains('beffroi_user', $tables);
        static::assertSame('host@example.com', self::entityManager()->find(HostUser::class, $host->id)?->email);
    }

    /**
     * @return array<string, Table>
     */
    private static function tablesOfTheProvider(): array
    {
        $entityManager = self::entityManager();
        $schema = new SchemaTool($entityManager)->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata());
        $tables = [];
        foreach ($schema->getTables() as $table) {
            $name = $table->getObjectName()->getUnqualifiedName()->getValue();
            if ($name !== 'app_user') {
                $tables[$name] = $table;
            }
        }

        return $tables;
    }
}
