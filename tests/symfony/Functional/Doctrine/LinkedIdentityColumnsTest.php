<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Application\Identity\IdentityAlreadyLinkedException;
use function array_keys;
use function array_map;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Index\IndexedColumn;
use Doctrine\DBAL\Schema\Index\IndexType;
use Doctrine\ORM\Tools\SchemaTool;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;
use Symfony\Component\Uid\Uuid;

final class LinkedIdentityColumnsTest extends DatabaseTestCase
{
    private const string PROVIDER = 'login.acme-federation.example';

    private const string SUBJECT = '110169484474386276334';

    private const array PLAINTEXTS = [
        'provider' => self::PROVIDER,
        'subject' => self::SUBJECT,
        'claims' => 'ada@example.org',
    ];

    private const array CLAIMS = [
        'email' => 'ada@example.org',
        'email_verified' => true,
        'name' => 'Augusta Ada King',
        'locale' => 'en-GB',
    ];

    #[Test]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(): void
    {
        // Given
        $sealed = [];
        foreach (ClassifiedModel::of(self::entityManager())->linesOf('beffroi_linked_identity') as $column => $line) {
            if ($line instanceof Sealed) {
                $sealed[] = $column;
            }
        }
        sort($sealed);

        // When
        $written = array_keys(self::PLAINTEXTS);
        sort($written);

        // Then
        static::assertSame($sealed, $written);
    }

    #[Test]
    public function aRowIsReadBackAsTheDomainWroteIt(): void
    {
        // Given
        $saved = self::identity();
        self::reload();

        // When
        $read = self::identities()->find(self::tenant(), self::PROVIDER, self::SUBJECT);

        // Then
        static::assertInstanceOf(LinkedIdentity::class, $read);
        static::assertTrue($read->id->equals($saved->id));
        static::assertSame(self::PROVIDER, $read->provider);
        static::assertSame(self::SUBJECT, $read->subject);
        static::assertSame(self::CLAIMS, $read->claims);
    }

    #[Test]
    #[DataProvider('provideSealedColumns')]
    public function theRowHoldsNoneOfThePlaintexts(string $column, string $plaintext): void
    {
        // Given
        self::identity();

        // When
        $stored = self::row()[$column];

        // Then
        static::assertStringNotContainsString(
            $plaintext,
            $stored,
            sprintf('beffroi_linked_identity.%s holds "%s" in the clear.', $column, $plaintext),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSealedColumns(): iterable
    {
        foreach (self::PLAINTEXTS as $column => $plaintext) {
            yield $column => [$column, $plaintext];
        }
    }

    #[Test]
    public function theColumnOfTheSnapshotHoldsNoneOfItsValues(): void
    {
        // Given
        self::identity();

        // When
        $stored = self::row()['claims'];

        // Then
        foreach (['ada@example.org', 'Augusta Ada King', 'en-GB'] as $value) {
            static::assertStringNotContainsString($value, $stored, sprintf('the snapshot holds "%s" in the clear.', $value));
        }
    }

    #[Test]
    public function theRowHoldsTheTagOfTheProviderAndTheTagOfTheSubject(): void
    {
        // Given
        self::identity();

        // When
        $row = self::row();

        // Then
        static::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row['provider_index']);
        static::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row['subject_index']);
        static::assertNotSame($row['provider_index'], $row['subject_index']);
    }

    /**
     * beffroi/saml S-56
     */
    #[Test]
    public function aSecondRowWithTheSamePairUnderOneTenantIsRefused(): void
    {
        // Given
        self::identity();
        self::reload();

        // Then
        $this->expectException(IdentityAlreadyLinkedException::class);
        $this->expectExceptionMessageIs('The identity was linked meanwhile in this tenant.');

        // When
        self::identity('someone-else-subject');
    }

    #[Test]
    public function theSamePairUnderAnotherTenantIsAdmitted(): void
    {
        // Given
        $ofAcme = self::identity();
        $other = new Tenant(Uuid::v7(), 'other', new Issuer('https://other.test'), 'Other', self::now());
        self::entityManager()->persist($other);
        self::derivations()->record($other, 0, 0);

        // When
        $ofOther = self::identity('bob-subject', $other);

        // Then
        static::assertFalse($ofOther->id->equals($ofAcme->id));
        static::assertCount(2, self::connection()->fetchAllAssociative('SELECT id FROM beffroi_linked_identity'));
    }

    #[Test]
    public function aFederationFindsTheColumnsAndTheConstraintInPlace(): void
    {
        // Given
        $entityManager = self::entityManager();
        $table = new SchemaTool($entityManager)
            ->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata())
            ->getTable('beffroi_linked_identity');

        // When
        $index = $table->getIndex('beffroi_linked_identity_subject');

        // Then
        foreach (['provider', 'provider_index', 'subject', 'subject_index', 'claims'] as $column) {
            static::assertTrue($table->hasColumn($column), sprintf('beffroi_linked_identity has no column "%s".', $column));
        }
        static::assertSame(IndexType::UNIQUE, $index->getType());
        static::assertSame(
            ['tenant_id', 'provider_index', 'subject_index'],
            array_map(
                static fn (IndexedColumn $column): string => $column->getColumnName()->getIdentifier()->getValue(),
                $index->getIndexedColumns(),
            ),
        );
    }

    private static function identity(string $subject = 'ada-subject', ?Tenant $tenant = null): LinkedIdentity
    {
        $user = User::create(Uuid::v7(), $tenant ?? self::tenant(), new Subject($subject), $subject, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        $identity = new LinkedIdentity(Uuid::v7(), $user, self::PROVIDER, self::SUBJECT, self::CLAIMS, self::now(), self::now());
        self::identities()->save($identity);

        return $identity;
    }

    /**
     * @return array<string, string>
     */
    private static function row(): array
    {
        $rows = RawRows::of(
            self::connection(),
            'beffroi_linked_identity',
            [...array_keys(self::PLAINTEXTS), 'provider_index', 'subject_index'],
        );
        static::assertCount(1, $rows);

        $row = [];
        foreach ($rows[0] as $column => $value) {
            $row[$column] = $value ?? static::fail(sprintf('beffroi_linked_identity.%s holds nothing.', $column));
        }

        return $row;
    }

    private static function identities(): LinkedIdentityRepositoryInterface
    {
        return self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
