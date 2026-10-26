<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Application\Identity\IdentityAlreadyLinkedException;
use function array_keys;
use function array_map;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Index\IndexedColumn;
use Doctrine\DBAL\Schema\Index\IndexType;
use Doctrine\ORM\Tools\SchemaTool;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedModel;
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

/**
 * The three columns of `beffroi_linked_identity` sealed, and the blind index of the pair a federated login
 * recognises an identity by (decisions 0011 and 0018).
 *
 * **The table is sealed before a federation fills it, and that is why it is sealed now.** What writes a row
 * today is `beffroi:user:link` and what reads one is the grant that reads an assertion of a trusted issuer,
 * so the lookup of the pair is a path this provider already takes; a federation will write one row per
 * person who signs in through it, and a blind index added at that point is a reindex of every row of every
 * tenant of a customer. The rows written here go through the repository that lookup uses, unchanged.
 */
final class LinkedIdentityColumnsTest extends DatabaseTestCase
{
    private const string PROVIDER = 'login.acme-federation.example';

    private const string SUBJECT = '110169484474386276334';

    /**
     * The three personal data of a linked identity, by the column each one lands in: what the fixture
     * writes and what the row must not hold. The claims are a JSON document, so what is asserted of it is
     * each value it carries.
     */
    private const array PLAINTEXTS = [
        'provider' => self::PROVIDER,
        'subject' => self::SUBJECT,
        'claims' => 'ada@example.org',
    ];

    /**
     * The snapshot the upstream provider returned, which is what the column holds whole.
     */
    private const array CLAIMS = [
        'email' => 'ada@example.org',
        'email_verified' => true,
        'name' => 'Augusta Ada King',
        'locale' => 'en-GB',
    ];

    /**
     * The fixture writes every column the classification of the schema declares sealed, and no other.
     */
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

    /**
     * The domain does not change because the columns seal: the snapshot comes back as the array that was
     * written, the encrypted type decorating the JSON type the column had.
     */
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

    /**
     * Column by column: a column that stopped sealing fails on its own line.
     */
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

    /**
     * Not one value of the snapshot is in the column, the whole document being sealed and not its keys one
     * by one.
     */
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
     * The unicity of the pair within a tenant, held on the two index columns: a constraint on the pair in
     * the clear would refuse nothing, every write of one subject giving another ciphertext. Its violation is the
     * exception of the core, naming nothing (beffroi/saml S-56).
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

    /**
     * And the same pair under another tenant is admitted: the constraint carries the tenant, so two tenants
     * federating from one provider are two rows even when their tags are the same string.
     */
    #[Test]
    public function theSamePairUnderAnotherTenantIsAdmitted(): void
    {
        // Given
        $ofAcme = self::identity();
        $other = new Tenant(Uuid::v7(), 'other', new Issuer('https://other.test'), 'Other', self::now());
        self::entityManager()->persist($other);

        // When
        $ofOther = self::identity('bob-subject', $other);

        // Then
        static::assertFalse($ofOther->id->equals($ofAcme->id));
        static::assertCount(2, self::connection()->fetchAllAssociative('SELECT id FROM beffroi_linked_identity'));
    }

    /**
     * What a federation was going to add, found in place in the mappings: the three sealed columns, the two
     * index columns, and the unique constraint on the pair of tags. It has nothing to migrate and nothing
     * to add, which is the whole reason this table is sealed before a directory is imported into it.
     */
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

    /**
     * A linked identity of the fixture, saved through the repository the federation will use.
     */
    private static function identity(string $subject = 'ada-subject', ?Tenant $tenant = null): LinkedIdentity
    {
        $user = User::create(Uuid::v7(), $tenant ?? self::tenant(), new Subject($subject), $subject, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        $identity = new LinkedIdentity(Uuid::v7(), $user, self::PROVIDER, self::SUBJECT, self::CLAIMS, self::now(), self::now());
        self::identities()->save($identity);

        return $identity;
    }

    /**
     * The one row of the table as the database holds it, the three sealed columns and the two tags: a
     * column that holds nothing is a column with nothing to assert against, so a null fails here and not
     * silently in the test that reads it.
     *
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
