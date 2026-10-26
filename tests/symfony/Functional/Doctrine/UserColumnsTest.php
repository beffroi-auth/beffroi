<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use function array_keys;
use Doctrine\DBAL\Connection;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\CountingKms;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * The six columns of `beffroi_user` sealed and read back, and the row underneath (decisions 0011
 * and 0018).
 *
 * What is played here is the deployment's own chain, end to end: the mapping that names an encrypted type
 * per column, the encrypter that composes the scope with the ambient tenant, the listener that writes the
 * blind index in the same statement as the value it indexes, and the repository that looks a user up by
 * that index because the column it used to match on no longer matches anything.
 */
final class UserColumnsTest extends DatabaseTestCase
{
    /**
     * The six personal data of a user, by the column each one lands in: what the fixture writes and
     * what the row must not hold. One list, so that a column sealed without being written here, or written
     * without being asserted, is a count that no longer adds up.
     */
    /**
     * Read from the shared fixture and declared nowhere else: the test that searches the whole database
     * searches for these very values, and two lists of the same values are two lists that disagree.
     *
     * @var array<string, string>
     */
    private const array PLAINTEXTS = SealedRows::VALUES['beffroi_user'];

    /**
     * The fixture writes every column the classification of the schema declares sealed, and no other: a
     * column sealed without a value written here would be asserted against nothing, and the walk of the
     * model is what says which those are (ClassifiedFieldsInterface, decision 0011).
     */
    #[Test]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(): void
    {
        // Given
        $sealed = [];
        foreach (ClassifiedModel::of(self::entityManager())->linesOf('beffroi_user') as $column => $line) {
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
     * The domain does not change because the column seals: what was written as an EmailAddress and an
     * Address comes back as one, the encrypted type decorating the type the column had.
     */
    #[Test]
    public function aUserIsReadBackAsTheDomainWroteIt(): void
    {
        // Given
        $saved = self::ada();
        self::reload();

        // When
        $read = self::users()->find($saved->id);

        // Then
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::PLAINTEXTS['username'], $read->username);
        static::assertInstanceOf(EmailAddress::class, $read->email);
        static::assertSame(self::PLAINTEXTS['email'], $read->email->value);
        static::assertSame(self::PLAINTEXTS['phone_number'], $read->phoneNumber);
        static::assertInstanceOf(Address::class, $read->address);
        static::assertSame(self::PLAINTEXTS['address'], $read->address->formatted);
        static::assertSame(self::PLAINTEXTS['profile'], $read->profile->name);
        static::assertSame(self::PLAINTEXTS['source'], $read->source->provider);
    }

    /**
     * Decision 0002: a local source holds nothing and has nothing to seal, so a person a console created
     * leaves the column empty.
     */
    #[Test]
    public function aLocalPersonLeavesTheSourceColumnEmpty(): void
    {
        // Given
        self::user('bob', 'bob-subject');

        // When
        $source = self::connection()->fetchOne('SELECT source FROM beffroi_user');

        // Then
        static::assertNull($source);
    }

    /**
     * The rows the table held before the column came are read as what they are: people a console, a
     * fixture or an import created.
     */
    #[Test]
    public function anEmptySourceColumnIsReadBackAsALocalPerson(): void
    {
        // Given
        $saved = self::ada();
        self::connection()->executeStatement('UPDATE beffroi_user SET source = NULL');
        self::reload();

        // When
        $read = self::users()->find($saved->id);

        // Then
        static::assertInstanceOf(User::class, $read);
        static::assertTrue($read->source->isLocal());
    }

    /**
     * Column by column, which is the point of the data provider: a column that stopped sealing would fail
     * on its own line and not hide behind five others.
     */
    #[Test]
    #[DataProvider('provideSealedColumns')]
    public function theRowHoldsNoneOfThePlaintexts(string $column, string $plaintext): void
    {
        // Given
        self::ada();

        // When
        $stored = self::row()[$column];

        // Then
        static::assertStringNotContainsString(
            $plaintext,
            $stored,
            sprintf('beffroi_user.%s holds "%s" in the clear.', $column, $plaintext),
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
     * The two tags, written where the row is written: sixty-four hexadecimal characters each, and neither
     * of them the value it indexes.
     */
    #[Test]
    public function theRowHoldsTheTagOfTheUsernameAndTheTagOfTheAddress(): void
    {
        // Given
        self::ada();

        // When
        $row = self::row();

        // Then
        static::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row['username_index']);
        static::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row['email_index']);
        static::assertNotSame($row['username_index'], $row['email_index']);
    }

    /**
     * A user who gave no address has no tag to hold, which is why the column is nullable: a tag of the
     * empty string would make every such user share one.
     */
    #[Test]
    public function aUserWhoGaveNoAddressHoldsNoTagForIt(): void
    {
        // Given
        self::user('no-address', 'no-address-subject');

        // When
        $row = self::connection()->fetchAssociative('SELECT email, email_index FROM beffroi_user');

        // Then
        static::assertIsArray($row);
        static::assertNull($row['email']);
        static::assertNull($row['email_index']);
    }

    /**
     * The lookup the login makes, on a column no lookup can match: what it matches is the tag the write
     * left beside the value.
     */
    #[Test]
    public function aUserIsReadBackByItsUsername(): void
    {
        // Given
        $saved = self::ada();
        self::reload();

        // When
        $read = self::users()->findByUsername(self::tenant(), self::PLAINTEXTS['username']);

        // Then
        static::assertInstanceOf(User::class, $read);
        static::assertTrue($read->id->equals($saved->id));
    }

    /**
     * A username differing by its case is another username, here as in the index: the identity model trims
     * a username and folds nothing (`User::normalizeUsername()`).
     */
    #[Test]
    public function aUsernameDifferingByItsCaseFindsNobody(): void
    {
        // Given
        self::ada();
        self::reload();

        // When
        $read = self::users()->findByUsername(self::tenant(), 'Ada-Lovelace');

        // Then
        static::assertNull($read);
    }

    /**
     * The unicity of a username within a tenant, held on the index column: a sealed column holds a
     * different ciphertext for every write of the same value, so the constraint had nowhere else to go. Its
     * violation is the exception of the core, naming nothing (beffroi/saml S-56).
     */
    #[Test]
    public function aSecondUserOfTheTenantWithTheSameUsernameIsRefused(): void
    {
        // Given
        self::ada();
        self::reload();

        // Then
        $this->expectException(UserAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A user of this name or of this subject was written meanwhile in this tenant.');

        // When
        self::users()
            ->save(User::create(
                Uuid::v7(),
                self::tenant(),
                new Subject('another-subject'),
                self::PLAINTEXTS['username'],
                self::now(),
            ));
    }

    /**
     * The third success criterion of the spike, on the lookup the login makes: one opening per data key and
     * per thread, and none at all on a page served by a thread that has already served one (decision
     * 0018). Two keys are touched here, the index key and the key of the "user" family, and a second
     * lookup touches neither.
     */
    #[Test]
    public function aSecondLookupOnTheSameThreadAsksTheKmsNothing(): void
    {
        // Given
        self::ada();
        self::reload();
        self::users()->findByUsername(self::tenant(), self::PLAINTEXTS['username']);
        self::kms()->forget();

        // When
        self::reload();
        $read = self::users()->findByUsername(self::tenant(), self::PLAINTEXTS['username']);

        // Then
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::PLAINTEXTS['email'], $read->email?->value);
        static::assertSame(0, self::kms()->minted);
        static::assertSame(0, self::kms()->unwrapped);
    }

    /**
     * The user of the fixture, with every one of the six columns written.
     */
    private static function ada(): User
    {
        return self::fixture()->user();
    }

    private static function fixture(): SealedRows
    {
        return new SealedRows(self::getContainer(), self::tenant(), self::now());
    }

    /**
     * The one row of the table as the database holds it, the six sealed columns and the two tags: a
     * column that holds nothing is a column with nothing to assert against, so a null fails here and not
     * silently in the test that reads it.
     *
     * @return array<string, string>
     */
    private static function row(): array
    {
        $rows = RawRows::of(self::connection(), 'beffroi_user', [...array_keys(self::PLAINTEXTS), 'username_index', 'email_index']);
        static::assertCount(1, $rows);

        $row = [];
        foreach ($rows[0] as $column => $value) {
            $row[$column] = $value ?? static::fail(sprintf('beffroi_user.%s holds nothing.', $column));
        }

        return $row;
    }

    private static function kms(): CountingKms
    {
        return self::service(CountingKms::class, CountingKms::class);
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
