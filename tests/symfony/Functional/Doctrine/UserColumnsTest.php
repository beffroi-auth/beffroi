<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use function array_keys;
use Doctrine\DBAL\Connection;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\CountingKms;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;
use Symfony\Component\Uid\Uuid;

final class UserColumnsTest extends DatabaseTestCase
{
    /**
     * @var array<string, string>
     */
    private const array PLAINTEXTS = SealedRows::VALUES['beffroi_user'];

    /**
     * Decision 0011
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
        static::assertSame([self::PLAINTEXTS['notification_channels']], $read->notificationChannels->forEveryKind);
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function aPersonWhoChoseNoChannelLeavesTheColumnEmpty(): void
    {
        // Given
        self::user('bob', 'bob-subject');

        // When
        $chosen = self::connection()->fetchOne('SELECT notification_channels FROM beffroi_user');

        // Then
        static::assertNull($chosen);
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function anEmptyColumnOfChannelsIsReadBackAsAPersonWhoChoseNothing(): void
    {
        // Given
        $saved = self::ada();
        self::connection()->executeStatement('UPDATE beffroi_user SET notification_channels = NULL');
        self::reload();

        // When
        $read = self::users()->find($saved->id);

        // Then
        static::assertInstanceOf(User::class, $read);
        static::assertTrue($read->notificationChannels->isNone());
    }

    /**
     * Decision 0002
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
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function aUsernameDifferingByItsCaseFindsTheSamePerson(): void
    {
        // Given
        $saved = self::ada();
        self::reload();

        // When
        $read = self::users()->findByUsername(self::tenant(), 'Ada-Lovelace');

        // Then
        static::assertTrue($read?->id->equals($saved->id));
    }

    /**
     * beffroi/saml S-56
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

    private static function ada(): User
    {
        return self::fixture()->user();
    }

    private static function fixture(): SealedRows
    {
        return new SealedRows(self::getContainer(), self::tenant(), self::now());
    }

    /**
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
