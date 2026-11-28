<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Doctrine\PersonalData\TenantDataKeyDestruction;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Event\TenantDataKeysDestroyed;
use Beffroi\Core\Domain\Event\TenantDataKeysRewrapped;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function array_column;
use function array_filter;
use function count;
use function sprintf;
use Throwable;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0018
 */
final class DataKeysTest extends ConsoleTestCase
{
    private const string USERNAME = 'ada-of-the-keys';

    #[Test]
    public function theListingShowsTheScopesOfTheTenantAndTheClientThatOpensEach(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = self::flattened($tester);
        static::assertStringContainsString(TenantScopedEncrypter::scope(self::tenant()->slug, 'user'), $display);
        static::assertStringContainsString('current', $display);
        static::assertStringContainsString('test', $display);
    }

    #[Test]
    public function aTenantThatHasSealedNothingIsToldWhichFamiliesThereAre(): void
    {
        // When
        $tester = self::console('beffroi:data-keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = self::flattened($tester);
        static::assertStringContainsString('holds no data key', $display);
        foreach (EncryptedColumnTypes::families() as $family) {
            static::assertStringContainsString($family, $display);
        }
    }

    #[Test]
    public function theListingShowsNoKeyMaterial(): void
    {
        // Given
        self::sealSomething();
        $material = RawRows::of(self::connection(), TenantDataKeyStores::TABLE, ['key_material'])[0]['key_material'] ?? null;
        static::assertNotNull($material);

        // When
        $tester = self::console('beffroi:data-keys:list');

        // Then
        static::assertStringNotContainsString($material, self::flattened($tester));
    }

    #[Test]
    public function theDestructionRefusesWithoutTheSlugTypedBack(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:destroy');

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('Type the slug of the tenant back', self::flattened($tester));
        static::assertNotSame([], self::rows());
    }

    #[Test]
    public function theDestructionRefusesAnotherSlug(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:destroy', [
            'slug' => 'another-tenant',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('is not the slug of the tenant', self::flattened($tester));
        static::assertNotSame([], self::rows());
    }

    #[Test]
    public function theDestructionErasesTheKeysAndLeavesTheRowsUnreadable(): void
    {
        // Given
        $user = self::sealSomething();
        $sealed = self::connection()->fetchOne('SELECT username FROM beffroi_user WHERE id = ?', [$user->id->toBinary()]);
        static::assertNotFalse($sealed);

        // When
        $tester = self::console('beffroi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('erased', self::flattened($tester));
        // The erasure is itself an act, and its sealed provenance mints the one journal key left.
        static::assertSame(
            [
                [
                    'scope' => self::tenant()->slug . '.journal',
                    'client' => 'test',
                ],
            ],
            self::rows(),
        );
        static::assertSame(
            $sealed,
            self::connection()->fetchOne('SELECT username FROM beffroi_user WHERE id = ?', [$user->id->toBinary()]),
            'The destruction erased a key and not a row: what is gone is the means of reading it.',
        );
    }

    #[Test]
    public function theDestructionIsWrittenToTheAuditTrail(): void
    {
        // Given
        self::sealSomething();

        // When
        self::console('beffroi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);

        // Then
        $event = self::recorded(TenantDataKeysDestroyed::class);
        static::assertInstanceOf(TenantDataKeysDestroyed::class, $event);
        static::assertTrue($event->tenant->equals(self::tenant()));
        static::assertGreaterThan(0, $event->keys);
        static::assertGreaterThan(0, $event->scopes);
    }

    #[Test]
    public function theRewrapNeedsTheClientItMovesTo(): void
    {
        // Given
        self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:rewrap');

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('--to', self::flattened($tester));
    }

    #[Test]
    public function theRewrapOfATenantThatHoldsNothingSaysSo(): void
    {
        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('holds no data key', self::flattened($tester));
    }

    #[Test]
    public function aDryRunListsWhatWouldMoveAndWritesNothing(): void
    {
        // Given
        self::sealSomething();
        $before = self::rows();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
            '--dry-run' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('would move', self::flattened($tester));
        static::assertSame($before, self::rows());
        static::assertNull(self::recorded(TenantDataKeysRewrapped::class));
    }

    #[Test]
    public function theRewrapMovesTheKeysAndWhatTheySealedStillReads(): void
    {
        // Given
        $user = self::sealSomething();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        foreach (self::rows() as $row) {
            // The rewrap's own journal key is minted after the move, under the client the configuration names.
            static::assertSame($row['scope'] === self::tenant()->slug . '.journal' ? 'test' : 'second', $row['client']);
        }
        self::reload();
        $read = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::USERNAME, $read->username);
    }

    #[Test]
    public function theRewrapIsWrittenToTheAuditTrail(): void
    {
        // Given
        self::sealSomething();

        // When
        self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        $event = self::recorded(TenantDataKeysRewrapped::class);
        static::assertInstanceOf(TenantDataKeysRewrapped::class, $event);
        static::assertSame('second', $event->to);
        static::assertNull($event->from);
        static::assertGreaterThan(0, $event->keys);
    }

    #[Test]
    public function aSecondDryRunFromTheOldClientListsOnlyWhatWasWrittenSince(): void
    {
        // Given
        self::sealSomething();
        self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
            '--from' => 'test',
            '--dry-run' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('1 data key(s) would move', self::flattened($tester));
        static::assertSame([self::tenant()->slug . '.journal'], array_column(array_filter(
            self::rows(),
            static fn (array $row): bool => $row['client'] === 'test',
        ), 'scope'));
    }

    #[Test]
    public function everySealedColumnIsByteIdenticalBeforeAndAfterTheRewrap(): void
    {
        // Given
        self::sealSomething();
        $before = self::sealedColumns();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'second',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertGreaterThanOrEqual(4, count($before), 'a comparison of nothing would pass for nothing.');
        static::assertSame($before, self::sealedColumns(), 'a rewrap that moved a payload would be a rewrap that read one.');
    }

    #[Test]
    public function aRowWhoseDataKeyIsWrappedUnderNoContextNoLongerOpens(): void
    {
        // Given
        $user = self::sealSomething();
        self::wrapTheKeysUnderNoContext();

        // When
        $thrown = null;
        try {
            self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        } catch (Throwable $caught) {
            $thrown = $caught;
        }

        // Then
        static::assertNotNull($thrown, 'a data key wrapped under no context opened, so the store binds none.');
        static::assertStringContainsString('Decryption failed.', self::reasonOf($thrown));
    }

    #[Test]
    public function aRewrapThatAcceptsTheKeysWrappedUnderNoContextMakesWhatTheySealedReadAgain(): void
    {
        // Given
        $user = self::sealSomething();
        self::wrapTheKeysUnderNoContext();

        // When
        $tester = self::console('beffroi:data-keys:rewrap', [
            '--to' => 'test',
            '--accept-unbound' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $read = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::USERNAME, $read->username);
    }

    #[Test]
    public function aRowWhoseDataKeyWasDestroyedNoLongerOpens(): void
    {
        // Given
        $user = self::sealSomething();
        self::console('beffroi:data-keys:destroy', [
            'slug' => self::tenant()->slug,
        ]);
        self::reload();

        // When
        $thrown = null;
        try {
            self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        } catch (Throwable $caught) {
            $thrown = $caught;
        }

        // Then
        static::assertNotNull($thrown, 'a row whose data key is gone read back as something, which is worse than refusing.');
        static::assertStringContainsString(
            'Data key',
            self::reasonOf($thrown),
            'the refusal names the data key the row refers to, which is what an operator needs to know.',
        );
        static::assertStringContainsString('was not found in the store', self::reasonOf($thrown));
    }

    #[Test]
    public function aRowOfTheOtherTenantStillOpens(): void
    {
        // Given
        $mine = self::sealSomething();
        $other = self::anotherTenant();
        self::sealSomethingFor($other, 'bob-of-the-other-tenant');

        // When
        self::destroyTheKeysOf($other);

        // Then
        $read = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($mine->id);
        static::assertInstanceOf(User::class, $read);
        static::assertSame(self::USERNAME, $read->username);
    }

    /**
     * @return array<string, string>
     */
    private static function sealedColumns(): array
    {
        $columns = [];
        foreach (ClassifiedModel::of(self::entityManager())->linesOf('beffroi_user') as $column => $line) {
            if ($line instanceof Sealed) {
                $columns[] = $column;
            }
        }

        $rows = RawRows::of(self::connection(), 'beffroi_user', $columns);
        static::assertCount(1, $rows);

        $held = [];
        foreach ($rows[0] as $column => $value) {
            if ($value !== null) {
                $held[$column] = $value;
            }
        }

        return $held;
    }

    private static function anotherTenant(): Tenant
    {
        $other = new Tenant(Uuid::v7(), 'other', new Issuer('https://other.test'), 'Other', self::now());
        self::entityManager()->persist($other);
        self::derivations()->record($other, 0, 0);
        self::entityManager()->flush();

        return $other;
    }

    /**
     * The same data key under the same master key, wrapped under no context; then a kernel of its own, the stores of
     * the one before holding the keys it opened.
     */
    private static function wrapTheKeysUnderNoContext(): void
    {
        $kms = self::service('test.beffroi.kms', DataKeyGeneratorInterface::class);
        $stores = self::service('test.beffroi.data_keys_index', TenantDataKeyStores::class);
        foreach ([...$stores->all()] as $row) {
            $unbound = $kms->unwrapDataKey($row->wrapped, $stores->wrappingContextOf($row))->use(
                static fn (string $key): Ciphertext => $kms->wrapDataKey($row->wrapped->keyId, $key),
            );
            self::connection()
                ->update(
                    TenantDataKeyStores::TABLE,
                    ['key_material' => $unbound->blob],
                    ['id' => $row->reference],
                    ['key_material' => ParameterType::BINARY, 'id' => ParameterType::BINARY],
                );
        }
        self::ensureKernelShutdown();
        self::bootKernel();
    }

    private static function destroyTheKeysOf(Tenant $tenant): void
    {
        self::service(TenantDataKeyDestruction::class, TenantDataKeyDestruction::class)->destroy($tenant, 'the test');
        self::reload();
    }

    private static function reasonOf(Throwable $thrown): string
    {
        $reason = $thrown->getMessage();
        $cause = $thrown->getPrevious();
        while ($cause !== null) {
            $reason .= ' ' . $cause->getMessage();
            $cause = $cause->getPrevious();
        }

        return $reason;
    }

    private static function sealSomethingFor(Tenant $tenant, string $username): User
    {
        $user = User::create(
            Uuid::v7(),
            $tenant,
            new Subject($username . '-subject'),
            $username,
            self::now(),
            new EmailAddress('bob@example.org'),
        );
        $user->changePhoneNumber('+441632960542', false, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        self::reload();

        return $user;
    }

    private static function sealSomething(): User
    {
        $user = User::create(
            Uuid::v7(),
            self::tenant(),
            new Subject('ada-of-the-keys-subject'),
            self::USERNAME,
            self::now(),
            new EmailAddress('ada@example.org'),
        );
        $user->changePhoneNumber('+441632960541', false, self::now());
        $user->changeAddress(new Address('12 Grand Rue, Saint-Germain'), self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
        self::reload();

        return $user;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function rows(): array
    {
        return self::connection()
            ->fetchAllAssociative(
                sprintf('SELECT scope, client FROM %s ORDER BY scope ASC', TenantDataKeyStores::TABLE),
            );
    }

    /**
     * @param class-string $class
     */
    private static function recorded(string $class): ?object
    {
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                return $event;
            }
        }

        return null;
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
