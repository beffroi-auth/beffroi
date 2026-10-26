<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #781: writes that are one fact, kept all or none in one transaction of the connection.
 */
final class DoctrineAtomicWritesTest extends DatabaseTestCase
{
    #[Test]
    public function writesThatAllSucceedAreAllKept(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());
        $bob = User::create(Uuid::v7(), self::tenant(), new Subject('bob-subject'), 'bob', self::now());

        // When
        self::writes()
            ->atomically(static function () use ($alice, $bob): void {
                self::users()->save($alice);
                self::users()->save($bob);
            });

        // Then
        self::reload();
        static::assertNotNull(self::users()->findByUsername(self::tenant(), 'alice'));
        static::assertNotNull(self::users()->findByUsername(self::tenant(), 'bob'));
    }

    #[Test]
    public function theFailureOfAWriteGoesOnToTheCaller(): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The second write failed.');

        // When
        self::writes()
            ->atomically(static function (): void {
                throw new RuntimeException('The second write failed.');
            });
    }

    /**
     * What was flushed before the write that failed is rolled back with it.
     */
    #[Test]
    public function aWriteThatFailsTakesTheWritesBeforeItWithIt(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());

        // When
        try {
            self::writes()
                ->atomically(static function () use ($alice): void {
                    self::users()->save($alice);

                    throw new RuntimeException('The second write failed.');
                });
        } catch (RuntimeException) {
        }

        // Then
        static::assertNull(self::users()->findByUsername(self::tenant(), 'alice'));
    }

    /**
     * The rollback takes the row back and the manager would keep the object it flushed into it, which a later
     * flush of the same request would write again or point a new row at: it holds nothing after a failure.
     */
    #[Test]
    public function aWriteThatFailsLeavesNothingManaged(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());

        // When
        try {
            self::writes()
                ->atomically(static function () use ($alice): void {
                    self::users()->save($alice);

                    throw new RuntimeException('The second write failed.');
                });
        } catch (RuntimeException) {
        }

        // Then
        static::assertFalse(self::entityManager()->contains($alice));
    }

    /**
     * What the request does after a failure is written, the manager forgetting what it held and not the
     * tenant it reads again.
     */
    #[Test]
    public function aWriteAfterAFailureIsKept(): void
    {
        // Given
        $alice = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now());
        try {
            self::writes()
                ->atomically(static function () use ($alice): void {
                    self::users()->save($alice);

                    throw new RuntimeException('The second write failed.');
                });
        } catch (RuntimeException) {
        }

        // When
        self::users()->save(User::create(Uuid::v7(), self::tenant(), new Subject('bob-subject'), 'bob', self::now()));

        // Then
        static::assertNotNull(self::users()->findByUsername(self::tenant(), 'bob'));
        static::assertNull(self::users()->findByUsername(self::tenant(), 'alice'));
    }

    /**
     * A refusal raised inside the writes leaves the manager open, as the middleware of the command bus does:
     * the rest of the request still reads and writes.
     */
    #[Test]
    public function aFailureLeavesTheManagerOpen(): void
    {
        // When
        try {
            self::writes()
                ->atomically(static function (): void {
                    throw new RuntimeException('Refused before anything was written.');
                });
        } catch (RuntimeException) {
        }

        // Then
        static::assertTrue(self::entityManager()->isOpen());
    }

    private static function writes(): AtomicWritesInterface
    {
        return self::service('test.beffroi.atomic_writes', AtomicWritesInterface::class);
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
