<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Message\RaiseTheVersionOfAGroup;
use App\Message\RaiseTheVersionOfAPerson;
use App\MessageHandler\RaiseTheVersionOfAGroupHandler;
use App\MessageHandler\RaiseTheVersionOfAPersonHandler;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Uid\Uuid;

/**
 * Each test plays a raise as a lane does: a first delivery that fails, the manager the worker clears, then the retry.
 */
final class RaisedVersionsTest extends DatabaseTestCase
{
    /**
     * RFC 7644 §3.14, RFC 9110 §8.8.1, RFC 7643 §3.1
     */
    #[Test]
    public function theRaiseOfAPersonThatFailedIsMadeByItsRetry(): void
    {
        // Given
        $user = self::user();
        $handler = new RaiseTheVersionOfAPersonHandler(self::usersFailingOnce());
        $command = new RaiseTheVersionOfAPerson($user->id, self::now()->modify('+1 hour'));
        self::failToHandle(static fn () => $handler($command));

        // When
        $handler($command);

        // Then
        self::reload();
        $found = self::entityManager()->find(User::class, $user->id) ?? static::fail('The person was not stored.');
        static::assertEquals([2, self::now()->modify('+1 hour')], [$found->version, $found->updatedAt]);
    }

    /**
     * RFC 7644 §3.14, RFC 9110 §8.8.1, RFC 7643 §3.1
     */
    #[Test]
    public function theRaiseOfAGroupThatFailedIsMadeByItsRetry(): void
    {
        // Given
        $group = new Group(Uuid::v7(), self::tenant(), 'staff', GroupSource::Local, self::now());
        self::storedGroups()->save($group);
        $handler = new RaiseTheVersionOfAGroupHandler(self::managers(), self::groupsFailingOnce());
        $command = new RaiseTheVersionOfAGroup($group->id, self::now()->modify('+1 hour'));
        self::failToHandle(static fn () => $handler($command));

        // When
        $handler($command);

        // Then
        self::reload();
        $found = self::entityManager()->find(Group::class, $group->id) ?? static::fail('The group was not stored.');
        static::assertEquals([2, self::now()->modify('+1 hour')], [$found->version, $found->updatedAt]);
    }

    /**
     * @param callable(): void $delivery
     */
    private static function failToHandle(callable $delivery): void
    {
        $failed = false;
        try {
            $delivery();
        } catch (RuntimeException) {
            $failed = true;
        }
        static::assertTrue($failed, 'The first delivery did not fail.');
        self::reload();
    }

    private static function usersFailingOnce(): UserRepositoryInterface
    {
        return new class(self::service('test.beffroi.users', UserRepositoryInterface::class)) implements UserRepositoryInterface {
            private bool $failed = false;

            public function __construct(
                private readonly UserRepositoryInterface $stored,
            ) {
            }

            public function find(Uuid $id): ?User
            {
                return $this->stored->find($id);
            }

            public function findBySubject(Tenant $tenant, Subject $subject): ?User
            {
                return $this->stored->findBySubject($tenant, $subject);
            }

            public function findByUsername(Tenant $tenant, string $username): ?User
            {
                return $this->stored->findByUsername($tenant, $username);
            }

            public function findAllByEmail(Tenant $tenant, EmailAddress $email): array
            {
                return $this->stored->findAllByEmail($tenant, $email);
            }

            public function save(User $user): void
            {
                if (! $this->failed) {
                    $this->failed = true;

                    throw new RuntimeException('The connection was lost.');
                }
                $this->stored->save($user);
            }
        };
    }

    private static function groupsFailingOnce(): GroupRepositoryInterface
    {
        return new class(self::storedGroups()) implements GroupRepositoryInterface {
            private bool $failed = false;

            public function __construct(
                private readonly GroupRepositoryInterface $stored,
            ) {
            }

            public function findByName(Tenant $tenant, string $name): ?Group
            {
                return $this->stored->findByName($tenant, $name);
            }

            public function save(Group $group): void
            {
                if (! $this->failed) {
                    $this->failed = true;

                    throw new RuntimeException('The connection was lost.');
                }
                $this->stored->save($group);
            }
        };
    }

    private static function storedGroups(): GroupRepositoryInterface
    {
        return self::service('test.beffroi.groups', GroupRepositoryInterface::class);
    }
}
