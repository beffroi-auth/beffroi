<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity\Member;

use Beffroi\Core\Application\Identity\Member\UsernameMember;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class UsernameMemberTest extends TestCase
{
    #[Test]
    public function thePersonSignsInWithTheUsernameSaid(): void
    {
        // Given
        $alice = Fixtures::user();

        // When
        new UsernameMember(new InMemoryUserRepository())->say($alice, ' ada ', Fixtures::now());

        // Then
        static::assertSame('ada', $alice->username);
    }

    #[Test]
    public function theirOwnUsernameSaidAgainChangesNothing(): void
    {
        // Given
        $alice = Fixtures::user();
        $users = new InMemoryUserRepository();
        $users->save($alice);

        // When
        new UsernameMember($users)->say($alice, 'alice', new DateTimeImmutable('2026-09-16T10:00:00+00:00'));

        // Then
        static::assertEquals(Fixtures::now(), $alice->updatedAt);
    }

    #[Test]
    public function aUsernameAnotherPersonOfTheTenantHasIsRefused(): void
    {
        // Given
        $alice = Fixtures::user();
        $users = new InMemoryUserRepository();
        $users->save(Fixtures::user($alice->tenant, 'bob', 'bob-subject'));

        // Then
        $this->expectException(UserAlreadyExistsException::class);

        // When
        new UsernameMember($users)->say($alice, 'bob', Fixtures::now());
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function aUsernameComparingEqualToThatOfAnotherPersonIsRefused(): void
    {
        // Given
        $alice = Fixtures::user();
        $users = new InMemoryUserRepository();
        $users->save(Fixtures::user($alice->tenant, 'bob', 'bob-subject'));

        // Then
        $this->expectException(UserAlreadyExistsException::class);

        // When
        new UsernameMember($users)->say($alice, 'BOB', Fixtures::now());
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function aPersonIsRenamedUnderAnotherCaseOfTheirOwnUsername(): void
    {
        // Given
        $alice = Fixtures::user();
        $users = new InMemoryUserRepository();
        $users->save($alice);

        // When
        new UsernameMember($users)->say($alice, 'Alice', Fixtures::now());

        // Then
        static::assertSame('Alice', $alice->username);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function noUsername(): iterable
    {
        yield 'null' => [null];
        yield 'an empty text' => [''];
        yield 'spaces' => ['   '];
    }

    #[Test]
    #[DataProvider('noUsername')]
    public function aPersonKeepsAUsername(mixed $value): void
    {
        // Given
        $alice = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A person keeps a username.');

        // When
        new UsernameMember(new InMemoryUserRepository())->say($alice, $value, Fixtures::now());
    }
}
