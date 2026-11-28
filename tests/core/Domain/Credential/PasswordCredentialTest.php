<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class PasswordCredentialTest extends TestCase
{
    #[Test]
    public function itBelongsToTheTenantOfItsUserAndStartsUnused(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());

        // Then
        static::assertSame($user->tenant, $credential->tenant);
        static::assertNull($credential->lastUsedAt);
        static::assertEquals(Fixtures::now(), $credential->hashChangedAt);
    }

    #[Test]
    public function itNamesItsKindAndHasNoLabel(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());

        // When / Then
        static::assertSame('password', $credential->kind());
        static::assertNull($credential->label());
    }

    /**
     * RFC 8176 §2, Architecture §4.3
     */
    #[Test]
    public function anAuthenticationWithItMayProveAPassword(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());

        // When / Then
        static::assertSame(['pwd'], array_map(static fn (AuthenticationMethod $method): string => $method->value, $credential->provableMethods()));
    }

    #[Test]
    public function itRecordsWhenItWasUsed(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');

        // When
        $credential->markUsed($used);

        // Then
        static::assertSame($used, $credential->lastUsedAt);
    }

    #[Test]
    public function aRehashReplacesTheHashAndDatesItWithoutTouchingTheLastUse(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        $rehashed = new DateTimeImmutable('2026-09-16T08:00:01+00:00');

        // When
        $credential->rehash(new PasswordHash(new Argon2id(), '$argon2id$new'), $rehashed);

        // Then
        static::assertSame(Argon2id::NAME, $credential->hash->algorithm->name());
        static::assertSame($rehashed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }

    #[Test]
    public function aPasswordChangeReplacesTheHashAndDatesItWithoutTouchingTheLastUse(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Argon2id(), '$argon2id$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        $changed = new DateTimeImmutable('2026-09-17T08:00:00+00:00');

        // When
        $credential->changePassword(new PasswordHash(new Argon2id(), '$argon2id$new'), $changed);

        // Then
        static::assertSame('$argon2id$new', $credential->hash->encoded);
        static::assertSame($changed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }

    #[Test]
    public function aPasswordFoundInABreachIsMarkedAsFoundAndAsLookedUp(): void
    {
        // Given
        $credential = self::credential();
        $found = new DateTimeImmutable('2026-10-10T12:00:00+00:00');

        // When
        $credential->foundInABreach($found);

        // Then
        static::assertTrue($credential->isBreached());
        static::assertSame($found, $credential->breachFoundAt);
        static::assertSame($found, $credential->breachCheckedAt);
    }

    #[Test]
    public function aPasswordNoListHoldsIsMarkedAsLookedUpAndNotAsFound(): void
    {
        // Given
        $credential = self::credential();
        $checked = new DateTimeImmutable('2026-10-10T12:00:00+00:00');

        // When
        $credential->notFoundInABreach($checked);

        // Then
        static::assertFalse($credential->isBreached());
        static::assertSame($checked, $credential->breachCheckedAt);
        static::assertNull($credential->breachFoundAt);
    }

    #[Test]
    public function aPasswordNobodyHasAskedAboutIsDue(): void
    {
        // When / Then
        static::assertTrue(self::credential()->dueForABreachLookup(Fixtures::now()));
    }

    #[Test]
    #[DataProvider('provideMomentsAfterALookup')]
    public function aPasswordIsDueAgainOnlyPastTheDelay(string $modification, bool $due): void
    {
        // Given
        $credential = self::credential();
        $checked = new DateTimeImmutable('2026-10-10T12:00:00+00:00');
        $credential->notFoundInABreach($checked);

        // When / Then
        static::assertSame($due, $credential->dueForABreachLookup($checked->modify($modification)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideMomentsAfterALookup(): iterable
    {
        yield 'the same moment' => ['+0 second', false];
        yield 'a day later' => ['+1 day', false];
        yield 'a second short of the delay' => ['+30 days -1 second', false];
        yield 'the delay to the second' => ['+30 days', true];
        yield 'a year later' => ['+1 year', true];
    }

    #[Test]
    public function aPasswordChangeForgetsWhatAListSaidOfTheOneBefore(): void
    {
        // Given
        $credential = self::credential();
        $credential->foundInABreach(Fixtures::now());

        // When
        $credential->changePassword(new PasswordHash(new Argon2id(), '$argon2id$new'), new DateTimeImmutable('2026-10-11T08:00:00+00:00'));

        // Then
        static::assertFalse($credential->isBreached());
        static::assertNull($credential->breachCheckedAt);
        static::assertTrue($credential->dueForABreachLookup(Fixtures::now()));
    }

    #[Test]
    public function aRehashKeepsWhatAListSaidOfTheSamePassword(): void
    {
        // Given
        $credential = self::credential();
        $found = new DateTimeImmutable('2026-10-10T12:00:00+00:00');
        $credential->foundInABreach($found);

        // When
        $credential->rehash(new PasswordHash(new Argon2id(), '$argon2id$stronger'), new DateTimeImmutable('2026-10-11T08:00:00+00:00'));

        // Then
        static::assertTrue($credential->isBreached());
        static::assertSame($found, $credential->breachFoundAt);
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aPasswordPosedNowIsNotHashedAsTyped(): void
    {
        // When / Then
        static::assertFalse(self::credential()->hashedAsTyped);
    }

    /**
     * Decision 0065, RFC 8265 §8.2
     */
    #[Test]
    public function aRehashLeavesNoHashOfTheBytesAsTyped(): void
    {
        // Given
        $credential = Fixtures::hashedAsTyped(self::credential());

        // When
        $credential->rehash(new PasswordHash(new Argon2id(), '$argon2id$enforced'), new DateTimeImmutable('2026-10-11T08:00:00+00:00'));

        // Then
        static::assertFalse($credential->hashedAsTyped);
    }

    /**
     * Decision 0065, RFC 8265 §8.2
     */
    #[Test]
    public function aPasswordChangeLeavesNoHashOfTheBytesAsTyped(): void
    {
        // Given
        $credential = Fixtures::hashedAsTyped(self::credential());

        // When
        $credential->changePassword(new PasswordHash(new Argon2id(), '$argon2id$posed'), new DateTimeImmutable('2026-10-11T08:00:00+00:00'));

        // Then
        static::assertFalse($credential->hashedAsTyped);
    }

    private static function credential(): PasswordCredential
    {
        return new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Argon2id(), '$argon2id$old'), Fixtures::now());
    }
}
