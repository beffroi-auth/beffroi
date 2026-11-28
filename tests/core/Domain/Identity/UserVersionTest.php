<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class UserVersionTest extends TestCase
{
    private const string ADDRESS = 'alice@acme.example';

    /**
     * RFC 7643 §3.1
     */
    #[Test]
    public function aPersonCreatedIsAtTheFirstVersionLastChangedWhenCreated(): void
    {
        // When
        $user = Fixtures::user();

        // Then
        static::assertSame([1, $user->createdAt], [$user->version, $user->updatedAt]);
    }

    /**
     * RFC 7643 §3.1
     */
    #[Test]
    public function aPersonCreatedWithAProfileAndAPhoneNumberIsAtTheFirstVersionLastChangedWhenCreated(): void
    {
        // When
        $user = User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice',
            Fixtures::now(),
            profile: new Profile(name: 'Alice'),
            phoneNumber: '+33612345678',
        );

        // Then
        static::assertSame([1, $user->createdAt], [$user->version, $user->updatedAt]);
    }

    /**
     * RFC 7644 §3.14, RFC 9110 §8.8.1, RFC 7643 §3.1
     *
     * @param Closure(): User                       $person
     * @param Closure(User, DateTimeImmutable): void $change
     */
    #[Test]
    #[DataProvider('provideChanges')]
    public function everyChangeOfAPersonRaisesItsVersionOnceAndDatesIt(Closure $person, Closure $change): void
    {
        // Given
        $user = $person();
        $version = $user->version;
        $later = Fixtures::now()->modify('+1 hour');

        // When
        $change($user, $later);

        // Then
        static::assertSame([$version + 1, $later], [$user->version, $user->updatedAt]);
    }

    /**
     * @return iterable<string, array{Closure(): User, Closure(User, DateTimeImmutable): void}>
     */
    public static function provideChanges(): iterable
    {
        yield 'renamed' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->rename('bob', $now),
        ];
        yield 'a new address, which takes the verification and the key back' => [
            self::encrypted(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changeEmail(new EmailAddress('alice@other.example'), false, $now),
        ];
        yield 'the verification of the address taken back' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changeEmail(new EmailAddress(self::ADDRESS), false, $now),
        ];
        yield 'a phone number' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changePhoneNumber('+33612345678', false, $now),
        ];
        yield 'the mail encrypted' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->encryptMailTo(self::key(), $now),
        ];
        yield 'the mail written in clear' => [
            self::encrypted(...),
            static fn (User $user, DateTimeImmutable $now) => $user->writeMailInClear($now),
        ];
        yield 'a profile' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->updateProfile(new Profile(name: 'Alice'), $now),
        ];
        yield 'an address' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changeAddress(new Address(locality: 'Lille'), $now),
        ];
        yield 'what its source holds' => [
            self::provisioned(...),
            static fn (User $user, DateTimeImmutable $now) => $user->heldBy(UserSource::upstream('workforce', ['email', 'name']), $now),
        ];
        yield 'the channels chosen' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->chooseChannels(new ChosenChannels(['email']), $now),
        ];
        yield 'disabled' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->disable($now),
        ];
        yield 'enabled' => [
            self::disabled(...),
            static fn (User $user, DateTimeImmutable $now) => $user->enable($now),
        ];
        yield 'a group entered or left' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->membershipChanged($now),
        ];
    }

    /**
     * RFC 7644 §3.14, RFC 7643 §3.1
     *
     * @param Closure(): User                       $person
     * @param Closure(User, DateTimeImmutable): void $call
     */
    #[Test]
    #[DataProvider('provideCallsThatChangeNothing')]
    public function aCallThatChangesNothingLeavesTheVersionAndTheLastChange(Closure $person, Closure $call): void
    {
        // Given
        $user = $person();
        $was = [$user->version, $user->updatedAt];

        // When
        $call($user, Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertSame($was, [$user->version, $user->updatedAt]);
    }

    /**
     * @return iterable<string, array{Closure(): User, Closure(User, DateTimeImmutable): void}>
     */
    public static function provideCallsThatChangeNothing(): iterable
    {
        yield 'the same username' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->rename('alice', $now),
        ];
        yield 'the same username, with the spaces a username loses' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->rename('  alice  ', $now),
        ];
        yield 'the same address, verified as it was' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changeEmail(new EmailAddress(self::ADDRESS), true, $now),
        ];
        yield 'no phone number again' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changePhoneNumber(null, false, $now),
        ];
        yield 'the same key' => [
            self::encrypted(...),
            static fn (User $user, DateTimeImmutable $now) => $user->encryptMailTo(self::key(), $now),
        ];
        yield 'the mail in clear again' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->writeMailInClear($now),
        ];
        yield 'the same profile' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->updateProfile(Profile::empty(), $now),
        ];
        yield 'an empty address, which is none' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->changeAddress(new Address(), $now),
        ];
        yield 'what its source held' => [
            self::provisioned(...),
            static fn (User $user, DateTimeImmutable $now) => $user->heldBy(UserSource::upstream('workforce', ['email']), $now),
        ];
        yield 'no channel again' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->chooseChannels(ChosenChannels::none(), $now),
        ];
        yield 'disabled again' => [
            self::disabled(...),
            static fn (User $user, DateTimeImmutable $now) => $user->disable($now),
        ];
        yield 'enabled again' => [
            self::verified(...),
            static fn (User $user, DateTimeImmutable $now) => $user->enable($now),
        ];
    }

    private static function verified(): User
    {
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());

        return $user;
    }

    private static function encrypted(): User
    {
        $user = self::verified();
        $user->encryptMailTo(self::key(), Fixtures::now());

        return $user;
    }

    private static function disabled(): User
    {
        $user = self::verified();
        $user->disable(Fixtures::now());

        return $user;
    }

    private static function provisioned(): User
    {
        return User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice',
            Fixtures::now(),
            source: UserSource::upstream('workforce', ['email']),
        );
    }

    private static function key(): MailEncryptionKey
    {
        return new MailEncryptionKey(
            'smime',
            'material',
            '9F2C',
            [new EmailAddress(self::ADDRESS)],
            new DateTimeImmutable('2020-01-01'),
            new DateTimeImmutable('2030-01-01'),
        );
    }
}
