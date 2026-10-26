<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Bundle\Doctrine\TenantSynchronizer;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Tests\Fixture\Predicates;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.4: users found by identifier, by subject, by username and by address within a tenant.
 */
final class DoctrineUserRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aUserComesBackAsItWasSaved(): void
    {
        // Given
        $user = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now(), new EmailAddress('alice@example.com'), true);
        $user->updateProfile(
            new Profile(
                'Alice Example',
                'Alice',
                'Example',
                null,
                'ali',
                'alice',
                'https://example.com/alice',
                'https://example.com/alice.png',
                'https://alice.example',
                'female',
                '1990-01-31',
                'Europe/Paris',
                'fr-FR',
            ),
            self::now(),
        );
        $user->changePhoneNumber('+33612345678', true, self::now());
        $user->changeAddress(new Address('1 rue de la Paix, 75002 Paris', '1 rue de la Paix', 'Paris', 'Île-de-France', '75002', 'FR'), self::now());
        $user->disable(self::now()->modify('+1 day'));
        self::users()->save($user);
        self::reload();

        // When
        $found = self::users()->find($user->id) ?? static::fail('The user was not stored.');

        // Then
        static::assertNotSame($user, $found);
        static::assertTrue($found->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('alice-subject', (string) $found->subject);
        static::assertSame('alice', $found->username);
        static::assertSame('alice@example.com', (string) $found->email);
        static::assertTrue($found->emailVerified);
        static::assertEquals($user->profile, $found->profile);
        static::assertSame('+33612345678', $found->phoneNumber);
        static::assertTrue($found->phoneNumberVerified);
        static::assertEquals($user->address, $found->address);
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now()->modify('+1 day'), $found->updatedAt);
        static::assertEquals(self::now()->modify('+1 day'), $found->disabledAt);
        static::assertFalse($found->isEnabled());
    }

    #[Test]
    public function anEmptyProfileAndNoAddressComeBackAsSuch(): void
    {
        // Given
        $user = self::user();
        self::reload();

        // When
        $found = self::users()->find($user->id) ?? static::fail('The user was not stored.');

        // Then
        static::assertNull($found->email);
        static::assertFalse($found->emailVerified);
        static::assertEquals(Profile::empty(), $found->profile);
        static::assertNull($found->address);
        static::assertNull($found->phoneNumber);
        static::assertNull($found->disabledAt);
        static::assertTrue($found->isEnabled());
    }

    #[Test]
    public function aChangeIsWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $user->rename('alice2', self::now()->modify('+1 hour'));
        $user->changeEmail(new EmailAddress('alice2@example.com'), false, self::now()->modify('+1 hour'));
        self::users()->save($user);
        self::reload();

        // When
        $found = self::users()->find($user->id) ?? static::fail('The user was not stored.');

        // Then
        static::assertSame('alice2', $found->username);
        static::assertSame('alice2@example.com', (string) $found->email);
        static::assertEquals(self::now()->modify('+1 hour'), $found->updatedAt);
    }

    /**
     * Issue #781: what the provider that created a person holds changes at its sign-ins, and the column
     * follows.
     */
    #[Test]
    public function whatItsSourceHoldsIsWrittenOnSave(): void
    {
        // Given
        $user = User::create(
            Uuid::v7(),
            self::tenant(),
            new Subject('alice-subject'),
            'alice',
            self::now(),
            source: UserSource::upstream('https://idp.acme.example/saml', ['email', 'given_name']),
        );
        self::users()->save($user);
        self::reload();
        $found = self::users()->find($user->id) ?? static::fail('The user was not stored.');
        $found->heldBy(UserSource::upstream('https://idp.acme.example/saml', ['email']), self::now()->modify('+1 hour'));
        self::users()->save($found);
        self::reload();

        // When
        $again = self::users()->find($user->id) ?? static::fail('The user was not stored.');

        // Then
        static::assertEquals(UserSource::upstream('https://idp.acme.example/saml', ['email']), $again->source);
    }

    #[Test]
    public function aUserIsFoundBySubjectWithinTheTenant(): void
    {
        // Given
        $alice = self::user();
        self::reload();

        // When
        $found = self::users()->findBySubject(self::tenant(), new Subject('alice-subject'));

        // Then
        static::assertTrue($alice->id->equals($found?->id));
    }

    #[Test]
    public function aUserIsFoundByUsernameWithinTheTenant(): void
    {
        // Given
        self::user();
        $bob = self::user('bob', 'bob-subject');
        self::reload();

        // When
        $found = self::users()->findByUsername(self::tenant(), 'bob');

        // Then
        static::assertTrue($bob->id->equals($found?->id));
    }

    /**
     * Issue #781: the first sign-in through an upstream provider asks whether somebody holds the address it
     * gave, on the blind index of the address, whose projection folds the domain and leaves the local part
     * as it is written (RFC 5321 §2.4).
     */
    #[Test]
    #[DataProvider('provideAddressesBobHolds')]
    public function aUserIsFoundByAddressWithinTheTenant(string $address): void
    {
        // Given
        self::user();
        $bob = self::user('bob', 'bob-subject');
        $bob->changeEmail(new EmailAddress('Bob@acme.example'), false, self::now());
        self::users()->save($bob);
        self::reload();

        // When
        $found = self::users()->findAllByEmail(self::tenant(), new EmailAddress($address));

        // Then
        static::assertCount(1, $found);
        static::assertTrue($bob->id->equals($found[0]->id));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddressesBobHolds(): iterable
    {
        yield 'as it was written' => ['Bob@acme.example'];
        yield 'its domain in another case' => ['Bob@ACME.Example'];
        // one mailbox however its local part is written, so that no second person holds it under another
        // spelling (issue #781)
        yield 'its local part in another case' => ['bob@acme.example'];
    }

    /**
     * Nothing says two persons may not share an address, so the lookup answers every one of them, and what
     * asks reads no order into it.
     */
    #[Test]
    public function everyPersonWhoHoldsAnAddressIsFound(): void
    {
        // Given
        $alice = self::user();
        $alice->changeEmail(new EmailAddress('Shared@acme.example'), false, self::now());
        self::users()->save($alice);
        $bob = self::user('bob', 'bob-subject');
        $bob->changeEmail(new EmailAddress('shared@acme.example'), false, self::now());
        self::users()->save($bob);
        self::reload();

        // When
        $found = self::users()->findAllByEmail(self::tenant(), new EmailAddress('shared@acme.example'));

        // Then
        static::assertCount(2, $found);
    }

    /**
     * Decision 0002: the same username and the same subject in another tenant are another user.
     */
    #[Test]
    public function aUserOfAnotherTenantIsFoundInThatTenant(): void
    {
        // Given
        self::user();
        $other = new TenantSynchronizer(
            new TenantFactory('https://other.test', 'other', null, new MockClock(self::now()), Predicates::wired()),
            self::managers(),
        )->synchronize();
        $stranger = User::create(Uuid::v7(), $other, new Subject('alice-subject'), 'alice', self::now());
        self::users()->save($stranger);
        self::reload();

        // When
        $found = self::users()->findByUsername($other, 'alice');

        // Then
        static::assertTrue($stranger->id->equals($found?->id));
    }

    #[Test]
    #[DataProvider('provideLookupsThatFindNothing')]
    public function anUnknownUserIsNotFound(callable $lookup): void
    {
        // Given
        self::user();
        self::reload();

        // When / Then
        static::assertNull($lookup(self::users()));
    }

    /**
     * @return iterable<string, array{callable(UserRepositoryInterface): ?User}>
     */
    public static function provideLookupsThatFindNothing(): iterable
    {
        yield 'an unknown subject' => [
            static fn (UserRepositoryInterface $users): ?User => $users->findBySubject(self::tenant(), new Subject('carol-subject')),
        ];
        yield 'an unknown username' => [
            static fn (UserRepositoryInterface $users): ?User => $users->findByUsername(self::tenant(), 'carol'),
        ];
        yield 'a username in another case' => [
            static fn (UserRepositoryInterface $users): ?User => $users->findByUsername(self::tenant(), 'ALICE'),
        ];
        yield 'an unknown address' => [
            static fn (UserRepositoryInterface $users): ?User => $users->findAllByEmail(self::tenant(), new EmailAddress('carol@example.com'))[0] ?? null,
        ];
        yield 'an unknown identifier' => [
            static fn (UserRepositoryInterface $users): ?User => $users->find(Uuid::v7()),
        ];
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
