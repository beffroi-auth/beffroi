<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use Symfony\Component\Uid\Uuid;

final class UserTest extends TestCase
{
    #[Test]
    public function aNewUserIsEnabledUnverifiedAndHasAnEmptyProfile(): void
    {
        // When
        $user = Fixtures::user();

        // Then
        static::assertTrue($user->isEnabled());
        static::assertNull($user->email);
        static::assertFalse($user->emailVerified);
        static::assertNull($user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
        static::assertEquals(Profile::empty(), $user->profile);
        static::assertNull($user->address);
        static::assertSame($user->createdAt, $user->updatedAt);
    }

    #[Test]
    public function theUsernameIsTrimmed(): void
    {
        // When
        $user = Fixtures::user(username: '  alice  ');

        // Then
        static::assertSame('alice', $user->username);
    }

    #[Test]
    public function theUsernameMayBe255CharactersLong(): void
    {
        // When
        $user = Fixtures::user(username: str_repeat('a', 255));

        // Then
        static::assertSame(255, strlen($user->username));
    }

    #[Test]
    public function theUsernameIsNeverEmpty(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        User::create(Uuid::v7(), Fixtures::tenant(), new Subject('s'), '   ', Fixtures::now());
    }

    #[Test]
    public function theUsernameIsAtMost255Characters(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        Fixtures::user(username: str_repeat('a', 256));
    }

    #[Test]
    public function itCannotBeCreatedWithAVerifiedButAbsentEmail(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new User(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('s'),
            'alice',
            null,
            true,
            Profile::empty(),
            null,
            false,
            null,
            Fixtures::now(),
            Fixtures::now(),
            UserSource::local(),
        );
    }

    #[Test]
    public function itCannotBeCreatedWithAVerifiedButAbsentPhoneNumber(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new User(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('s'),
            'alice',
            null,
            false,
            Profile::empty(),
            null,
            true,
            null,
            Fixtures::now(),
            Fixtures::now(),
            UserSource::local(),
        );
    }

    #[Test]
    public function itCanBeCreatedWithAVerifiedEmailAndAVerifiedPhoneNumber(): void
    {
        // When
        $user = new User(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('s'),
            'alice',
            new EmailAddress('alice@acme.example'),
            true,
            Profile::empty(),
            '+33600000000',
            true,
            null,
            Fixtures::now(),
            Fixtures::now(),
            UserSource::local(),
        );

        // Then
        static::assertTrue($user->emailVerified);
        static::assertTrue($user->phoneNumberVerified);
    }

    #[Test]
    public function aPhoneNumberCanBeSetAsVerified(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $user->changePhoneNumber('+33600000000', true, Fixtures::now());

        // Then
        static::assertSame('+33600000000', $user->phoneNumber);
        static::assertTrue($user->phoneNumberVerified);
    }

    #[Test]
    public function aPhoneNumberCanBeRemoved(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changePhoneNumber('+33600000000', true, Fixtures::now());

        // When
        $user->changePhoneNumber(null, false, Fixtures::now());

        // Then
        static::assertNull($user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
    }

    #[Test]
    public function changingTheEmailCarriesItsVerificationStateAndDatesTheUser(): void
    {
        // Given
        $user = Fixtures::user();
        $later = new DateTimeImmutable('2026-09-16T00:00:00+00:00');

        // When
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, $later);

        // Then
        static::assertSame('alice@acme.example', (string) $user->email);
        static::assertTrue($user->emailVerified);
        static::assertSame($later, $user->updatedAt);
    }

    /**
     * A verified flag never survives a change of address: a new address is unverified until proven otherwise.
     */
    #[Test]
    public function aNewEmailDoesNotInheritTheVerificationOfThePreviousOne(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        $user->changeEmail(new EmailAddress('alice@other.example'), false, Fixtures::now());

        // Then
        static::assertFalse($user->emailVerified);
    }

    #[Test]
    public function anAbsentEmailCannotBeVerified(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        Fixtures::user()->changeEmail(null, true, Fixtures::now());
    }

    #[Test]
    public function anAbsentPhoneNumberCannotBeVerified(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        Fixtures::user()->changePhoneNumber(null, true, Fixtures::now());
    }

    #[Test]
    public function anEmptyAddressIsStoredAsNoAddress(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $user->changeAddress(new Address(), Fixtures::now());

        // Then
        static::assertNull($user->address);
    }

    #[Test]
    public function anAddressWithAFieldIsStored(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $user->changeAddress(new Address(locality: 'Lyon'), Fixtures::now());

        // Then
        static::assertSame('Lyon', $user->address?->locality);
    }

    #[Test]
    public function anAddressCanBeRemoved(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeAddress(new Address(locality: 'Lyon'), Fixtures::now());

        // When
        $user->changeAddress(null, Fixtures::now());

        // Then
        static::assertNull($user->address);
    }

    #[Test]
    public function disablingDatesTheUser(): void
    {
        // Given
        $user = Fixtures::user();
        $disabledAt = new DateTimeImmutable('2026-09-16T00:00:00+00:00');

        // When
        $user->disable($disabledAt);

        // Then
        static::assertFalse($user->isEnabled());
        static::assertSame($disabledAt, $user->disabledAt);
        static::assertSame($disabledAt, $user->updatedAt);
    }

    #[Test]
    public function disablingIsIdempotent(): void
    {
        // Given
        $user = Fixtures::user();
        $first = new DateTimeImmutable('2026-09-16T00:00:00+00:00');
        $user->disable($first);

        // When
        $user->disable(new DateTimeImmutable('2026-09-17T00:00:00+00:00'));

        // Then
        static::assertFalse($user->isEnabled());
        static::assertSame($first, $user->disabledAt);
        static::assertSame($first, $user->updatedAt);
    }

    #[Test]
    public function disablingIsReversible(): void
    {
        // Given
        $user = Fixtures::user();
        $user->disable(new DateTimeImmutable('2026-09-16T00:00:00+00:00'));
        $enabledAt = new DateTimeImmutable('2026-09-17T00:00:00+00:00');

        // When
        $user->enable($enabledAt);

        // Then
        static::assertTrue($user->isEnabled());
        static::assertSame($enabledAt, $user->updatedAt);
    }

    #[Test]
    public function itBelongsToItsTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);

        // When / Then
        static::assertTrue($user->belongsTo($tenant));
    }

    #[Test]
    public function itDoesNotBelongToAnotherTenant(): void
    {
        // Given
        $user = Fixtures::user(Fixtures::tenant());

        // When / Then
        static::assertFalse($user->belongsTo(Fixtures::tenant('other', 'https://id.other.example')));
    }

    /**
     * Issue #452 and decision 0002: a person may say a claim of themselves when their tenant opens it and
     * the source that created them does not hold it.
     *
     * @param list<string> $opened
     */
    #[Test]
    #[DataProvider('provideWhatAPersonMaySay')]
    public function whatAPersonMaySayOfThemselvesIsWhatTheTenantOpensAndTheSourceLeaves(array $opened, UserSource $source, bool $may): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $tenant->adoptSelfServedClaims(new SelfServedClaims($opened));
        $user = User::create(Uuid::v7(), $tenant, new Subject('alice-subject'), 'alice', Fixtures::now(), source: $source);

        // When / Then
        static::assertSame($may, $user->maySayOfThemselves('nickname'));
    }

    /**
     * @return iterable<string, array{list<string>, UserSource, bool}>
     */
    public static function provideWhatAPersonMaySay(): iterable
    {
        yield 'opened, of a local person' => [['nickname'], UserSource::local(), true];
        yield 'opened, and left by the source' => [['nickname'], UserSource::upstream('workforce', ['email']), true];
        yield 'opened, and held by the source' => [['nickname'], UserSource::upstream('workforce', ['nickname']), false];
        yield 'not opened' => [['zoneinfo'], UserSource::local(), false];
    }

    /**
     * Issue #781: what the provider that created a person holds of them is what it fills and says at its
     * last sign-in, so no claim is held for ever.
     */
    #[Test]
    public function whatItsSourceHoldsChanges(): void
    {
        // Given
        $user = User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice',
            Fixtures::now(),
            source: UserSource::upstream('workforce', ['email', 'given_name']),
        );
        $now = new DateTimeImmutable('2026-10-22T12:00:00+00:00');

        // When
        $user->heldBy(UserSource::upstream('workforce', ['email']), $now);

        // Then
        static::assertEquals(UserSource::upstream('workforce', ['email']), $user->source);
        static::assertSame($now, $user->updatedAt);
    }

    /**
     * The person stays the one the provider created: a source of another provider, or none, is a link or a
     * move, and no sign-in makes either.
     */
    #[Test]
    #[DataProvider('provideSourcesOfAnotherProvider')]
    public function theProviderThatCreatedThePersonDoesNotChange(UserSource $was, UserSource $other): void
    {
        // Given
        $user = User::create(Uuid::v7(), Fixtures::tenant(), new Subject('alice-subject'), 'alice', Fixtures::now(), source: $was);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('What a source holds of a person changes, and the provider that created the person does not.');

        // When
        $user->heldBy($other, Fixtures::now());
    }

    /**
     * @return iterable<string, array{UserSource, UserSource}>
     */
    public static function provideSourcesOfAnotherProvider(): iterable
    {
        yield 'another provider' => [UserSource::upstream('workforce', ['email']), UserSource::upstream('partners', ['email'])];
        yield 'a local person given a provider' => [UserSource::local(), UserSource::upstream('workforce', ['email'])];
        yield 'a person of a provider made local' => [UserSource::upstream('workforce', ['email']), UserSource::local()];
    }
}
