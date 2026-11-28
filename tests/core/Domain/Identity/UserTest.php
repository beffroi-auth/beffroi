<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Tests\Fixture\TextsThatAreNotPlain;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UsernameRefusedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function mb_strlen;
use function str_repeat;
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

    /**
     * Decision 0050
     */
    #[Test]
    public function aNewUserChoseNoChannel(): void
    {
        // When
        $user = Fixtures::user();

        // Then
        static::assertTrue($user->notificationChannels->isNone());
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function choosingChannelsDatesTheUser(): void
    {
        // Given
        $user = Fixtures::user();
        $later = new DateTimeImmutable('2026-09-16T00:00:00+00:00');
        $chosen = new ChosenChannels(['mail']);

        // When
        $user->chooseChannels($chosen, $later);

        // Then
        static::assertSame([$chosen, $later], [$user->notificationChannels, $user->updatedAt]);
    }

    /**
     * RFC 8265 §3.2: the case of a username is mapped where it is compared, never where it is kept.
     */
    #[Test]
    public function theUsernameIsKeptAsWritten(): void
    {
        // When
        $user = Fixtures::user(username: "\u{FF21}lice");

        // Then
        static::assertSame("\u{FF21}lice", $user->username);
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
    #[DataProvider('provideCharacters')]
    public function theUsernameMayBe255CharactersLong(string $character): void
    {
        // When
        $user = Fixtures::user(username: str_repeat($character, 255));

        // Then
        static::assertSame(255, mb_strlen($user->username));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCharacters(): iterable
    {
        yield 'one byte each' => ['a'];
        yield 'two bytes each' => ['é'];
        yield 'four bytes each' => ["\u{20000}"];
    }

    /**
     * RFC 8265 §3.1
     */
    #[Test]
    public function theUsernameIsNeverEmpty(): void
    {
        // Then
        $this->expectException(UsernameRefusedException::class);

        // When
        User::create(Uuid::v7(), Fixtures::tenant(), new Subject('s'), '   ', Fixtures::now());
    }

    #[Test]
    #[DataProvider('provideCharactersPastTheBound')]
    public function theUsernameIsAtMost255Characters(string $character): void
    {
        // Then
        $this->expectException(UsernameRefusedException::class);
        $this->expectExceptionMessageIs('A username is 1 to 255 characters long.');

        // When
        Fixtures::user(username: str_repeat($character, 256));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCharactersPastTheBound(): iterable
    {
        yield 'one byte each' => ['a'];
        yield 'two bytes each' => ['é'];
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

    /**
     * OIDC Core §5.1
     */
    #[Test]
    #[DataProvider('providePhoneNumbersThatAreNotPlain')]
    public function aPhoneNumberThatIsNotPlainTextIsRefused(string $phoneNumber): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A phone number is plain text of at most 64 characters, with no control, format or line separator character.');

        // When
        $user->changePhoneNumber($phoneNumber, false, Fixtures::now());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePhoneNumbersThatAreNotPlain(): iterable
    {
        yield 'two million characters' => [str_repeat('1', 2_000_000)];
        yield 'a number followed by a line' => ["+33600000000\nCall this number instead"];
        yield 'a number written right to left' => ["+33600000000\u{202E}"];
    }

    #[Test]
    public function aPhoneNumberWithAnExtensionIsKept(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $user->changePhoneNumber('+1 (604) 555-1234;ext=5678', false, Fixtures::now());

        // Then
        static::assertSame('+1 (604) 555-1234;ext=5678', $user->phoneNumber);
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

    /**
     * Decision 0048
     */
    #[Test]
    #[DataProvider('provideEmailVerifications')]
    public function aMessageIsWrittenToAnEmailOnceItIsVerified(bool $verified, ?string $writtenTo): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('alice@acme.example'), $verified, Fixtures::now());

        // When / Then
        static::assertSame($writtenTo, $user->verifiedEmail()?->value);
    }

    /**
     * @return iterable<string, array{bool, ?string}>
     */
    public static function provideEmailVerifications(): iterable
    {
        yield 'verified' => [true, 'alice@acme.example'];
        yield 'not verified' => [false, null];
    }

    /**
     * Decision 0048
     */
    #[Test]
    #[DataProvider('providePhoneNumberVerifications')]
    public function aMessageIsTextedToAPhoneNumberOnceItIsVerified(bool $verified, ?string $textedTo): void
    {
        // Given
        $user = Fixtures::user();
        $user->changePhoneNumber('+33600000000', $verified, Fixtures::now());

        // When / Then
        static::assertSame($textedTo, $user->verifiedPhoneNumber());
    }

    /**
     * @return iterable<string, array{bool, ?string}>
     */
    public static function providePhoneNumberVerifications(): iterable
    {
        yield 'verified' => [true, '+33600000000'];
        yield 'not verified' => [false, null];
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
     * Decision 0002
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

    /**
     * RFC 8264 §4.2.3
     */
    #[Test]
    #[DataProvider('provideUsernamesThatAreNotPlainText')]
    public function aUsernameThatIsNotPlainTextIsRefused(string $username): void
    {
        // Then
        $this->expectException(UsernameRefusedException::class);
        $this->expectExceptionMessageIsOrContains('A username holds letters and digits of any script and printable ASCII');

        // When
        Fixtures::user(username: $username);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUsernamesThatAreNotPlainText(): iterable
    {
        yield from TextsThatAreNotPlain::around('mallory');
    }

    /**
     * RFC 8264 §4.2.3
     */
    #[Test]
    public function aUsernameThatIsNotPlainTextIsRefusedOnARename(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(UsernameRefusedException::class);
        $this->expectExceptionMessageIsOrContains('A username holds letters and digits of any script and printable ASCII');

        // When
        $user->rename("alice\e[2K\e[1Aadmin", Fixtures::now());
    }
}
