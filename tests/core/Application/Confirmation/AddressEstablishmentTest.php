<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Confirmation;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Confirmation\AddressConfirmationIssuing;
use Beffroi\Core\Application\Confirmation\AddressConfirmationRedeeming;
use Beffroi\Core\Application\Confirmation\AddressEstablishment;
use Beffroi\Core\Bridge\InMemory\InMemoryAddressConfirmationRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Confirmation\AddressConfirmation;
use Beffroi\Core\Domain\Confirmation\ConfirmableAddressInterface;
use Beffroi\Core\Domain\Confirmation\ConfirmableEmail;
use Beffroi\Core\Domain\Confirmation\ConfirmablePhoneNumber;
use Beffroi\Core\Domain\Event\AddressConfirmationSent;
use Beffroi\Core\Domain\Event\AddressConfirmationWithheld;
use Beffroi\Core\Domain\Event\AddressEstablished;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Exception\AddressConfirmationRefusedException;
use Beffroi\Core\Exception\AddressConfirmationWithheldException;
use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Core\Tests\Fixture\FakeAttemptLimiter;
use Beffroi\Core\Tests\Fixture\FakeConfirmationSendLimiter;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingAddressConfirmationSender;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use function pack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function substr;
use Symfony\Component\Uid\Uuid;
use Beffroi\Core\Tests\Fixture\FakeMonotonicClock;

/**
 * NIST SP 800-63B-4 §4.2.1.2, decision 0026
 */
final class AddressEstablishmentTest extends TestCase
{
    private const string EMAIL = 'alice@acme.example';

    private const string PHONE_NUMBER = '+33612345678';

    private User $alice;

    private FakePasswordHasher $hasher;

    private InMemoryAddressConfirmationRepository $confirmations;

    private RecordingAddressConfirmationSender $sender;

    private InMemoryUserRepository $users;

    private InMemoryClaimHistory $history;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->alice->changeEmail(new EmailAddress(self::EMAIL), false, Fixtures::now());
        $this->alice->changePhoneNumber(self::PHONE_NUMBER, false, Fixtures::now());
        $this->hasher = new FakePasswordHasher();
        $this->confirmations = new InMemoryAddressConfirmationRepository();
        $this->sender = new RecordingAddressConfirmationSender();
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
        $this->history = new InMemoryClaimHistory();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock(Fixtures::now());
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function anAddressNobodyVerifiedAwaitsItsConfirmation(ConfirmableAddressInterface $kind, string $address): void
    {
        // When
        $awaited = $this->establishment($kind)->awaits($this->alice);

        // Then
        static::assertSame($address, $awaited);
    }

    /**
     * @return iterable<string, array{ConfirmableAddressInterface, string}>
     */
    public static function provideKinds(): iterable
    {
        yield 'the phone number' => [new ConfirmablePhoneNumber(), self::PHONE_NUMBER];
        yield 'the email address' => [new ConfirmableEmail(), self::EMAIL];
    }

    #[Test]
    #[DataProvider('provideAddressesThatAreNotTheirsToEstablish')]
    public function anAddressThatIsNotTheirsToEstablishAwaitsNoConfirmation(User $user): void
    {
        // When
        $awaited = $this->establishment(new ConfirmablePhoneNumber())->awaits($user);

        // Then
        static::assertNull($awaited);
    }

    /**
     * @return iterable<string, array{User}>
     */
    public static function provideAddressesThatAreNotTheirsToEstablish(): iterable
    {
        yield 'no number' => [Fixtures::user()];
        $verified = Fixtures::user();
        $verified->changePhoneNumber(self::PHONE_NUMBER, true, Fixtures::now());
        yield 'a number already verified' => [$verified];
        $disabled = Fixtures::user();
        $disabled->changePhoneNumber(self::PHONE_NUMBER, false, Fixtures::now());
        $disabled->disable(Fixtures::now());
        yield 'a person who cannot sign in' => [$disabled];
        $held = self::upstreamUser(['phone_number']);
        $held->changePhoneNumber(self::PHONE_NUMBER, false, Fixtures::now());
        yield 'a number the source holds' => [$held];
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function theCodeAndTheLinkGoToTheAddressTheyEstablish(ConfirmableAddressInterface $kind, string $address): void
    {
        // When
        $this->establishment($kind)->send($this->alice, Fixtures::context());

        // Then
        $issued = $this->sender->last();
        static::assertSame([$kind->claim(), $address], [$issued->claim, $issued->address]);
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    public function theCodeIsSixDecimalDigits(): void
    {
        // When
        $this->establishment(new ConfirmablePhoneNumber())->send($this->alice, Fixtures::context());

        // Then
        static::assertMatchesRegularExpression('/^\d{6}$/', $this->sender->last()->code);
    }

    /**
     * NIST SP 800-63B-4 §3.2.12
     */
    #[Test]
    public function aDrawThatWouldFavourSomeCodesIsDrawnAgain(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), randomness: new FixedRandomness([pack('N', 4_294_967_295), pack('N', 1_234_567)]));

        // When
        $establishment->send($this->alice, Fixtures::context());

        // Then
        static::assertSame('234567', $this->sender->last()->code);
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function theCodeIsKeptAsAHashBoundToTheAddress(): void
    {
        // When
        $this->establishment(new ConfirmablePhoneNumber())->send($this->alice, Fixtures::context());

        // Then
        $issued = $this->sender->last();
        static::assertEquals($this->hasher->hash(AddressConfirmation::bound($issued->code, self::PHONE_NUMBER)), $issued->confirmation->code);
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function theLinkIsKeptAsAHashBoundToTheAddress(): void
    {
        // When
        $this->establishment(new ConfirmablePhoneNumber())->send($this->alice, Fixtures::context());

        // Then
        $issued = $this->sender->last();
        static::assertEquals($this->hasher->hash(AddressConfirmation::bound($issued->value, self::PHONE_NUMBER)), $issued->confirmation->link);
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    #[DataProvider('provideLifetimes')]
    public function aConfirmationIsValidForAsLongAsACodeSentThereMayBe(ConfirmableAddressInterface $kind, string $lifetime): void
    {
        // When
        $this->establishment($kind)->send($this->alice, Fixtures::context());

        // Then
        static::assertEquals(Fixtures::now()->modify($lifetime), $this->sender->last()->confirmation->expiresAt);
    }

    /**
     * @return iterable<string, array{ConfirmableAddressInterface, string}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'by text message' => [new ConfirmablePhoneNumber(), '+10 minutes'];
        yield 'by mail' => [new ConfirmableEmail(), '+24 hours'];
    }

    #[Test]
    public function sendingAConfirmationIsAnActOfTheAccount(): void
    {
        // When
        $this->establishment(new ConfirmablePhoneNumber())->send($this->alice, Fixtures::context());

        // Then
        $acts = $this->events->of(AddressConfirmationSent::class);
        static::assertCount(1, $acts);
        static::assertSame(['phone_number', $this->alice->subject->value], [$acts[0]->claim, $acts[0]->subject()->value]);
    }

    #[Test]
    public function aSendIsCountedForThePersonAndTheAddress(): void
    {
        // Given
        $sends = new FakeConfirmationSendLimiter();

        // When
        $this->establishment(new ConfirmablePhoneNumber(), sends: $sends)->send($this->alice, Fixtures::context());

        // Then
        static::assertSame([[$this->alice->id->toRfc4122(), self::PHONE_NUMBER]], $sends->sends);
    }

    #[Test]
    public function aSendPastTheBudgetIsRefused(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), sends: new FakeConfirmationSendLimiter(1));
        $establishment->send($this->alice, Fixtures::context());

        // Then
        $this->expectException(AddressConfirmationWithheldException::class);
        $this->expectExceptionMessageIs('The person or the address has had every confirmation its budget allows.');

        // When
        $establishment->send($this->alice, Fixtures::context());
    }

    #[Test]
    public function aSendPastTheBudgetSendsNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), sends: new FakeConfirmationSendLimiter(1));
        $establishment->send($this->alice, Fixtures::context());

        // When
        try {
            $establishment->send($this->alice, Fixtures::context());
        } catch (AddressConfirmationWithheldException) {
        }

        // Then
        static::assertCount(1, $this->sender->sent);
    }

    #[Test]
    public function aSendPastTheBudgetLeavesTheConfirmationSentBeforeOpen(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), sends: new FakeConfirmationSendLimiter(1));
        $establishment->send($this->alice, Fixtures::context());
        $code = $this->sender->last()->code;
        try {
            $establishment->send($this->alice, Fixtures::context());
        } catch (AddressConfirmationWithheldException) {
        }

        // When
        $establishment->confirm($this->alice, $code, Fixtures::context());

        // Then
        static::assertSame(self::PHONE_NUMBER, $this->alice->verifiedPhoneNumber());
    }

    #[Test]
    public function aSendPastTheBudgetIsAnActOfTheAccount(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), sends: new FakeConfirmationSendLimiter(0));

        // When
        try {
            $establishment->send($this->alice, Fixtures::context());
        } catch (AddressConfirmationWithheldException) {
        }

        // Then
        $acts = $this->events->of(AddressConfirmationWithheld::class);
        static::assertCount(1, $acts);
        static::assertSame(['phone_number', $this->alice->subject->value], [$acts[0]->claim, $acts[0]->subject()->value]);
    }

    #[Test]
    public function anAddressThatAwaitsNoConfirmationIsSentNothing(): void
    {
        // Given
        $this->alice->changePhoneNumber(self::PHONE_NUMBER, true, Fixtures::now());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs('No address of this kind awaits a confirmation.');

        // When
        $this->establishment(new ConfirmablePhoneNumber())->send($this->alice, Fixtures::context());
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function theCodeTypedEstablishesTheAddress(ConfirmableAddressInterface $kind, string $address): void
    {
        // Given
        $establishment = $this->establishment($kind);
        $establishment->send($this->alice, Fixtures::context());

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());

        // Then
        static::assertTrue($kind->isVerified($this->alice));
        static::assertSame($address, $kind->of($this->alice));
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function theLinkFollowedEstablishesTheAddress(ConfirmableAddressInterface $kind, string $address): void
    {
        // Given
        $establishment = $this->establishment($kind);
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());

        // Then
        static::assertTrue($kind->isVerified($this->alice));
        static::assertSame($address, $kind->of($this->alice));
    }

    #[Test]
    public function aCodeTypedWithSpacesEstablishesTheAddress(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $code = $this->sender->last()->code;

        // When
        $establishment->confirm($this->alice, ' ' . substr($code, 0, 3) . ' ' . substr($code, 3) . ' ', Fixtures::context());

        // Then
        static::assertNotNull($this->alice->verifiedPhoneNumber());
    }

    #[Test]
    public function establishingAnAddressIsWrittenInTheHistoryOfThePerson(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());

        // Then
        $changes = $this->history->lastOf($this->alice, 2);
        static::assertCount(1, $changes);
        static::assertEquals(['phone_number_verified', 'false', 'true', new ThePerson()], [
            $changes[0]->claim,
            $changes[0]->was,
            $changes[0]->became,
            $changes[0]->author,
        ]);
    }

    #[Test]
    public function establishingAnAddressIsAnActOfTheAccount(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());

        // Then
        $acts = $this->events->of(AddressEstablished::class);
        static::assertCount(1, $acts);
        static::assertSame('phone_number', $acts[0]->claim);
    }

    #[Test]
    public function establishingAnAddressSpendsItsConfirmation(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());

        // Then
        static::assertSame([], $this->confirmations->unspentOf($this->alice));
    }

    #[Test]
    public function aWrongCodeEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, self::anotherCode($this->sender->last()->code), Fixtures::context());
    }

    #[Test]
    public function aNewCodeTakesBackTheOneNotSpent(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $first = $this->sender->last()->code;
        $establishment->send($this->alice, Fixtures::context());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $first, Fixtures::context());
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function aCodeSentToAnAddressThePersonChangedSinceEstablishesNothing(ConfirmableAddressInterface $kind, string $address): void
    {
        // Given
        $establishment = $this->establishment($kind);
        $establishment->send($this->alice, Fixtures::context());
        $this->alice->changeEmail(new EmailAddress('alice@elsewhere.example'), false, Fixtures::now());
        $this->alice->changePhoneNumber('+33698765432', false, Fixtures::now());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    #[DataProvider('provideLifetimes')]
    public function aCodeOutOfTimeEstablishesNothing(ConfirmableAddressInterface $kind, string $lifetime): void
    {
        // Given
        $establishment = $this->establishment($kind);
        $establishment->send($this->alice, Fixtures::context());
        $this->clock->modify($lifetime);

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());
    }

    #[Test]
    public function aCodeSpentEstablishesNothingAgain(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $code = $this->sender->last()->code;
        $establishment->confirm($this->alice, $code, Fixtures::context());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $code, Fixtures::context());
    }

    #[Test]
    public function aCodeTypedWhenNoneWasSentEstablishesNothing(): void
    {
        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $this->establishment(new ConfirmablePhoneNumber())->confirm($this->alice, '123456', Fixtures::context());
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aCodeTypedWhenNoneWasSentCostsAHash(): void
    {
        // When
        try {
            $this->establishment(new ConfirmablePhoneNumber())->confirm($this->alice, '123456', Fixtures::context());
        } catch (AddressConfirmationRefusedException) {
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aCodeIsCountedUnderTheLimitOfAGuess(): void
    {
        // Given
        $attempts = new FakeAttemptLimiter();
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), $attempts);
        $establishment->send($this->alice, Fixtures::context());

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $attempts->attempts);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aCodeTypedPastTheLimitOfAGuessEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), new FakeAttemptLimiter(allowed: 0));
        $establishment->send($this->alice, Fixtures::context());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aCodeTypedPastTheLimitOfAGuessCostsAHash(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), new FakeAttemptLimiter(allowed: 0));
        $establishment->send($this->alice, Fixtures::context());

        // When
        try {
            $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());
        } catch (AddressConfirmationRefusedException) {
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
    }

    /**
     * NIST SP 800-63B-4 §3.2.2
     */
    #[Test]
    public function aConfirmationWornOutByWrongCodesEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $code = $this->sender->last()->code;
        for ($failure = 0; $failure < AddressConfirmation::FAILURES; ++$failure) {
            try {
                $establishment->confirm($this->alice, self::anotherCode($code), Fixtures::context());
            } catch (AddressConfirmationRefusedException) {
            }
        }

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $code, Fixtures::context());
    }

    #[Test]
    public function aConfirmationOneWrongCodeShortOfWornOutStillEstablishesTheAddress(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $code = $this->sender->last()->code;
        for ($failure = 1; $failure < AddressConfirmation::FAILURES; ++$failure) {
            try {
                $establishment->confirm($this->alice, self::anotherCode($code), Fixtures::context());
            } catch (AddressConfirmationRefusedException) {
            }
        }

        // When
        $establishment->confirm($this->alice, $code, Fixtures::context());

        // Then
        static::assertNotNull($this->alice->verifiedPhoneNumber());
    }

    #[Test]
    public function aCodeOfAPersonWhoCannotSignInEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $this->alice->disable(Fixtures::now());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($this->alice, $this->sender->last()->code, Fixtures::context());
    }

    #[Test]
    public function aNumberItsSourceCameToHoldIsNotEstablished(): void
    {
        // Given
        $bob = self::upstreamUser([]);
        $bob->changePhoneNumber(self::PHONE_NUMBER, false, Fixtures::now());
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($bob, Fixtures::context());
        $bob->heldBy(UserSource::upstream('https://idp.acme.example', ['phone_number']), Fixtures::now());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirm($bob, $this->sender->last()->code, Fixtures::context());
    }

    #[Test]
    public function aLinkWithAnotherValueEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value . 'x', Fixtures::context());
    }

    #[Test]
    public function aLinkNoConfirmationCarriesEstablishesNothing(): void
    {
        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $this->establishment(new ConfirmablePhoneNumber())->confirmByLink($this->alice, Uuid::v7(), 'value', Fixtures::context());
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aLinkNoConfirmationCarriesCostsAHash(): void
    {
        // When
        try {
            $this->establishment(new ConfirmablePhoneNumber())->confirmByLink($this->alice, Uuid::v7(), 'value', Fixtures::context());
        } catch (AddressConfirmationRefusedException) {
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function aLinkSentToAnotherPersonEstablishesNothingForTheOneWhoFollowsIt(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $bob->changePhoneNumber(self::PHONE_NUMBER, false, Fixtures::now());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirmByLink($bob, $issued->confirmation->id, $issued->value, Fixtures::context());
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function aLinkSentToAnAddressThePersonChangedSinceEstablishesNothing(ConfirmableAddressInterface $kind, string $address): void
    {
        // Given
        $establishment = $this->establishment($kind);
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();
        $this->alice->changeEmail(new EmailAddress('alice@elsewhere.example'), false, Fixtures::now());
        $this->alice->changePhoneNumber('+33698765432', false, Fixtures::now());

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    #[DataProvider('provideLifetimes')]
    public function aLinkOutOfTimeEstablishesNothing(ConfirmableAddressInterface $kind, string $lifetime): void
    {
        // Given
        $establishment = $this->establishment($kind);
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();
        $this->clock->modify($lifetime);

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2, decision 0014
     */
    #[Test]
    public function aLinkIsCountedUnderTheLimitOfAGuess(): void
    {
        // Given
        $attempts = new FakeAttemptLimiter();
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), $attempts);
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());

        // Then
        static::assertSame([$this->alice->id->toRfc4122()], $attempts->attempts);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aLinkFollowedPastTheLimitOfAGuessEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber(), new FakeAttemptLimiter(allowed: 0));
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());
    }

    /**
     * NIST SP 800-63B-4 §3.2.2
     */
    #[Test]
    public function aConfirmationWornOutByWrongLinksEstablishesNothing(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();
        for ($failure = 0; $failure < AddressConfirmation::FAILURES; ++$failure) {
            try {
                $establishment->confirmByLink($this->alice, $issued->confirmation->id, 'another value', Fixtures::context());
            } catch (AddressConfirmationRefusedException) {
            }
        }

        // Then
        $this->expectException(AddressConfirmationRefusedException::class);
        $this->expectExceptionMessageIs(AddressConfirmationRedeeming::REFUSED);

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());
    }

    #[Test]
    public function wrongValuesForTheLinkOfAnotherPersonLeaveTheirConfirmationWhole(): void
    {
        // Given
        $establishment = $this->establishment(new ConfirmablePhoneNumber());
        $establishment->send($this->alice, Fixtures::context());
        $issued = $this->sender->last();
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $bob->changePhoneNumber(self::PHONE_NUMBER, false, Fixtures::now());
        for ($failure = 0; $failure < AddressConfirmation::FAILURES; ++$failure) {
            try {
                $establishment->confirmByLink($bob, $issued->confirmation->id, 'another value', Fixtures::context());
            } catch (AddressConfirmationRefusedException) {
            }
        }

        // When
        $establishment->confirmByLink($this->alice, $issued->confirmation->id, $issued->value, Fixtures::context());

        // Then
        static::assertNotNull($this->alice->verifiedPhoneNumber());
    }

    private function establishment(
        ConfirmableAddressInterface $kind,
        FakeAttemptLimiter $attempts = new FakeAttemptLimiter(),
        RandomnessInterface $randomness = new FixedRandomness(),
        FakeConfirmationSendLimiter $sends = new FakeConfirmationSendLimiter(),
    ): AddressEstablishment {
        $uuids = new SymfonyUuidGenerator();

        return new AddressEstablishment(
            $kind,
            $this->confirmations,
            $this->sender,
            $sends,
            new AddressConfirmationIssuing($uuids, $randomness, $this->hasher, $this->clock),
            new AddressConfirmationRedeeming($this->hasher, new DecoyHash($this->hasher, $uuids, new FakeMonotonicClock()), $attempts, $this->clock),
            $this->users,
            $this->history,
            new WritesAsTheyCome(),
            $this->clock,
            $this->events,
        );
    }

    private static function anotherCode(string $code): string
    {
        return $code === '000000' ? '000001' : '000000';
    }

    /**
     * @param list<string> $claims
     */
    private static function upstreamUser(array $claims): User
    {
        return User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('bob-subject'),
            'bob',
            Fixtures::now(),
            source: UserSource::upstream('https://idp.acme.example', $claims),
        );
    }
}
