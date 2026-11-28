<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use function array_map;
use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Event\PersonDescribedThemselves;
use Beffroi\Core\Domain\Identity\Claim\Birthdate;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PhoneNumber;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\FakeChannelChangeWindow;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class SelfDescriptionTest extends TestCase
{
    #[Test]
    public function aPersonSaysWhatTheTenantOpens(): void
    {
        // Given
        $user = self::user(['nickname']);

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertSame('Ada', $user->profile->nickname);
    }

    #[Test]
    public function theDescriptionAndItsHistoryLineAreWrittenInOneUnit(): void
    {
        // Given
        $writes = new WritesAsTheyCome();

        // When
        self::describing(writes: $writes)->describe(self::user(['nickname']), new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertSame(1, $writes->units);
    }

    #[Test]
    public function anEmptyValueTakesBackWhatTheyHadSaid(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());

        // When
        self::describing()->describe($user, new Nickname(), null, Fixtures::context());

        // Then
        static::assertNull($user->profile->nickname);
    }

    #[Test]
    public function aClaimTheTenantDoesNotOpenIsRefused(): void
    {
        // Given
        $user = self::user(['zoneinfo']);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This tenant does not let a person change "nickname" of themselves.');

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function aClaimTheSourceOfThePersonHoldsIsNotTheirsToSay(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $tenant->adoptSelfServedClaims(new SelfServedClaims(['nickname']));
        $user = User::create(
            Uuid::v7(),
            $tenant,
            new Subject('alice-subject'),
            'alice',
            Fixtures::now(),
            source: UserSource::upstream('workforce', ['nickname']),
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The upstream provider "workforce" created this person and holds "nickname": a manual description does not change what its source holds.');

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());
    }

    #[Test]
    public function aClaimRefusedForItsSourceWritesNothingAndAnnouncesNothing(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $tenant->adoptSelfServedClaims(new SelfServedClaims(['nickname']));
        $user = User::create(
            Uuid::v7(),
            $tenant,
            new Subject('alice-subject'),
            'alice',
            Fixtures::now(),
            source: UserSource::upstream('workforce', ['nickname']),
        );
        $user->updateProfile(new Profile(nickname: 'Alice'), Fixtures::now());
        $events = new RecordingEventDispatcher();
        $history = new InMemoryClaimHistory();

        // When
        try {
            self::describing($events, $history)->describe($user, new Nickname(), 'Ada', Fixtures::context());
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame('Alice', $user->profile->nickname);
        static::assertSame([], $history->lastOf($user, 10));
        static::assertSame([], $events->of(PersonDescribedThemselves::class));
    }

    #[Test]
    public function aTenantThatOpensNothingRefusesEverything(): void
    {
        // Given
        $user = self::user([]);

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());
    }

    #[Test]
    public function aValueTheClaimDoesNotHoldIsRefused(): void
    {
        // Given
        $user = self::user(['birthdate']);

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        self::describing()->describe($user, new Birthdate(), 'the first of May', Fixtures::context());
    }

    #[Test]
    public function sayingATelephoneNumberTakesItsVerificationBack(): void
    {
        // Given
        $user = self::user(['phone_number']);
        $user->changePhoneNumber('+44 1865 000000', true, Fixtures::now());

        // When
        self::describing()->describe($user, new PhoneNumber(), '+33 1 23 45 67 89', Fixtures::context());

        // Then
        static::assertSame('+33 1 23 45 67 89', $user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
    }

    #[Test]
    public function theActIsAnnouncedAndTheValueIsNot(): void
    {
        // Given
        $user = self::user(['nickname']);
        $events = new RecordingEventDispatcher();

        // When
        self::describing($events)->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        $announced = $events->of(PersonDescribedThemselves::class);
        static::assertCount(1, $announced);
        static::assertSame('nickname', $announced[0]->claim);
        static::assertFalse($announced[0]->takenBack);
    }

    #[Test]
    public function whatTheClaimUsedToSayIsWrittenDownWithWhatItSaysNow(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), 'Augusta', Fixtures::context());

        // Then
        $changes = $history->lastOf($user, 10);
        static::assertCount(1, $changes);
        static::assertSame('nickname', $changes[0]->claim);
        static::assertSame('Ada', $changes[0]->was);
        static::assertSame('Augusta', $changes[0]->became);
    }

    #[Test]
    public function aClaimFilledInForTheFirstTimeIsAChangeFromNothing(): void
    {
        // Given
        $user = self::user(['nickname']);
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertNull($history->lastOf($user, 10)[0]->was);
    }

    #[Test]
    public function takingAValueBackIsAChangeToNothing(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), null, Fixtures::context());

        // Then
        static::assertNull($history->lastOf($user, 10)[0]->became);
    }

    #[Test]
    public function sayingAgainWhatAClaimAlreadySaidIsNoChange(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertSame([], $history->lastOf($user, 10));
    }

    #[Test]
    public function theTelephoneNumberIsInTheHistoryToo(): void
    {
        // Given
        $user = self::user(['phone_number']);
        $user->changePhoneNumber('+44 1865 000000', true, Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new PhoneNumber(), '+33 1 23 45 67 89', Fixtures::context());

        // Then
        $changes = $history->lastOf($user, 10);
        static::assertSame('+44 1865 000000', $changes[0]->was);
        static::assertSame('+33 1 23 45 67 89', $changes[0]->became);
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function aNumberThePersonChangesIsToldToTheOneItReplaced(): void
    {
        // Given
        $user = self::user(['phone_number']);
        $user->changePhoneNumber('+44 1865 000000', true, Fixtures::now());
        $notifier = new RecordingCredentialChangeNotifier();

        // When
        self::describing(notifier: $notifier)->describe($user, new PhoneNumber(), '+33 1 23 45 67 89', Fixtures::context());

        // Then
        static::assertSame(
            [[ChannelChangeNotice::ACT, 'phone_number', '+44 1865 000000']],
            array_map(static fn (CredentialChange $change): array => [$change->act, $change->kind, $change->replaced?->value], $notifier->told),
        );
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aClaimThatIsNoChannelTellsNothing(): void
    {
        // Given
        $notifier = new RecordingCredentialChangeNotifier();

        // When
        self::describing(notifier: $notifier)->describe(self::user(['nickname']), new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertSame([], $notifier->told);
    }

    private static function describing(
        ?RecordingEventDispatcher $events = null,
        ?InMemoryClaimHistory $history = null,
        ?WritesAsTheyCome $writes = null,
        ?RecordingCredentialChangeNotifier $notifier = null,
    ): SelfDescription {
        return new SelfDescription(
            new InMemoryUserRepository(),
            $history ?? new InMemoryClaimHistory(),
            $writes ?? new WritesAsTheyCome(),
            $events ?? new RecordingEventDispatcher(),
            new MockClock(Fixtures::now()),
            new ChannelChangeNotice(new FakeChannelChangeWindow(), $notifier ?? new RecordingCredentialChangeNotifier()),
        );
    }

    /**
     * @param list<string> $opened
     */
    private static function user(array $opened): User
    {
        $tenant = Fixtures::tenant();
        $tenant->adoptSelfServedClaims(new SelfServedClaims($opened));

        return Fixtures::user($tenant);
    }
}
