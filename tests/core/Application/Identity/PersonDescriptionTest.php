<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use function implode;
use function array_map;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Application\Identity\Member\AddressMember;
use Beffroi\Core\Application\Identity\Member\EmailMember;
use Beffroi\Core\Application\Identity\Member\EmailVerifiedMember;
use Beffroi\Core\Application\Identity\Member\PhoneNumberVerifiedMember;
use Beffroi\Core\Application\Identity\Member\UsernameMember;
use Beffroi\Core\Application\Identity\PersonDescription;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Event\PersonDescribed;
use Beffroi\Core\Domain\Identity\Claim\Birthdate;
use Beffroi\Core\Domain\Identity\Claim\GivenName;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PhoneNumber;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\FakeChannelChangeWindow;
use Beffroi\Core\Tests\Fixture\FixedClaims;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sort;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038
 */
final class PersonDescriptionTest extends TestCase
{
    private const string ADMINISTRATOR = 'administrator-subject';

    private const string WRITTEN_BY_THE_ADMINISTRATOR = 'administrator administrator-subject';

    private InMemoryUserRepository $users;

    private InMemoryClaimHistory $history;

    private RecordingEventDispatcher $events;

    private WritesAsTheyCome $writes;

    private RecordingCredentialChangeNotifier $notifier;

    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->history = new InMemoryClaimHistory();
        $this->events = new RecordingEventDispatcher();
        $this->writes = new WritesAsTheyCome();
        $this->notifier = new RecordingCredentialChangeNotifier();
    }

    #[Test]
    public function anAdministratorChangesAClaimOfAPerson(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $this->describe($alice, ['nickname' => 'Ada']);

        // Then
        static::assertSame('Ada', $alice->profile->nickname);
    }

    #[Test]
    public function eachValueThatChangedIsARowOfTheHistoryThatNamesTheAdministrator(): void
    {
        // Given
        $alice = $this->alice();
        $alice->updateProfile(new Profile(nickname: 'Alice'), Fixtures::now());

        // When
        $this->describe($alice, ['nickname' => 'Ada', 'given_name' => 'Ada']);

        // Then
        static::assertSame(
            [['given_name', null, 'Ada', self::WRITTEN_BY_THE_ADMINISTRATOR], ['nickname', 'Alice', 'Ada', self::WRITTEN_BY_THE_ADMINISTRATOR]],
            $this->rows($alice),
        );
    }

    #[Test]
    public function theRowsAndTheRecordAreWrittenInOneUnit(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $this->describe($alice, ['nickname' => 'Ada', 'username' => 'ada']);

        // Then
        static::assertSame(1, $this->writes->units);
    }

    #[Test]
    public function theDescriptionIsOneActThatNamesTheAdministratorAndWhatChanged(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $this->describe($alice, ['username' => 'ada', 'nickname' => 'Ada']);

        // Then
        $acts = $this->events->of(PersonDescribed::class);
        static::assertCount(1, $acts);
        static::assertEquals(
            ['alice-subject', ['nickname', 'username'], new AnAdministrator(new Subject(self::ADMINISTRATOR))],
            [$acts[0]->subject()->value, $acts[0]->changed, $acts[0]->author()],
        );
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function aDirectoryThatDescribesIsNamedByEachChangeAndByTheAct(): void
    {
        // Given
        $alice = $this->alice();
        $directory = new ADirectory('Entra ID');

        // When
        $this->describe($alice, ['given_name' => 'Ada'], $directory);

        // Then
        static::assertSame(
            [[['given_name', null, 'Ada', 'directory Entra ID']], [$directory]],
            [$this->rows($alice), array_map(static fn (PersonDescribed $act): AuthorInterface => $act->author(), $this->events->of(PersonDescribed::class))],
        );
    }

    #[Test]
    public function theDescriptionAnswersTheNamesOfWhatChanged(): void
    {
        // Given
        $alice = $this->alice();
        $alice->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());

        // When
        $changed = $this->describe($alice, ['nickname' => 'Ada', 'given_name' => 'Ada']);

        // Then
        static::assertSame(['given_name'], $changed);
    }

    #[Test]
    public function aDescriptionThatChangesNothingAnswersNothing(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $changed = $this->describe($alice, ['username' => 'alice']);

        // Then
        static::assertSame([], $changed);
    }

    #[Test]
    public function aValueSaidAsItIsWritesNoRowAndAnnouncesNoAct(): void
    {
        // Given
        $alice = $this->alice();
        $alice->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());

        // When
        $this->describe($alice, ['nickname' => 'Ada', 'username' => 'alice']);

        // Then
        static::assertSame([[], []], [$this->rows($alice), $this->events->events]);
    }

    #[Test]
    public function whatNoAdministratorSaysOfAPersonIsRefused(): void
    {
        // Given
        $alice = $this->alice();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An administrator says no "shoe_size" of a person.');

        // When
        $this->describe($alice, ['shoe_size' => '38']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function heldBySource(): iterable
    {
        yield 'a claim it holds' => [['nickname' => 'Ada'], 'nickname'];
        yield 'the email address' => [['email' => 'ada@acme.example'], 'email'];
        yield 'whether the email address was verified' => [['email_verified' => false], 'email'];
        yield 'the username, which is the email address' => [['username' => 'ada'], 'email'];
    }

    /**
     * Decision 0002
     *
     * @param array<string, mixed> $said
     */
    #[Test]
    #[DataProvider('heldBySource')]
    public function whatTheUpstreamSourceOfThePersonHoldsStaysItsOwn(array $said, string $held): void
    {
        // Given
        $alice = $this->aliceOfTheWorkforce();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The upstream provider "workforce" created this person and holds "%s": a manual description does not change what its source holds.',
            $held,
        ));

        // When
        $this->describe($alice, $said);
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function whatTheSourceHoldsSaidAsItIsChangesNothingAndIsNotRefused(): void
    {
        // Given
        $alice = $this->aliceOfTheWorkforce();

        // When
        $this->describe($alice, ['username' => 'alice@acme.example', 'email' => 'alice@acme.example', 'email_verified' => true]);

        // Then
        static::assertSame([[], []], [$this->rows($alice), $this->events->events]);
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function aChangeTheSourceRefusesWritesNoRowAndAnnouncesNoAct(): void
    {
        // Given
        $alice = $this->aliceOfTheWorkforce();

        // When
        try {
            $this->describe($alice, ['given_name' => 'Ada', 'nickname' => 'Ada']);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame([[], []], [$this->rows($alice), $this->events->events]);
    }

    #[Test]
    public function aValueRefusedWritesNoRowAndAnnouncesNoAct(): void
    {
        // Given
        $alice = $this->alice();

        // When
        try {
            $this->describe($alice, ['nickname' => 'Ada', 'birthdate' => 'the first of May']);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame([[], []], [$this->rows($alice), $this->events->events]);
    }

    #[Test]
    public function aNewEmailAddressIsUnverifiedUntilTheAdministratorSaysItWasVerified(): void
    {
        // Given
        $alice = $this->alice();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        $this->describe($alice, ['email' => 'ada@acme.example']);

        // Then
        static::assertSame(['ada@acme.example', false], [$alice->email?->value, $alice->emailVerified]);
    }

    #[Test]
    public function theVerificationAnAddressLosesIsARowOfTheHistoryToo(): void
    {
        // Given
        $alice = $this->alice();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        $this->describe($alice, ['email' => 'ada@acme.example']);

        // Then
        static::assertSame(
            [
                ['email', 'alice@acme.example', 'ada@acme.example', self::WRITTEN_BY_THE_ADMINISTRATOR],
                ['email_verified', 'true', 'false', self::WRITTEN_BY_THE_ADMINISTRATOR],
            ],
            $this->rows($alice),
        );
    }

    #[Test]
    public function anAddressIsWrittenBeforeWhetherItWasVerified(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $this->describe($alice, ['email_verified' => true, 'email' => 'ada@acme.example']);

        // Then
        static::assertSame(['ada@acme.example', true], [$alice->email?->value, $alice->emailVerified]);
    }

    #[Test]
    public function aPhoneNumberIsWrittenBeforeWhetherItWasVerified(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $this->describe($alice, ['phone_number_verified' => true, 'phone_number' => '+33 1 23 45 67 89']);

        // Then
        static::assertSame(['+33 1 23 45 67 89', true], [$alice->phoneNumber, $alice->phoneNumberVerified]);
    }

    #[Test]
    public function anAbsentEmailAddressIsNotVerified(): void
    {
        // Given
        $alice = $this->alice();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An absent email address cannot be verified.');

        // When
        $this->describe($alice, ['email_verified' => true]);
    }

    #[Test]
    public function aUsernameAnotherPersonOfTheTenantHasIsRefused(): void
    {
        // Given
        $alice = $this->alice();
        $this->users->save(Fixtures::user($alice->tenant, 'bob', 'bob-subject'));

        // Then
        $this->expectException(UserAlreadyExistsException::class);

        // When
        $this->describe($alice, ['username' => 'bob']);
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function anAddressAnAdministratorChangesIsToldToTheOneItReplaced(): void
    {
        // Given
        $alice = $this->alice();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        $this->describe($alice, ['email' => 'alice@elsewhere.example', 'email_verified' => true]);

        // Then
        static::assertSame(
            [[ChannelChangeNotice::ACT, 'email', 'alice@acme.example']],
            array_map(static fn (CredentialChange $change): array => [$change->act, $change->kind, $change->replaced?->value], $this->notifier->told),
        );
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function anAdministratorChangingTheAddressAndTheNumberTellsEachChange(): void
    {
        // Given
        $alice = $this->alice();

        // When
        $this->describe($alice, ['email' => 'alice@acme.example', 'phone_number' => '+44 1865 000000']);

        // Then
        static::assertSame(
            [
                [ChannelChangeNotice::ACT, 'email'],
                [ChannelChangeNotice::ACT, 'phone_number'],
            ],
            $this->notifier->acts(),
        );
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aDescriptionRefusedTellsNothing(): void
    {
        // Given
        $alice = $this->aliceOfTheWorkforce();

        // When
        try {
            $this->describe($alice, ['email' => 'alice@elsewhere.example']);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame([], $this->notifier->told);
    }

    /**
     * A person the upstream provider "workforce" created, which holds her email address and her nickname.
     */
    private function aliceOfTheWorkforce(): User
    {
        $alice = User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice@acme.example',
            Fixtures::now(),
            new EmailAddress('alice@acme.example'),
            true,
            UserSource::upstream('workforce', ['email', 'nickname']),
        );
        $this->users->save($alice);

        return $alice;
    }

    private function alice(): User
    {
        $alice = Fixtures::user();
        $this->users->save($alice);

        return $alice;
    }

    /**
     * @param array<string, mixed> $said
     *
     * @return list<string>
     */
    private function describe(User $user, array $said, AuthorInterface $author = new AnAdministrator(new Subject(self::ADMINISTRATOR))): array
    {
        return new PersonDescription(
            new FixedClaims([new Nickname(), new GivenName(), new Birthdate(), new PhoneNumber()]),
            [new UsernameMember($this->users), new EmailMember(), new EmailVerifiedMember(), new PhoneNumberVerifiedMember(), new AddressMember()],
            $this->users,
            $this->history,
            $this->writes,
            $this->events,
            new MockClock(Fixtures::now()),
            new ChannelChangeNotice(new FakeChannelChangeWindow(), $this->notifier),
        )->describe($user, $said, $author, Fixtures::context());
    }

    /**
     * @return list<array{string, string|null, string|null, string}> each row of the history of the person, by the name of what changed and its author as written
     */
    private function rows(User $user): array
    {
        $rows = array_map(
            static fn (ClaimChange $change): array => [$change->claim, $change->was, $change->became, implode(' ', $change->author->toDocument())],
            $this->history->lastOf($user, 50),
        );
        sort($rows);

        return $rows;
    }
}
