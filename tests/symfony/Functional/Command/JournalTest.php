<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use function array_column;
use App\Command\UserJournalCommand;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use DateTimeImmutable;
use const JSON_THROW_ON_ERROR;
use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Uid\Uuid;

final class JournalTest extends ConsoleTestCase
{
    #[Test]
    public function everyActOfThePersonIsListedMostRecentFirst(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, UserAuthenticated::NAME, self::day('2026-10-02'));
        self::act($alice, 'tokens.issued', self::day('2026-10-03'), 'oidc-demo');

        // When
        $tester = self::journal('alice');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertMatchesRegularExpression('/tokens\.issued.+\n.+user\.authenticated/s', $tester->getDisplay());
    }

    #[Test]
    public function eachActSaysTheApplicationItWasDoneOnBehalfOf(): void
    {
        // Given
        self::act(self::user('alice'), 'tokens.issued', self::day('2026-10-03'), 'oidc-demo');

        // When
        $tester = self::journal('alice');

        // Then
        static::assertStringContainsString('oidc-demo', $tester->getDisplay());
    }

    #[Test]
    public function theActsOfAnotherPersonAreNotRead(): void
    {
        // Given
        self::act(self::user('bob', 'bob-subject'), 'tokens.issued', self::day('2026-10-03'), 'oidc-demo');
        self::user('alice');

        // When
        $tester = self::journal('alice');

        // Then
        static::assertStringContainsString('holds no act', $tester->getDisplay());
    }

    #[Test]
    public function thePeriodNarrowsTheReadingToTheDaysItNames(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'tokens.issued', self::day('2026-10-02'));
        self::act($alice, 'consent.granted', self::day('2026-10-05'));

        // When
        $tester = self::journal('alice', [
            '--from' => '2026-10-04',
            '--to' => '2026-10-05',
        ]);

        // Then
        static::assertStringContainsString('consent.granted', $tester->getDisplay());
        static::assertStringNotContainsString('tokens.issued', $tester->getDisplay());
    }

    #[Test]
    public function theLastDayOfThePeriodIsHeldWhole(): void
    {
        // Given
        self::act(self::user('alice'), 'tokens.issued', new DateTimeImmutable('2026-10-05 23:59:58'));

        // When
        $tester = self::journal('alice', [
            '--to' => '2026-10-05',
        ]);

        // Then
        static::assertStringContainsString('tokens.issued', $tester->getDisplay());
    }

    #[Test]
    public function oneActNamedIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'tokens.issued', self::day('2026-10-02'));
        self::act($alice, 'consent.granted', self::day('2026-10-03'));

        // When
        $tester = self::journal('alice', [
            '--act' => ['consent.granted'],
        ]);

        // Then
        static::assertStringContainsString('consent.granted', $tester->getDisplay());
        static::assertStringNotContainsString('tokens.issued', $tester->getDisplay());
    }

    #[Test]
    public function oneApplicationNamedIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'tokens.issued', self::day('2026-10-02'), 'oidc-demo');
        self::act($alice, 'tokens.issued', self::day('2026-10-03'), 'native-app');

        // When
        $tester = self::journal('alice', [
            '--client' => 'native-app',
        ]);

        // Then
        static::assertStringContainsString('native-app', $tester->getDisplay());
        static::assertStringNotContainsString('oidc-demo', $tester->getDisplay());
    }

    #[Test]
    public function aPeriodTheRetentionCannotCoverIsNamedAsSuch(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::journal('alice', [
            '--from' => '2020-01-01',
        ]);

        // Then
        static::assertStringContainsString('keeps an act 180 day(s)', self::flattened($tester));
        static::assertStringContainsString('nothing that happened before', self::flattened($tester));
    }

    #[Test]
    public function aPeriodTheRetentionCoversIsSaidToBeInsideIt(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::journal('alice', [
            '--from' => self::currentSecond()->format('Y-m-d'),
        ]);

        // Then
        static::assertStringContainsString('the whole of that period is inside it', self::flattened($tester));
    }

    #[Test]
    public function theJsonFormatIsADocumentARequestCanBeAnsweredWith(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'tokens.issued', self::day('2026-10-03'), 'oidc-demo');

        // When
        $document = self::document(self::journal('alice', [
            '--format' => UserJournalCommand::JSON,
        ]));

        // Then
        static::assertSame('alice', $document['username']);
        static::assertSame('alice-subject', $document['sub']);
        static::assertSame(180, self::member($document, 'kept')['days']);
        static::assertSame(['tokens.issued'], array_column(self::acts($document), 'act'));
        static::assertSame(['oidc-demo'], array_column(self::acts($document), 'client'));
        static::assertSame(self::day('2026-10-03')->format('Y-m-d\TH:i:sP'), self::acts($document)[0]['occurred_at']);
    }

    /**
     * Decision 0038: the operator of the instance reads which administrator did an act to the person.
     */
    #[Test]
    public function theJsonFormatNamesTheAdministratorWhoDidAnAct(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'administration.person_read', self::day('2026-10-03'), 'tui-of-mallory', new AnAdministrator(new Subject('mallory-subject')));

        // When
        $document = self::document(self::journal('alice', [
            '--format' => UserJournalCommand::JSON,
        ]));

        // Then
        static::assertSame([['kind' => 'administrator', 'subject' => 'mallory-subject']], array_column(self::acts($document), 'author'));
    }

    #[Test]
    public function theJsonFormatHoldsAValueAsItWasWritten(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'tokens.issued', self::day('2026-10-03'), '<fg=red>oidc-demo</>');

        // When
        $document = self::document(self::journal('alice', [
            '--format' => UserJournalCommand::JSON,
        ]));

        // Then
        static::assertSame(['<fg=red>oidc-demo</>'], array_column(self::acts($document), 'client'));
    }

    #[Test]
    public function theTableNamesTheAdministratorWhoDidAnAct(): void
    {
        // Given
        $alice = self::user('alice');
        self::act($alice, 'administration.person_read', self::day('2026-10-03'), 'tui-of-mallory', new AnAdministrator(new Subject('mallory-subject')));

        // When
        $tester = self::journal('alice');

        // Then
        static::assertStringContainsString('mallory-subject', $tester->getDisplay());
    }

    #[Test]
    public function aFormatThatIsNeitherIsRefused(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::journal('alice', [
            '--format' => 'csv',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('neither "table" nor "json"', self::flattened($tester));
    }

    #[Test]
    public function aDayThatIsNotADayIsRefused(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::journal('alice', [
            '--from' => 'last monday',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('takes a day as YYYY-MM-DD', self::flattened($tester));
    }

    #[Test]
    public function aPeriodThatEndsBeforeItStartsIsRefused(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::journal('alice', [
            '--from' => '2026-10-05',
            '--to' => '2026-10-02',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('ends before it starts', self::flattened($tester));
    }

    #[Test]
    public function aUserNobodyAnswersToIsRefused(): void
    {
        // When
        $tester = self::journal('nobody');

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('There is no user named "nobody"', self::flattened($tester));
    }

    /**
     * @param array<string, string|list<string>> $options
     */
    private static function journal(string $username, array $options = []): CommandTester
    {
        return self::console(UserJournalCommand::NAME, [
            'username' => $username,
            ...$options,
        ]);
    }

    private static function act(User $user, string $name, DateTimeImmutable $occurredAt, ?string $client = null, ?AuthorInterface $author = null): void
    {
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(new JournalEntry(Uuid::v7(), $user->tenant, $name, $occurredAt, self::context(), $user->subject, $client, $author));
        self::reload();
    }

    private static function day(string $day): DateTimeImmutable
    {
        return new DateTimeImmutable($day . ' 12:00:00');
    }

    /**
     * @return array<string, mixed>
     */
    private static function document(CommandTester $tester): array
    {
        $document = json_decode($tester->getDisplay(true), true, 16, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return array<string, mixed>
     */
    private static function member(array $document, string $name): array
    {
        $member = $document[$name] ?? null;
        static::assertIsArray($member);

        /** @var array<string, mixed> $member */
        return $member;
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return list<array<string, mixed>>
     */
    private static function acts(array $document): array
    {
        $acts = $document['acts'] ?? null;
        static::assertIsArray($acts);

        /** @var list<array<string, mixed>> $acts */
        return $acts;
    }
}
