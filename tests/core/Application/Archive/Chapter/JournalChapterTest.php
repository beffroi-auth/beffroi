<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\JournalChapter;
use Beffroi\Core\Tests\Fixture\RecordedActs;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function array_column;
use function array_fill;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class JournalChapterTest extends TestCase
{
    #[Test]
    public function anActIsOnItsNameItsMomentAndWhatTheRequestCarried(): void
    {
        // Given
        $user = Fixtures::user();
        $journal = new RecordedActs();
        $journal->record(
            new JournalEntry(Uuid::v7(), $user->tenant, UserAuthenticated::NAME, Fixtures::now(), Fixtures::context(), $user->subject, 'oidc-demo'),
        );

        // When
        $lines = new JournalChapter($journal, [])->of($user);

        // Then
        static::assertSame(UserAuthenticated::NAME, $lines[0]['act']);
        static::assertSame(Fixtures::now()->format('c'), $lines[0]['occurred_at']);
        static::assertSame('oidc-demo', $lines[0]['client']);
        $from = $lines[0]['from'];
        static::assertIsArray($from);
        static::assertSame(Fixtures::context()->ipAddress, $from['ip_address']);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theClientAnActIsAboutStaysInTheChapterWhenAnAdministratorDidIt(): void
    {
        // Given
        $user = Fixtures::user();
        $journal = new RecordedActs();
        $journal->record(new JournalEntry(
            Uuid::v7(),
            $user->tenant,
            'session_tokens.revoked',
            Fixtures::now(),
            Fixtures::context(),
            $user->subject,
            'oidc-demo',
            new AnAdministrator(new Subject('administrator-subject')),
        ));

        // When
        $lines = new JournalChapter($journal, ['session_tokens.revoked'])->of($user);

        // Then
        static::assertSame('oidc-demo', $lines[0]['client']);
    }

    #[Test]
    public function everyActOfThePersonIsInTheChapterWhateverItIsCalled(): void
    {
        // Given
        $user = Fixtures::user();
        $journal = new RecordedActs();
        self::acts($journal, $user, [UserAuthenticated::NAME, AuthenticationFailed::NAME, 'archive.asked']);

        // When
        $lines = new JournalChapter($journal, [])->of($user);

        // Then
        static::assertCount(3, $lines);
    }

    #[Test]
    public function aJournalLongerThanOnePageIsReadWhole(): void
    {
        // Given
        $user = Fixtures::user();
        $journal = new RecordedActs();
        $howMany = JournalChapter::READ_AT_ONCE + 7;
        self::acts($journal, $user, array_fill(0, $howMany, UserAuthenticated::NAME));

        // When
        $lines = new JournalChapter($journal, [])->of($user);

        // Then
        static::assertCount($howMany, $lines);
    }

    #[Test]
    public function theActsAreOldestFirst(): void
    {
        // Given
        $user = Fixtures::user();
        $journal = new RecordedActs();
        self::acts($journal, $user, ['first.act', 'second.act', 'third.act']);

        // When
        $lines = new JournalChapter($journal, [])->of($user);

        // Then
        static::assertSame(['first.act', 'second.act', 'third.act'], array_column($lines, 'act'));
    }

    #[Test]
    public function theJournalOfAnotherPersonIsNotInTheChapter(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $ada = Fixtures::user($tenant, 'ada', 'ada-subject');
        $grace = Fixtures::user($tenant, 'grace', 'grace-subject');
        $journal = new RecordedActs();
        self::acts($journal, $grace, [UserAuthenticated::NAME]);

        // When / Then
        static::assertSame([], new JournalChapter($journal, [])->of($ada));
    }

    /**
     * @param list<string> $names
     */
    private static function acts(RecordedActs $journal, User $user, array $names): void
    {
        $at = Fixtures::now();
        foreach ($names as $name) {
            $journal->record(new JournalEntry(Uuid::v7(), $user->tenant, $name, $at, Fixtures::context(), $user->subject));
        }
    }
}
