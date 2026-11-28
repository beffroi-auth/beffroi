<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\ChangesChapter;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ChangesChapterTest extends TestCase
{
    #[Test]
    public function aChangeIsOnWhatChangedWhatItSaidWhenAndWhereThePersonMadeIt(): void
    {
        // Given
        $user = Fixtures::user();
        $history = new InMemoryClaimHistory();
        $history->record(self::change($user, new ThePerson()));

        // When
        $lines = new ChangesChapter($history)->of($user);

        // Then
        static::assertSame(
            ['nickname', 'Ada', 'Augusta', Fixtures::now()->format('c'), ArchivedFacts::context(Fixtures::context()), ['kind' => 'person']],
            [$lines[0]['claim'], $lines[0]['was'], $lines[0]['became'], $lines[0]['changed_at'], $lines[0]['from'], $lines[0]['author']],
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aChangeAnAdministratorMadeSaysSoAndNeitherWhoNorWhereFrom(): void
    {
        // Given
        $user = Fixtures::user();
        $history = new InMemoryClaimHistory();
        $history->record(self::change($user, new AnAdministrator(new Subject('administrator-subject'))));

        // When
        $lines = new ChangesChapter($history)->of($user);

        // Then
        static::assertSame([['kind' => 'administrator'], null], [$lines[0]['author'], $lines[0]['from']]);
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function aChangeADirectoryMadeNamesItAndWhereItCameFrom(): void
    {
        // Given
        $user = Fixtures::user();
        $history = new InMemoryClaimHistory();
        $history->record(self::change($user, new ADirectory('Entra ID')));

        // When
        $lines = new ChangesChapter($history)->of($user);

        // Then
        static::assertSame(
            [['kind' => 'directory', 'name' => 'Entra ID'], ArchivedFacts::context(Fixtures::context())],
            [$lines[0]['author'], $lines[0]['from']],
        );
    }

    #[Test]
    public function aHistoryLongerThanOnePageIsReadWhole(): void
    {
        // Given
        $user = Fixtures::user();
        $history = new InMemoryClaimHistory();
        $howMany = ChangesChapter::READ_AT_ONCE + 3;
        for ($made = 0; $made < $howMany; ++$made) {
            $history->record(self::change($user, new ThePerson()));
        }

        // When
        $lines = new ChangesChapter($history)->of($user);

        // Then
        static::assertCount($howMany, $lines);
    }

    private static function change(User $user, AuthorInterface $author): ClaimChange
    {
        return new ClaimChange(Uuid::v7(), $user, 'nickname', 'Ada', 'Augusta', Fixtures::now(), Fixtures::context(), $author);
    }
}
