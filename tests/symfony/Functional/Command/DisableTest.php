<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserDisableCommand;
use function array_map;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Event\PersonDisabled;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function str_contains;
use Symfony\Component\Console\Command\Command;

/**
 * Decision 0038: the operator of the instance disables a person from the console, the recourse when the provider no
 * longer answers.
 */
final class DisableTest extends ConsoleTestCase
{
    #[Test]
    public function thePersonIsDisabledAndTheActNamesTheHost(): void
    {
        // Given
        $alice = self::user('alice');

        // When
        $tester = self::console(UserDisableCommand::NAME, ['username' => 'alice']);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertEquals(
            [false, [new TheHost()]],
            [
                self::personAgain($alice)->isEnabled(),
                array_map(static fn (PersonDisabled $act): AuthorInterface => $act->author(), self::events(PersonDisabled::class)),
            ],
        );
    }

    #[Test]
    public function everySessionOfThePersonEnds(): void
    {
        // Given
        $session = self::session(self::user('alice'), self::currentSecond());

        // When
        $tester = self::console(UserDisableCommand::NAME, ['username' => 'alice']);

        // Then
        static::assertSame([true, true], [self::sessionAgain($session)->hasEnded(), str_contains(self::flattened($tester), '1 session(s) of theirs ended')]);
    }

    #[Test]
    public function aPersonDisabledAlreadyIsLeftAsTheyAre(): void
    {
        // Given
        self::user('alice');
        self::console(UserDisableCommand::NAME, ['username' => 'alice']);

        // When
        $tester = self::console(UserDisableCommand::NAME, ['username' => 'alice']);

        // Then
        static::assertSame(
            [Command::SUCCESS, true, 1],
            [$tester->getStatusCode(), str_contains(self::flattened($tester), 'was disabled already'), count(self::events(PersonDisabled::class))],
        );
    }
}
