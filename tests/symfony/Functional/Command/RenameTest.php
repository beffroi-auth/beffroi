<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserReindexCommand;
use App\Command\UserRenameCommand;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use function array_map;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Event\PersonDescribed;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

final class RenameTest extends ConsoleTestCase
{
    #[Test]
    public function aPersonIsRenamedByTheirIdentifier(): void
    {
        // Given
        $alice = self::user('alice', 'alice-subject');

        // When
        self::console(UserRenameCommand::NAME, [
            'user' => $alice->id->toRfc4122(),
            'username' => 'alice.martin',
        ]);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'alice.martin')?->id->equals($alice->id));
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function theRenameIsALineOfTheHistoryOfThePersonThatNamesTheHost(): void
    {
        // Given
        $alice = self::user('alice', 'alice-subject');

        // When
        self::console(UserRenameCommand::NAME, [
            'user' => 'alice',
            'username' => 'alice.martin',
        ]);

        // Then
        static::assertEquals(
            [['username', 'alice', 'alice.martin', new TheHost()]],
            array_map(
                static fn (ClaimChange $change): array => [$change->claim, $change->was, $change->became, $change->author],
                self::service('test.beffroi.changes', ChangesOfAPersonInterface::class)->lastOf(self::personAgain($alice), 10),
            ),
        );
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function theRenameIsAnActOfThePersonThatNamesTheHost(): void
    {
        // Given
        self::user('alice', 'alice-subject');

        // When
        self::console(UserRenameCommand::NAME, [
            'user' => 'alice',
            'username' => 'alice.martin',
        ]);

        // Then
        static::assertEquals(
            [new TheHost()],
            array_map(static fn (PersonDescribed $act): AuthorInterface => $act->author(), self::events(PersonDescribed::class)),
        );
    }

    /**
     * RFC 8265 §3.3.4: the way out of a pair the reindex set aside, whom no username finds.
     */
    #[Test]
    public function aPersonOfAPairTheReindexSetAsideIsFoundUnderTheUsernameTheyAreGiven(): void
    {
        // Given
        self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');
        self::console(UserReindexCommand::NAME);

        // When
        self::console(UserRenameCommand::NAME, [
            'user' => $other->id->toRfc4122(),
            'username' => 'alice.martin',
        ]);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'Alice.Martin')?->id->equals($other->id));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function aUsernameAnotherPersonComparesAsIsRefused(): void
    {
        // Given
        self::user('alice', 'alice-subject');
        $bob = self::user('bob', 'bob-subject');

        // When
        $tester = self::console(UserRenameCommand::NAME, [
            'user' => $bob->id->toRfc4122(),
            'username' => 'ALICE',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user named "ALICE" already exists', self::flattened($tester));
    }

    /**
     * RFC 8265 §3.3.4, RFC 7644 §5
     */
    #[Test]
    public function nobodyIsRenamedIntoTheUsernameAPairTheReindexSetAsideShares(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        self::personOf01('alice', 'alice');
        self::personOf01('Alice', 'other-alice');
        self::console(UserReindexCommand::NAME);

        // When
        $tester = self::console(UserRenameCommand::NAME, [
            'user' => $bob->id->toRfc4122(),
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user named "alice" already exists', self::flattened($tester));
    }

    /**
     * RFC 8265 §3.3.4, RFC 7644 §5
     */
    #[Test]
    public function aPersonOfAPairIsNotRenamedIntoTheUsernameThePairShares(): void
    {
        // Given
        self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');
        self::console(UserReindexCommand::NAME);

        // When
        $tester = self::console(UserRenameCommand::NAME, [
            'user' => $other->id->toRfc4122(),
            'username' => 'ALICE',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user named "ALICE" already exists', self::flattened($tester));
    }

    /**
     * RFC 8265 §3.3, RFC 8264 §4.2.3
     */
    #[Test]
    public function aUsernameTheProfileRefusesIsRefused(): void
    {
        // Given
        self::user('alice', 'alice-subject');

        // When
        $tester = self::console(UserRenameCommand::NAME, [
            'user' => 'alice',
            'username' => 'alice smith',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('U+0020 is none of them', self::flattened($tester));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function noPersonIsRenamedWhileTheUsernamesOfTheTenantAreNotAllComparedByTheirForm(): void
    {
        // Given
        self::user('alice', 'alice-subject');
        self::entityManager()
            ->getConnection()
            ->executeStatement('DELETE FROM ' . BlindIndexDerivations::TABLE);

        // When
        $tester = self::console(UserRenameCommand::NAME, [
            'user' => 'alice',
            'username' => 'alice.martin',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('No person is created or renamed in the tenant', self::flattened($tester));
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
