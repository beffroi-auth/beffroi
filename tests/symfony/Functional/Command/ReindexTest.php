<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserReindexCommand;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Console\Command\Command;

final class ReindexTest extends ConsoleTestCase
{
    #[Test]
    public function aPersonWhoseTagWasDerivedUnderAnotherProjectionIsFoundAgain(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $bob->changeEmail(new EmailAddress('Bob@acme.example'), false, self::now());
        self::users()->save($bob);
        self::entityManager()->getConnection()->executeStatement("UPDATE beffroi_user SET email_index = 'derived-under-another-projection'");
        self::reload();

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertCount(1, self::users()->findAllByEmail(self::tenant(), new EmailAddress('bob@acme.example')));
    }

    #[Test]
    public function itSaysHowManyPersonsItWalked(): void
    {
        // Given
        self::user('alice', 'alice-subject');
        self::user('bob', 'bob-subject');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertStringContainsString(
            sprintf('The blind indexes of 2 person(s) of the tenant "%s" were derived again.', self::tenant()->slug),
            self::flattened($tester),
        );
    }

    /**
     * RFC 8265 §3.3.4: the upgrade of a tag derived from the username as written.
     */
    #[Test]
    public function aPersonWhoseTagWasDerivedFromTheUsernameAsWrittenIsFoundUnderAnotherCase(): void
    {
        // Given
        $bob = self::writtenBefore('Bob', 'bob');

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'bob')?->id->equals($bob->id));
    }

    /**
     * RFC 8265 §3.3
     */
    #[Test]
    public function itNamesAPersonWhoseUsernameTheProfileRefuses(): void
    {
        // Given
        $jean = self::writtenBefore('Jean Dupont', 'jean');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertStringContainsString(
            'RFC 8265 §3.3 refuses the username of 1 person(s), who sign in under it as written until an administrator renames them.',
            self::flattened($tester),
        );
        static::assertMatchesRegularExpression(sprintf('/^\s*%s\s+Jean Dupont\s*$/m', $jean->id->toRfc4122()), $tester->getDisplay(true));
    }

    /**
     * RFC 8265 §3.3
     */
    #[Test]
    public function aPersonWhoseUsernameTheProfileRefusesIsStillFoundAsWritten(): void
    {
        // Given
        $jean = self::writtenBefore('Jean Dupont', 'jean');

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'Jean Dupont')?->id->equals($jean->id));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function itNamesThePersonsWhoseUsernamesTheProfileComparesAsOne(): void
    {
        // Given
        $alice = self::user('alice', 'alice-subject');
        $other = self::writtenBefore('Alice', 'other-alice');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertStringContainsString(
            '2 persons have usernames RFC 8265 §3.3.4 compares as one: their blind indexes were left as they were. Rename all of them but one, then run this command again.',
            self::flattened($tester),
        );
        static::assertMatchesRegularExpression(
            sprintf('/^\s*%s\s+alice\s*\n\s*%s\s+Alice\s*$/m', $alice->id->toRfc4122(), $other->id->toRfc4122()),
            $tester->getDisplay(true),
        );
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function thePersonsTheProfileComparesAsOneKeepTheirTags(): void
    {
        // Given
        self::user('alice', 'alice-subject');
        $other = self::writtenBefore('Alice', 'other-alice');

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertSame('derived-before-other-alice', self::entityManager()
            ->getConnection()
            ->fetchOne(
                'SELECT username_index FROM beffroi_user WHERE id = ?',
                [$other->id],
                [UuidType::NAME],
            ));
    }

    #[Test]
    public function itFailsWhileAPersonIsLeftToRename(): void
    {
        // Given
        self::writtenBefore('Jean Dupont', 'jean');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
    }

    /**
     * A person written before RFC 8265 §3.3 applied: their username as it was kept, and a tag of their own.
     */
    private static function writtenBefore(string $username, string $name): User
    {
        $user = self::user($name, $name . '-subject');
        self::entityManager()
            ->getConnection()
            ->update(
                'beffroi_user',
                [
                    'username' => $username,
                    'username_index' => 'derived-before-' . $name,
                ],
                [
                    'id' => $user->id,
                ],
                [
                    'username' => EncryptedColumnTypes::name('user', 'string'),
                    'id' => UuidType::NAME,
                ],
            );
        self::reload();

        return $user;
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
