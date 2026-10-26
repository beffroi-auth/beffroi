<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Beffroi\Bundle\Command\UserReindexCommand;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Console\Command\Command;

/**
 * Issue #781: the blind indexes of the persons of the tenant derived again after a projection changed, the
 * address folded whole where only its domain was. A row written under the old projection is a row no search
 * finds until then.
 */
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

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
