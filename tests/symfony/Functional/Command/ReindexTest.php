<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\ConfiguredTenant;
use App\Command\UserReindexCommand;
use App\Doctrine\EntityManagers;
use App\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Port\ExclusiveSectionsInterface;
use function array_map;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Beffroi\Core\Domain\Identity\User;
use Closure;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use App\Command\UserRenameCommand;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Port\UserRepositoryInterface;
use IntlChar;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Console\Command\Command;

/**
 * A row of 0.1 holds its username as written, and the tag the Verbatim projection derived of it under the name of the
 * column; its tenant recorded no derivation.
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

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function beforeTheReindexAPersonOf01IsFoundUnderTheirUsernameAsWritten(): void
    {
        // Given
        $bob = self::personOf01('Bob', 'bob');

        // When
        $found = self::users()->findByUsername(self::tenant(), 'Bob');

        // Then
        static::assertTrue($found?->id->equals($bob->id));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function afterTheReindexAPersonOf01IsFoundUnderAnotherCaseOfTheirUsername(): void
    {
        // Given
        $bob = self::personOf01('Bob', 'bob');

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'bob')?->id->equals($bob->id));
    }

    /**
     * RFC 6532 §3.1: 0.1 folded the local part without bringing it to NFC, which a compatibility ideograph tells apart.
     */
    #[Test]
    public function beforeTheReindexAPersonOf01IsFoundByAnAddressWhoseFoldChanged(): void
    {
        // Given
        $address = new EmailAddress("\u{F900}@acme.example");
        $bob = self::user('bob', 'bob-subject');
        $bob->changeEmail($address, false, self::now());
        self::users()->save($bob);
        self::entityManager()
            ->getConnection()
            ->update(
                'beffroi_user',
                [
                    'email_index' => self::service(TenantBlindIndexes::class, TenantBlindIndexes::class)->of(
                        BlindIndexedColumns::emailAsFoldedBefore(),
                    )->of($address->value),
                ],
                [
                    'id' => $bob->id,
                ],
                [
                    'id' => UuidType::NAME,
                ],
            );
        self::reload();

        // When
        $found = self::users()->findAllByEmail(self::tenant(), $address);

        // Then
        static::assertSame([$bob->id->toRfc4122()], array_map(static fn (User $user): string => $user->id->toRfc4122(), $found));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function beforeTheReindexTheNameAsWrittenOfAPairFindsThePersonWrittenSo(): void
    {
        // Given
        self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');

        // When
        $found = self::users()->findByUsername(self::tenant(), 'Alice');

        // Then
        static::assertTrue($found?->id->equals($other->id));
    }

    /**
     * RFC 8265 §3.3
     */
    #[Test]
    public function itNamesAPersonWhoseUsernameTheProfileRefuses(): void
    {
        // Given
        $jean = self::personOf01('Jean Dupont', 'jean');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertStringContainsString(
            'RFC 8265 §3.3 refuses the username of 1 person(s), who sign in under it as written until an administrator renames them, and at the latest until 1.0.0.',
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
        $jean = self::personOf01('Jean Dupont', 'jean');

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
        $alice = self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertStringContainsString(
            '2 persons have usernames RFC 8265 §3.3.4 compares as one: no lookup finds them, and nobody else takes their username, until they are renamed.',
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
    public function itSaysWhomTheOtherSpellingsOfAPairNamedBefore(): void
    {
        // Given
        $alice = self::personOf01('alice', 'alice');
        self::personOf01('Alice', 'other-alice');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertStringContainsString(
            sprintf('Before, each username named the person written so, and any other spelling named %s.', $alice->id->toRfc4122()),
            self::flattened($tester),
        );
    }

    /**
     * RFC 8265 §3.3.4: neither person of a pair is found under the name of the other.
     */
    #[Test]
    #[DataProvider('provideSpellingsOfAPair')]
    public function afterTheReindexNoSpellingOfAPairFindsAnyOfIt(string $spelling): void
    {
        // Given
        self::personOf01('alice', 'alice');
        self::personOf01('Alice', 'other-alice');

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertNull(self::users()->findByUsername(self::tenant(), $spelling));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpellingsOfAPair(): iterable
    {
        yield 'the enforced form' => ['alice'];
        yield 'the other username' => ['Alice'];
        yield 'a third spelling' => ['ALICE'];
    }

    /**
     * RFC 8265 §3.3.4: a change of a person the reindex set aside is written, and leaves them where no lookup finds them.
     */
    #[Test]
    public function aPersonOfAPairIsChangedOtherwiseThanRenamedAndStaysSetAside(): void
    {
        // Given
        self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');
        self::console(UserReindexCommand::NAME);
        $person = self::users()->find($other->id) ?? static::fail('The person is not stored.');
        $person->changeEmail(new EmailAddress('alice.martin@acme.example'), false, self::now());

        // When
        self::users()->save($person);

        // Then
        self::reload();
        static::assertSame(
            ['alice.martin@acme.example', null],
            [self::users()->find($other->id)?->email?->value, self::users()->findByUsername(self::tenant(), 'Alice')],
        );
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function onceThePairIsRenamedTheNextReindexGivesItsLastPersonTheirUsernameBack(): void
    {
        // Given
        $alice = self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');
        self::console(UserReindexCommand::NAME);
        self::console(UserRenameCommand::NAME, [
            'user' => $other->id->toRfc4122(),
            'username' => 'alice.martin',
        ]);

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'ALICE')?->id->equals($alice->id));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function onceThePairIsRenamedTheNextReindexReservesItsUsernameNoLonger(): void
    {
        // Given
        self::personOf01('alice', 'alice');
        $other = self::personOf01('Alice', 'other-alice');
        self::console(UserReindexCommand::NAME);
        self::console(UserRenameCommand::NAME, [
            'user' => $other->id->toRfc4122(),
            'username' => 'alice.martin',
        ]);

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        static::assertSame([], self::derivations()->recorded(self::tenant())?->reserved);
    }

    /**
     * Two servers starting at once walk the tenant one after the other, the second finding nothing due.
     */
    #[Test]
    public function itWalksInTheSectionEveryProcessOfTheDeploymentShares(): void
    {
        // Given
        $sections = new class implements ExclusiveSectionsInterface {
            /**
             * @var list<string>
             */
            public array $entered = [];

            public function exclusively(string $name, Closure $section): mixed
            {
                $this->entered[] = $name;

                return $section();
            }
        };
        $command = new UserReindexCommand(
            self::service(ConfiguredTenant::class, ConfiguredTenant::class),
            self::service(EntityManagers::class, EntityManagers::class),
            self::service(TenantBlindIndexes::class, TenantBlindIndexes::class),
            self::derivations(),
            $sections,
        );

        // When
        $command(new SymfonyStyle(new ArrayInput([]), new NullOutput()));

        // Then
        static::assertSame([sprintf('beffroi:user:reindex %s', self::tenant()->slug)], $sections->entered);
    }

    #[Test]
    public function aRunThatNamesPersonsEndsWithItsOwnStatus(): void
    {
        // Given
        self::personOf01('Jean Dupont', 'jean');

        // When
        $tester = self::console(UserReindexCommand::NAME);

        // Then
        static::assertSame(UserReindexCommand::PERSONS_NAMED, $tester->getStatusCode());
    }

    #[Test]
    public function itRecordsTheDerivationAndTheVersionOfUnicodeItDerivedUnder(): void
    {
        // Given
        self::personOf01('Bob', 'bob');

        // When
        self::console(UserReindexCommand::NAME);

        // Then
        $recorded = self::derivations()->recorded(self::tenant());
        static::assertSame(
            [BlindIndexedColumns::DERIVATION, IntlChar::UNICODE_VERSION],
            [$recorded?->derivation, $recorded?->unicodeVersion],
        );
    }

    #[Test]
    public function whenDueItLeavesATenantWhoseTagsAreDerivedUnderThisBuild(): void
    {
        // Given
        self::user('alice', 'alice-subject');

        // When
        $tester = self::console(UserReindexCommand::NAME, [
            '--when-due' => true,
        ]);

        // Then
        static::assertStringContainsString(
            sprintf('The blind indexes of the tenant "%s" are derived under the projections of this build.', self::tenant()->slug),
            self::flattened($tester),
        );
    }

    #[Test]
    #[DataProvider('provideDerivationsDue')]
    public function whenDueItDerivesATenantWhoseTagsAreDerivedUnderAnother(string $statement): void
    {
        // Given
        $bob = self::personOf01('Bob', 'bob');
        self::derivations()->record(self::tenant(), 0, 0);
        self::entityManager()->getConnection()->executeStatement($statement);

        // When
        self::console(UserReindexCommand::NAME, [
            '--when-due' => true,
        ]);

        // Then
        static::assertTrue(self::users()->findByUsername(self::tenant(), 'bob')?->id->equals($bob->id));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDerivationsDue(): iterable
    {
        yield 'none, as 0.1 left it' => ['DELETE FROM ' . BlindIndexDerivations::TABLE];
        yield 'under another version of Unicode' => ['UPDATE ' . BlindIndexDerivations::TABLE . " SET unicode_version = '15.1'"];
        yield 'under an earlier derivation' => ['UPDATE ' . BlindIndexDerivations::TABLE . ' SET derivation = 0'];
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
