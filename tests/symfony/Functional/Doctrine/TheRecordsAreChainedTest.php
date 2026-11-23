<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Configuration\JournalSection;
use App\Doctor\Finding;
use App\Doctor\ChainHoldsTogether;
use App\Key\FileChainCheckpoints;
use App\Message\ForgetTheActsPastTheirRetention;
use App\Message\SignTheChains;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\ClaimHistoryChain;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\ChainOfRowsInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Chain\ChainInterface;
use function file_get_contents;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Domain\Disclosure\DisclosureChain;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\DisclosuresInterface;
use App\Command\ChainSignAnewCommand;
use App\Command\ChainVerifyCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use function file_put_contents;
use function array_map;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0060
 */
final class TheRecordsAreChainedTest extends DatabaseTestCase
{
    use ClockSensitiveTrait;

    protected function tearDown(): void
    {
        new Filesystem()->remove(self::keyStorage() . '/default/' . FileChainCheckpoints::DIRECTORY);
        parent::tearDown();
    }

    #[Test]
    public function twoActsTakeTwoPositionsThatFollowEachOther(): void
    {
        // Given
        self::anAct();

        // When
        self::anAct();

        // Then
        static::assertSame([1, 2], array_map(
            static fn ($linked): int => $linked->position,
            self::service('test.beffroi.chains', ChainOfRowsInterface::class)->linkedAfter(self::tenant(), new JournalChain(), 0, 10),
        ));
    }

    #[Test]
    public function aJournalWrittenByTheProviderHoldsTogether(): void
    {
        // Given
        self::anAct();
        self::anAct();

        // When
        $finding = self::finding();

        // Then
        static::assertSame(
            [true, 'The 2 row(s) the chain keeps, positions 1 to 2, follow one another; none is signed yet, which the next pass does.'],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    #[Test]
    public function anActChangedInTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        self::anAct();
        $changed = self::anAct();
        self::connection()->update('beffroi_journal', ['act' => 'user.signed_out'], ['id' => $changed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The row at position 2 of the chain "journal" is not the one written there.'], [
            $finding->green,
            $finding->lines[0] ?? null,
        ]);
    }

    #[Test]
    public function aProvenanceMovedFromAnotherActIsNamedByItsPosition(): void
    {
        // Given
        $from = self::anAct();
        $to = self::anAct();
        $sealed = self::connection()->fetchOne('SELECT context FROM beffroi_journal WHERE id = ?', [$from->id], [UuidType::NAME]);
        self::connection()->update('beffroi_journal', ['context' => $sealed], ['id' => $to->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The row at position 2 of the chain "journal" is not the one written there.'], [
            $finding->green,
            $finding->lines[0] ?? null,
        ]);
    }

    #[Test]
    public function anActRemovedFromTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        self::anAct();
        $removed = self::anAct();
        self::anAct();
        self::connection()->delete('beffroi_journal', ['id' => $removed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The row at position 2 of the chain "journal" is missing.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function theFirstActRemovedAfterTheSignatureIsNamedByItsPosition(): void
    {
        // Given
        $removed = self::anAct();
        self::aSigningKey();
        self::dispatch(new SignTheChains());
        self::connection()->delete('beffroi_journal', ['id' => $removed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The row at position 1 of the chain "journal" is missing.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function anActAddedToTheDatabaseOutsideTheChainIsSeen(): void
    {
        // Given
        self::anAct();
        $manager = self::entityManager();
        $manager->persist(self::entry(self::now()));
        $manager->flush();

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, '1 row(s) of the chain "journal" are not in it.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function theSignatureIsKeptBesideTheKeysOfTheTenant(): void
    {
        // Given
        self::aSigningKey();

        // When
        self::dispatch(new SignTheChains());

        // Then
        static::assertFileExists(self::keyStorage() . '/default/' . FileChainCheckpoints::DIRECTORY . '/journal' . FileChainCheckpoints::SUFFIX);
    }

    #[Test]
    public function aSignedJournalSaysUpToWhereItIsSigned(): void
    {
        // Given
        self::aSigningKey();
        self::dispatch(new SignTheChains());

        // When
        $finding = self::finding();

        // Then
        static::assertStringContainsString(
            'holds up to position 2 and the rows written since follow it, 0 of them waiting for the next pass',
            $finding->lines[0] ?? '',
        );
    }

    #[Test]
    public function anActWhoseMomentIsMovedBackIsNotForgottenByTheRetention(): void
    {
        // Given
        $moved = self::anAct();
        self::aSigningKey();
        self::dispatch(new SignTheChains());
        self::movedBack($moved);

        // When
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // Then
        static::assertTrue(self::isKept($moved));
    }

    #[Test]
    public function anActWhoseMomentIsMovedBackIsNamedByItsPosition(): void
    {
        // Given
        $moved = self::anAct();
        self::aSigningKey();
        self::dispatch(new SignTheChains());
        self::movedBack($moved);
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // When
        $finding = self::finding();

        // Then
        static::assertStringContainsString('found the row at position 1 not following the one before it', $finding->lines[0] ?? '');
    }

    #[Test]
    public function theRetentionForgetsTheOldestActs(): void
    {
        // Given
        $old = self::anAct(self::past());
        self::aSigningKey();

        // When
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // Then
        static::assertFalse(self::isKept($old));
    }

    #[Test]
    public function aJournalTheRetentionCutHoldsTogether(): void
    {
        // Given
        self::anAct(self::past());
        self::aSigningKey();
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // When
        $finding = self::finding();

        // Then
        static::assertTrue($finding->green);
        static::assertStringStartsWith('The chain keeps positions 2 to 3; the signature of ', $finding->lines[0] ?? '');
    }

    #[Test]
    public function aChangeOfAClaimTakesThePositionThatFollows(): void
    {
        // Given
        self::aChangeOfAClaim();

        // When
        self::aChangeOfAClaim();

        // Then
        static::assertSame([1, 2], self::positions(new ClaimHistoryChain()));
    }

    #[Test]
    public function whatAClientWasGivenTakesThePositionThatFollows(): void
    {
        // Given
        self::whatWasGiven();

        // When
        self::whatWasGiven();

        // Then
        static::assertSame([1, 2], self::positions(new DisclosureChain()));
    }

    #[Test]
    public function aChangeOfAClaimRewrittenInTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        self::aChangeOfAClaim();
        $rewritten = self::aChangeOfAClaim();
        self::connection()->update('beffroi_claim_change', ['claim' => 'family_name'], ['id' => $rewritten->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::service('test.beffroi.doctor.claim_history_chain', ChainHoldsTogether::class)->finding();

        // Then
        static::assertSame([false, 'The row at position 2 of the chain "claim_history" is not the one written there.'], [
            $finding->green,
            $finding->lines[0] ?? null,
        ]);
    }

    #[Test]
    public function whatAClientWasGivenRemovedFromTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        $removed = self::whatWasGiven();
        self::whatWasGiven();
        self::aSigningKey();
        self::dispatch(new SignTheChains());
        self::connection()->delete('beffroi_disclosure', ['id' => $removed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::service('test.beffroi.doctor.disclosure_chain', ChainHoldsTogether::class)->finding();

        // Then
        static::assertSame([false, 'The row at position 1 of the chain "disclosures" is missing.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function aChainTheScheduleStoppedSigningIsRed(): void
    {
        // Given
        self::mockTime(self::service('clock', ClockInterface::class)->now());
        self::aSigningKey();
        self::dispatch(new SignTheChains());
        self::mockTime(self::service('clock', ClockInterface::class)->now()->modify('+11 minutes'));

        // When
        $finding = self::finding();

        // Then
        static::assertStringStartsWith('The chain was last signed at ', $finding->lines[0] ?? '');
    }

    #[Test]
    public function aChainNobodySignedIsRedOnceTwoPassesHaveGone(): void
    {
        // Given
        self::mockTime(self::service('clock', ClockInterface::class)->now());
        self::anAct();
        self::mockTime(self::service('clock', ClockInterface::class)->now()->modify('+11 minutes'));

        // When
        $finding = self::finding();

        // Then
        static::assertStringStartsWith('Nothing has signed the chain, whose first row is from ', $finding->lines[0] ?? '');
    }

    #[Test]
    public function theVerificationNamesAChainCutShortAgainstACopyKeptOutside(): void
    {
        // Given
        self::aSigningKey();
        self::dispatch(new SignTheChains());
        $older = self::kept();
        $cut = self::anAct();
        self::dispatch(new SignTheChains());
        $copy = self::keyStorage() . '/copy.jws';
        file_put_contents($copy, self::kept());
        self::connection()->delete('beffroi_journal', ['id' => $cut->id], ['id' => UuidType::NAME]);
        self::connection()->delete('beffroi_chain_link', ['row_id' => $cut->id], ['row_id' => UuidType::NAME]);
        self::connection()->executeStatement("UPDATE beffroi_chain_head SET position = position - 1 WHERE chain = 'journal'");
        file_put_contents(self::keyStorage() . '/default/' . FileChainCheckpoints::DIRECTORY . '/journal' . FileChainCheckpoints::SUFFIX, $older);

        // When
        $verify = self::command(ChainVerifyCommand::NAME, ['chain' => 'journal', '--against' => $copy]);

        // Then
        static::assertSame(Command::FAILURE, $verify->getStatusCode(), $verify->getDisplay());
    }

    #[Test]
    public function aChainSignedAnewByAPersonHoldsTogether(): void
    {
        // Given
        self::aSigningKey();
        $changed = self::anAct();
        self::anAct();
        self::connection()->update('beffroi_journal', ['act' => 'user.signed_out'], ['id' => $changed->id], ['id' => UuidType::NAME]);
        self::command(ChainSignAnewCommand::NAME, ['chain' => 'journal', 'slug' => self::tenant()->slug]);

        // When
        $finding = self::finding();

        // Then
        static::assertTrue($finding->green, $finding->lines[0] ?? '');
    }

    #[Test]
    public function aChainIsSignedAnewOnlyOnceTheSlugIsTypedBack(): void
    {
        // When
        $signAnew = self::command(ChainSignAnewCommand::NAME, ['chain' => 'journal']);

        // Then
        static::assertSame(Command::INVALID, $signAnew->getStatusCode());
    }

    /**
     * @param array<string, string> $input
     */
    private static function command(string $name, array $input): CommandTester
    {
        $application = new Application(self::$kernel ?? static::fail('No kernel.'));
        $application->setAutoExit(false);
        $tester = new CommandTester($application->find($name));
        $tester->execute($input);
        self::reload();

        return $tester;
    }

    private static function kept(): string
    {
        $kept = file_get_contents(self::keyStorage() . '/default/' . FileChainCheckpoints::DIRECTORY . '/journal' . FileChainCheckpoints::SUFFIX);
        static::assertIsString($kept);

        return $kept;
    }

    /**
     * @return list<int>
     */
    private static function positions(ChainInterface $chain): array
    {
        return array_map(
            static fn ($linked): int => $linked->position,
            self::service('test.beffroi.chains', ChainOfRowsInterface::class)->linkedAfter(self::tenant(), $chain, 0, 10),
        );
    }

    private static function aChangeOfAClaim(): ClaimChange
    {
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'alice') ?? self::user();
        $change = new ClaimChange(Uuid::v7(), $user, 'nickname', 'Ada', 'Augusta', self::service('clock', ClockInterface::class)->now(), self::context());
        self::service('test.beffroi.claim_history', ClaimHistoryInterface::class)->record($change);
        self::reload();

        return $change;
    }

    private static function whatWasGiven(): Disclosure
    {
        $given = new Disclosure(
            Uuid::v7(),
            self::tenant(),
            new Subject('alice-subject'),
            'oidc-demo',
            'tokens.issued',
            self::service('clock', ClockInterface::class)->now(),
            new Scopes([Scope::openid()]),
            null,
            null,
            'jwt',
        );
        self::service('test.beffroi.disclosures', DisclosuresInterface::class)->record($given);
        self::reload();

        return $given;
    }

    private static function anAct(?DateTimeImmutable $occurredAt = null): JournalEntry
    {
        $entry = self::entry($occurredAt ?? self::service('clock', ClockInterface::class)->now());
        self::service('test.beffroi.journal', JournalInterface::class)->record($entry);
        self::reload();

        return $entry;
    }

    private static function entry(DateTimeImmutable $occurredAt): JournalEntry
    {
        return new JournalEntry(Uuid::v7(), self::tenant(), UserAuthenticated::NAME, $occurredAt, self::context());
    }

    /**
     * Its activation is an act of the journal, written now.
     */
    private static function aSigningKey(): void
    {
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());
        self::reload();
    }

    private static function dispatch(object $message): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch($message);
        self::reload();
    }

    private static function finding(): Finding
    {
        return self::service('test.beffroi.doctor.journal_chain', ChainHoldsTogether::class)->finding();
    }

    private static function past(): DateTimeImmutable
    {
        return self::service('clock', ClockInterface::class)
            ->now()
            ->modify(sprintf('-%d days', JournalSection::DEFAULT_RETENTION + 1));
    }

    private static function movedBack(JournalEntry $act): void
    {
        self::connection()
            ->update(
                'beffroi_journal',
                ['occurred_at' => self::past()->format('Y-m-d H:i:s')],
                ['id' => $act->id],
                ['id' => UuidType::NAME],
            );
    }

    private static function isKept(JournalEntry $act): bool
    {
        return self::connection()->fetchOne('SELECT 1 FROM beffroi_journal WHERE id = ?', [$act->id], [UuidType::NAME]) !== false;
    }

    private static function connection(): Connection
    {
        return self::service('doctrine.dbal.default_connection', Connection::class);
    }
}
