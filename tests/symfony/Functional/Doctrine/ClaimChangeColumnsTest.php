<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0011
 */
final class ClaimChangeColumnsTest extends DatabaseTestCase
{
    private const string WAS = SealedRows::VALUES['beffroi_claim_change']['was'];

    private const string BECAME = SealedRows::VALUES['beffroi_claim_change']['became'];

    #[Test]
    public function bothValuesAreReadBackAsTheyWereWritten(): void
    {
        // Given
        $user = self::user();
        self::history()->record(self::change($user));
        self::reload();

        // When
        $read = self::changes()->lastOf(self::reread($user), 10);

        // Then
        static::assertCount(1, $read);
        static::assertSame(self::WAS, $read[0]->was);
        static::assertSame(self::BECAME, $read[0]->became);
        static::assertSame(SealedRows::USER_AGENT, $read[0]->context->userAgent);
    }

    #[Test]
    public function theColumnsHoldNeitherValue(): void
    {
        // Given
        self::history()->record(self::change(self::user()));
        self::reload();

        // When
        $row = self::row();

        // Then
        static::assertStringNotContainsString(self::WAS, $row['was']);
        static::assertStringNotContainsString(self::BECAME, $row['became']);
        static::assertStringNotContainsString(SealedRows::USER_AGENT, $row['context']);
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    public function theNameOfTheClaimIsInTheClear(): void
    {
        // Given
        self::history()->record(self::change(self::user()));
        self::reload();

        // When / Then
        static::assertSame('nickname', self::row()['claim']);
    }

    /**
     * @return iterable<string, array{AuthorInterface, string}>
     */
    public static function authors(): iterable
    {
        yield 'a change the person made' => [new ThePerson(), '{"kind":"person"}'];
        yield 'a change an administrator made' => [
            new AnAdministrator(new Subject('administrator-subject')),
            '{"kind":"administrator","subject":"administrator-subject"}',
        ];
        yield 'a change a client made' => [new AClient('oidc-demo'), '{"kind":"client","client_id":"oidc-demo"}'];
        yield 'a change a directory made' => [new ADirectory('Entra ID'), '{"kind":"directory","name":"Entra ID"}'];
        yield 'a change the host made' => [new TheHost(), '{"kind":"host"}'];
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('authors')]
    public function whoMadeAChangeIsWrittenAsTheDocumentOfTheirKindAndReadBackAsTheyWere(AuthorInterface $author, string $written): void
    {
        // Given
        $user = self::user();
        self::history()->record(new ClaimChange(Uuid::v7(), $user, 'nickname', self::WAS, self::BECAME, self::now(), self::context(), $author));
        self::reload();

        // When
        $read = self::changes()->lastOf(self::reread($user), 10);

        // Then
        static::assertEquals([$written, $author], [self::connection()->fetchOne('SELECT author FROM beffroi_claim_change'), $read[0]->author]);
    }

    /**
     * Decision 0060: a change written before changes named the kind of their author is never rewritten, and reads back
     * as it was written: an administrator by their bare subject, the person by nothing.
     */
    #[Test]
    #[DataProvider('provideAuthorsWrittenBefore')]
    public function aChangeWrittenBeforeChangesNamedTheKindOfTheirAuthorReadsBackAsItWasWritten(?string $written, AuthorInterface $read): void
    {
        // Given
        $user = self::user();
        self::history()->record(self::change($user));
        self::connection()->executeStatement('UPDATE beffroi_claim_change SET author = ?', [$written]);
        self::reload();

        // When
        $changes = self::changes()->lastOf(self::reread($user), 10);

        // Then
        static::assertEquals($read, $changes[0]->author);
    }

    /**
     * @return iterable<string, array{string|null, AuthorInterface}>
     */
    public static function provideAuthorsWrittenBefore(): iterable
    {
        yield 'an administrator, by their bare subject' => ['administrator-subject', new AnAdministrator(new Subject('administrator-subject'))];
        yield 'the person, by nothing' => [null, new ThePerson()];
    }

    /**
     * @return array<string, string>
     */
    private static function row(): array
    {
        $rows = RawRows::of(self::connection(), 'beffroi_claim_change', ['claim', 'was', 'became', 'context']);
        static::assertCount(1, $rows);

        $row = [];
        foreach ($rows[0] as $column => $value) {
            $row[$column] = $value ?? static::fail(sprintf('beffroi_claim_change.%s holds nothing.', $column));
        }

        return $row;
    }

    private static function change(User $user): ClaimChange
    {
        return new ClaimChange(Uuid::v7(), $user, 'nickname', self::WAS, self::BECAME, self::now(), self::context(), new ThePerson());
    }

    private static function reread(User $user): User
    {
        $reread = self::entityManager()->find(User::class, $user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }

    private static function history(): ClaimHistoryInterface
    {
        return self::service('test.beffroi.claim_history', ClaimHistoryInterface::class);
    }

    private static function changes(): ChangesOfAPersonInterface
    {
        return self::service('test.beffroi.changes', ChangesOfAPersonInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
