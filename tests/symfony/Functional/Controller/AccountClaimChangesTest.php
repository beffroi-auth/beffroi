<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\AskedPage;
use App\Http\ClaimChangesPage;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ClaimHistoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class AccountClaimChangesTest extends BrowserTestCase
{
    #[Test]
    public function thePageShowsWhatThePersonChangedWithWhatItSaidBefore(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        static::assertSame(['nickname'], $page->filter('tbody tr[data-change]')->extract(['data-change']));
        $row = $page->filter('tbody tr[data-change]')->first()->filter('td');
        static::assertSame('Ada', $row->eq(1)->text());
        static::assertSame('Augusta', $row->eq(2)->text());
    }

    /**
     * @return iterable<string, array{AuthorInterface, string, string}>
     */
    public static function authors(): iterable
    {
        yield 'a change the person made' => [new ThePerson(), 'person', 'You'];
        yield 'a change an administrator made' => [
            new AnAdministrator(new Subject('administrator-subject')),
            'administrator',
            'An administrator of your organisation',
        ];
        yield 'a change a directory made, by its name' => [new ADirectory('Entra <ID>'), 'directory', 'The directory Entra <ID>'];
    }

    /**
     * Decisions 0038 and 0066: the person reads that an administrator of their organisation made a change, never which
     * one, and the name of a directory that made one.
     */
    #[Test]
    #[DataProvider('authors')]
    public function eachChangeSaysWhoMadeIt(AuthorInterface $author, string $kind, string $said): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta', author: $author);
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        $cell = $page->filter('tbody tr[data-change] td[data-author]');
        static::assertSame([[$kind], $said], [$cell->extract(['data-author']), $cell->text()]);
    }

    #[Test]
    public function aVerificationIsSaidInWords(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'true', 'false', claim: 'email_verified');
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        $row = $page->filter('tbody tr[data-change]')->first()->filter('td');
        static::assertSame(['verified', 'not verified'], [$row->eq(1)->text(), $row->eq(2)->text()]);
    }

    /**
     * Decision 0050
     */
    #[Test]
    #[DataProvider('provideChoicesOfChannels')]
    public function aChoiceOfChannelsIsSaidInWords(?string $value, string $said): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, $value, 'mail', claim: 'notification_channels.pending_approval');
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        static::assertSame($said, $page->filter('tbody tr[data-change]')->first()->filter('td')->eq(1)->text());
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function provideChoicesOfChannels(): iterable
    {
        yield 'nothing chosen' => [null, 'Not chosen'];
        yield 'no channel' => ['', 'No channel'];
        yield 'channels' => ['sms web_push', 'Text message, Browsers'];
    }

    #[Test]
    public function aPersonWhoChangedNothingIsToldSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->changesPage();

        // Then
        static::assertCount(1, $page->filter('table[data-changes="0"] tr[data-empty]'));
    }

    #[Test]
    public function theHistoryIsReadInPages(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        for ($made = 0; $made <= AskedPage::ROWS; ++$made) {
            self::aChange($alice, 'Ada', 'Augusta');
        }
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        static::assertCount(AskedPage::ROWS, $page->filter('tbody tr[data-change]'));
        static::assertSame('/account/profile/changes?page=2', $page->filter('a[data-pager="next"]')->attr('href'));
    }

    #[Test]
    public function thePeriodNarrowsTheHistoryToTheDaysItNames(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Augusta', 'Ada', '-2 months');
        self::reload();

        // When
        $page = $this->changesPage(['from' => self::currentSecond()->format('Y-m-d')]);

        // Then
        static::assertCount(1, $page->filter('tbody tr[data-change]'));
        static::assertSame('/account/profile/changes', $page->filter('a[data-filter="clear"]')->attr('href'));
    }

    #[Test]
    public function aPeriodThatEndsBeforeItStartsNarrowsNothing(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Augusta', 'Ada', '-2 months');
        self::reload();

        // When
        $page = $this->changesPage([
            'from' => self::currentSecond()->format('Y-m-d'),
            'to' => self::currentSecond()->modify('-1 month')->format('Y-m-d'),
        ]);

        // Then
        static::assertCount(2, $page->filter('tbody tr[data-change]'));
        static::assertCount(0, $page->filter('a[data-filter="clear"]'));
    }

    #[Test]
    public function theClaimAskedForIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Lovelace', 'King', claim: 'family_name');
        self::reload();

        // When
        $page = $this->changesPage([ClaimChangesPage::CLAIM => 'family_name']);

        // Then
        static::assertSame(['family_name'], $page->filter('tbody tr[data-change]')->extract(['data-change']));
    }

    #[Test]
    public function theClaimsOfferedAreThoseTheHistoryOfThePersonHolds(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Lovelace', 'King', claim: 'family_name');
        self::aChange($alice, 'Augusta', 'Ada');
        self::aChange(self::user('bob', 'bob-subject'), 'Bob', 'Robert', claim: 'given_name');
        self::reload();

        // When
        $page = $this->changesPage();

        // Then
        static::assertSame(['', 'family_name', 'nickname'], $page->filter('select[name="claim"] option')->extract(['value']));
    }

    /**
     * Decision 0066: a change written before changes named the kind of their author is the person's when it names
     * nobody, and an administrator's when it names a bare subject.
     *
     * @param list<string> $kinds
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theChangesOfAKindOfAuthorAreReadApart(string $by, array $kinds): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::aChange($alice, 'Ada', 'Augusta');
        self::aChange($alice, 'Augusta', 'Ada', author: new AnAdministrator(new Subject('mallory-subject')));
        self::aChange($alice, 'Ada', 'Augusta', author: new ADirectory('Entra ID'));
        self::aChange($alice, 'Augusta', 'Ada', author: new TheHost());
        self::aChange($alice, 'Ada', 'Augusta', claim: 'family_name');
        self::aChange($alice, 'Augusta', 'Ada', claim: 'given_name');
        self::entityManager()->getConnection()->executeStatement("UPDATE beffroi_claim_change SET author = NULL WHERE claim = 'family_name'");
        self::entityManager()->getConnection()->executeStatement("UPDATE beffroi_claim_change SET author = 'mallory-subject' WHERE claim = 'given_name'");
        self::reload();

        // When
        $page = $this->changesPage([ClaimChangesPage::AUTHOR => $by]);

        // Then
        static::assertSame($kinds, $page->filter('tbody tr[data-change] td[data-author]')->extract(['data-author']));
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'what an administrator made' => ['administrator', ['administrator', 'administrator']];
        yield 'what the person made' => ['person', ['person', 'person']];
        yield 'what a directory made' => ['directory', ['directory']];
        yield 'what the host made' => ['host', ['host']];
    }

    #[Test]
    public function theKindsOfAuthorAreOffered(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->changesPage();

        // Then
        static::assertSame(
            ['', 'person', 'administrator', 'client', 'directory', 'upstream', 'unauthenticated', 'host'],
            $page->filter('select[name="by"] option')->extract(['value']),
        );
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/account/profile/changes');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @param array<string, string> $narrowed
     */
    private function changesPage(array $narrowed = []): Crawler
    {
        $page = $this->browser->request('GET', '/account/profile/changes', $narrowed);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    private static function aChange(
        User $user,
        ?string $was,
        ?string $became,
        string $ago = 'now',
        string $claim = 'nickname',
        AuthorInterface $author = new ThePerson(),
    ): void {
        $at = self::currentSecond()->modify($ago);
        self::service('test.beffroi.claim_history', ClaimHistoryInterface::class)
            ->record(new ClaimChange(Uuid::v7(), $user, $claim, $was, $became, $at, self::context(), $author));
    }
}
