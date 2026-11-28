<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_keys;
use function array_map;
use function array_values;
use App\Http\ActsPage;
use App\Http\AskedPage;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Event\CredentialForgotten;
use Beffroi\Core\Domain\Author\AnUnauthenticatedCaller;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Event\GroupMembershipRemoved;
use Beffroi\Core\Domain\Author\AnUpstreamProvider;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Event\PersonDisabled;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Oidc\Domain\Event\ConsentRevoked;
use Beffroi\Oidc\Domain\Event\ConsentsReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\JournalReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\SessionsReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function str_contains;
use function str_starts_with;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class AccountActsTest extends BrowserTestCase
{
    /**
     * Architecture §5.7
     */
    #[Test]
    #[DataProvider('provideLanguages')]
    public function everyActOfAnAccountIsOnThePageAndNamesItself(string $language): void
    {
        // Given
        $alice = self::user('alice');
        foreach (ActsPage::ACTS as $act) {
            self::record($alice, $act);
        }
        self::reload();
        $this->signIn($alice);

        // When
        $rows = $this->rowsOfEveryPage($language);

        // Then
        static::assertSame(self::sorted(ActsPage::ACTS), self::sorted(array_keys($rows)));
        foreach ($rows as $named) {
            static::assertFalse(str_starts_with($named, 'act.'), 'An act is named and never shown by its key.');
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLanguages(): iterable
    {
        yield 'a browser in English' => ['en-US,en;q=0.9'];
        yield 'a browser in French' => ['fr-FR,fr;q=0.9'];
    }

    /**
     * Decision 0038: the person reads that an administrator of their organisation did it, and nothing else of them.
     */
    #[Test]
    #[DataProvider('provideActsOfAnAdministrator')]
    public function anActAnAdministratorDidIsOnThePageByTheirRoleAlone(string $act): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, $act, 'tui-of-mallory', author: new AnAdministrator(new Subject('mallory-subject')));
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        $row = $page->filter('tbody tr');
        static::assertSame(
            [[$act], 'An administrator of your organisation', false],
            [$row->extract(['data-act']), $row->filter('[data-author]')->text(), str_contains($row->html(), SealedRows::IP_ADDRESS)],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideActsOfAnAdministrator(): iterable
    {
        yield 'their account read' => [PersonReadByAnAdministrator::NAME];
        yield 'their open sessions read' => [SessionsReadByAnAdministrator::NAME];
        yield 'their journal read' => [JournalReadByAnAdministrator::NAME];
        yield 'a session of theirs ended' => [AuthenticationSessionEnded::NAME];
        yield 'a credential of theirs revoked' => [CredentialRevoked::NAME];
        yield 'their consents read' => [ConsentsReadByAnAdministrator::NAME];
        yield 'a consent of theirs taken back' => [ConsentRevoked::NAME];
    }

    /**
     * Decision 0066: the person reads the name of the directory that did it, in place of where it came from.
     */
    #[Test]
    public function anActADirectoryDidIsOnThePageByItsName(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, PersonDisabled::NAME, author: new ADirectory('Entra <ID>'));
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        $row = $page->filter('tbody tr');
        static::assertSame(
            ['The directory Entra <ID>', 'directory', false],
            [$row->filter('[data-author]')->text(), $row->filter('[data-author]')->attr('data-author'), str_contains($row->html(), SealedRows::IP_ADDRESS)],
        );
    }

    /**
     * Decision 0066, beffroi/saml S-56: the person reads the sign-in through the provider in place of where the act came
     * from, true even when a change the tenant made is what took the membership away.
     */
    #[Test]
    public function aMembershipASignInTookAwayIsOnThePageByTheProviderItCameThrough(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, GroupMembershipRemoved::NAME, author: new AnUpstreamProvider('https://sts.windows.net/acme/'));
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        $row = $page->filter('tbody tr');
        static::assertSame(
            ['A sign-in through https://sts.windows.net/acme/', 'upstream', false],
            [$row->filter('[data-author]')->text(), $row->filter('[data-author]')->attr('data-author'), str_contains($row->html(), SealedRows::IP_ADDRESS)],
        );
    }

    /**
     * Decision 0066: the person reads that the host did an act, and neither the user of its shell nor its name, which
     * the provenance of a command names.
     */
    #[Test]
    public function anActOfTheHostIsOnThePageByItsRoleAlone(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, CredentialForgotten::NAME, author: new TheHost());
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        $row = $page->filter('tbody tr');
        static::assertSame(['This service', 'host', false], [
            $row->filter('[data-author]')->text(),
            $row->filter('[data-author]')->attr('data-author'),
            str_contains($row->html(), SealedRows::IP_ADDRESS),
        ]);
    }

    /**
     * Decision 0066: an act the person did, a refused attempt and an act written before acts named their author say
     * where they came from.
     */
    #[Test]
    #[DataProvider('provideAuthorsSaidByWhereTheyActedFrom')]
    public function anActToldByWhereItCameFromSaysIt(?AuthorInterface $author): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, CredentialRevoked::NAME, author: $author);
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        $row = $page->filter('tbody tr');
        static::assertSame([0, true], [$row->filter('[data-author]')->count(), str_contains($row->html(), SealedRows::IP_ADDRESS)]);
    }

    /**
     * @return iterable<string, array{AuthorInterface|null}>
     */
    public static function provideAuthorsSaidByWhereTheyActedFrom(): iterable
    {
        yield 'the person' => [new ThePerson()];
        yield 'an unauthenticated caller' => [new AnUnauthenticatedCaller()];
        yield 'nobody, written before acts named their author' => [null];
    }

    #[Test]
    public function aReadAnAdministratorMadeOfThemselvesIsNotOnThePage(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, PersonReadByAnAdministrator::NAME, 'tui-of-alice', author: new AnAdministrator($alice->subject));
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    #[Test]
    public function aChangeAnAdministratorMadeToThemselvesIsOnThePage(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, AuthenticationSessionEnded::NAME, author: new AnAdministrator($alice->subject));
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertSame([AuthenticationSessionEnded::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    #[Test]
    public function anActOfTheProtocolIsNotOnThePageOfTheAccount(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, TokensIssued::NAME, 'oidc-demo');
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    #[Test]
    public function thePageShowsASignInThatSucceeded(): void
    {
        // Given
        $alice = self::user('alice');
        $session = self::session($alice, self::currentSecond());
        self::announce(new UserAuthenticated($session));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertSame('1', $page->filter('table[data-acts]')->attr('data-acts'));
        static::assertSame([UserAuthenticated::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    #[Test]
    public function thePageShowsAnAttemptThatWasRefused(): void
    {
        // Given
        $alice = self::user('alice');
        self::announce(self::refusedFor($alice));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertSame([AuthenticationFailed::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    #[Test]
    public function theActsOfSomebodyElseAreNotOnIt(): void
    {
        // Given
        $alice = self::user('alice');
        $bob = self::user('bob', 'bob-subject');
        self::announce(new UserAuthenticated(self::session($bob, self::currentSecond())));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    #[Test]
    public function aPersonWithNothingRecordedIsToldSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(1, $page->filter('table[data-acts="0"] tr[data-empty]'));
    }

    #[Test]
    public function onlyTheActsOfTheDaysAskedForAreOnIt(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, UserAuthenticated::NAME, occurredAt: self::currentSecond()->modify('-20 days'));
        self::record($alice, AuthenticationFailed::NAME);
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage(from: self::day('-10 days'), to: self::day('now'));

        // Then
        static::assertSame([AuthenticationFailed::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    #[Test]
    public function theActAskedForIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, UserAuthenticated::NAME);
        self::record($alice, AuthenticationFailed::NAME);
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage(narrowed: [ActsPage::ACT => AuthenticationFailed::NAME]);

        // Then
        static::assertSame([AuthenticationFailed::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    #[Test]
    public function anActThePageDoesNotOfferNarrowsNothing(): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, UserAuthenticated::NAME);
        self::record($alice, TokensIssued::NAME, 'oidc-demo');
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage(narrowed: [ActsPage::ACT => TokensIssued::NAME]);

        // Then
        static::assertSame([UserAuthenticated::NAME], $page->filter('tbody tr')->extract(['data-act']));
        static::assertCount(0, $page->filter('a[data-filter="clear"]'));
    }

    #[Test]
    public function theActsOfferedAreTheActsOfAnAccount(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $offered = $this->actsPage()->filter('select[name="act"] option')->extract(['value']);

        // Then
        static::assertSame(self::sorted(['', ...ActsPage::ACTS]), self::sorted($offered));
    }

    /**
     * Decision 0066: an act written before acts named their author is an administrator's when it names a bare subject,
     * and of no kind the page can ask for when it names nobody.
     *
     * @param list<string> $acts
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theActsOfAKindOfAuthorAreReadApart(string $by, array $acts): void
    {
        // Given
        $alice = self::user('alice');
        self::record($alice, UserAuthenticated::NAME);
        self::record($alice, CredentialRevoked::NAME, author: new ThePerson());
        self::record($alice, PersonDisabled::NAME, author: new ADirectory('Entra ID'));
        self::record($alice, PersonReadByAnAdministrator::NAME, 'tui-of-mallory', author: new AnAdministrator(new Subject('mallory-subject')));
        self::record($alice, JournalReadByAnAdministrator::NAME, 'tui-of-mallory', author: new AnAdministrator(new Subject('mallory-subject')));
        self::record($alice, CredentialForgotten::NAME, author: new TheHost());
        self::record($alice, AuthenticationFailed::NAME, author: new AnUnauthenticatedCaller());
        self::entityManager()
            ->getConnection()
            ->executeStatement('UPDATE beffroi_journal SET author = ? WHERE act = ?', ['mallory-subject', JournalReadByAnAdministrator::NAME]);
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->actsPage(narrowed: [ActsPage::AUTHOR => $by]);

        // Then
        static::assertSame(self::sorted($acts), self::sorted($page->filter('tbody tr')->extract(['data-act'])));
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'what an administrator did' => ['administrator', [PersonReadByAnAdministrator::NAME, JournalReadByAnAdministrator::NAME]];
        yield 'what the person did' => ['person', [CredentialRevoked::NAME]];
        yield 'what a directory did' => ['directory', [PersonDisabled::NAME]];
        yield 'what the host did' => ['host', [CredentialForgotten::NAME]];
        yield 'what an unauthenticated caller tried' => ['unauthenticated', [AuthenticationFailed::NAME]];
    }

    #[Test]
    public function thePageReadsOnePageOfTheJournalAndSaysWhereTheRestIs(): void
    {
        // Given
        $alice = self::user('alice');
        self::announceRefusals($alice, AskedPage::ROWS + 1);
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(AskedPage::ROWS, $page->filter('tbody tr[data-act]'));
        static::assertSame('/account/acts?page=2', $page->filter('a[data-pager="next"]')->attr('href'));
    }

    #[Test]
    public function theLastPageOfTheJournalHoldsWhatIsLeftOfIt(): void
    {
        // Given
        $alice = self::user('alice');
        self::announceRefusals($alice, AskedPage::ROWS + 1);
        $this->signIn($alice);

        // When
        $page = $this->actsPage(2);

        // Then
        static::assertCount(1, $page->filter('tbody tr[data-act]'));
        static::assertCount(0, $page->filter('a[data-pager="next"]'));
    }

    #[Test]
    public function aPagePastTheLastOneIsTheLastOne(): void
    {
        // Given
        $alice = self::user('alice');
        self::announceRefusals($alice, AskedPage::ROWS + 1);
        $this->signIn($alice);

        // When
        $page = $this->actsPage(99);

        // Then
        static::assertSame('2', $page->filter('nav[data-pager]')->attr('data-pager'));
        static::assertCount(1, $page->filter('tbody tr[data-act]'));
    }

    #[Test]
    public function aJournalThatFitsOnOnePageCarriesNoControl(): void
    {
        // Given
        $alice = self::user('alice');
        self::announce(self::refusedFor($alice));
        $this->signIn($alice);

        // When
        $page = $this->actsPage();

        // Then
        static::assertCount(0, $page->filter('nav[data-pager]'));
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/account/acts');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @param array<string, string> $narrowed what else the table is narrowed to, by the words of its query string
     */
    private function actsPage(?int $number = null, ?string $from = null, ?string $to = null, ?string $language = null, array $narrowed = []): Crawler
    {
        $asked = $narrowed;
        if ($number !== null) {
            $asked['page'] = (string) $number;
        }
        if ($from !== null) {
            $asked['from'] = $from;
        }
        if ($to !== null) {
            $asked['to'] = $to;
        }
        $page = $this->browser->request(
            'GET',
            '/account/acts',
            $asked,
            server: $language === null
                ? []
                : [
                    'HTTP_ACCEPT_LANGUAGE' => $language,
                ],
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    /**
     * The name each row of every page shows, by the act of the row, the pages read until one says there is none after it.
     *
     * @return array<string, string>
     */
    private function rowsOfEveryPage(string $language): array
    {
        $rows = [];
        $number = 1;
        do {
            $page = $this->actsPage($number, language: $language);
            foreach ($page->filter('tbody tr[data-act]') as $row) {
                $crawler = new Crawler($row);
                $rows[self::string($crawler->attr('data-act'))] = $crawler->filter('td')->first()->text();
            }
            ++$number;
        } while ($page->filter('a[data-pager="next"]')->count() > 0);

        return $rows;
    }

    private static function record(
        User $user,
        string $act,
        ?string $client = null,
        ?DateTimeImmutable $occurredAt = null,
        ?AuthorInterface $author = null,
    ): void {
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(new JournalEntry(
                Uuid::v7(),
                $user->tenant,
                $act,
                $occurredAt ?? self::currentSecond(),
                self::context(),
                $user->subject,
                $client,
                $author,
            ));
    }

    private static function day(string $moment): string
    {
        return new DateTimeImmutable($moment)->format('Y-m-d');
    }

    /**
     * @param array<array-key, mixed> $names
     *
     * @return list<string>
     */
    private static function sorted(array $names): array
    {
        $sorted = array_map(self::string(...), array_values($names));
        sort($sorted);

        return $sorted;
    }

    private static function announceRefusals(User $user, int $howMany): void
    {
        $bus = self::service('event.bus', MessageBusInterface::class);
        for ($refused = 0; $refused < $howMany; ++$refused) {
            $bus->dispatch(self::refusedFor($user));
        }
        self::reload();
    }

    private static function refusedFor(User $user): AuthenticationFailed
    {
        return new AuthenticationFailed(
            self::currentSecond(),
            $user->tenant,
            self::context(),
            null,
            AuthenticationFailureReason::InvalidCredential,
            $user->username,
            $user,
        );
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }
}
