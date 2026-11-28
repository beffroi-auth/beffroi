<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\SessionsPage;
use function array_map;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class AccountSessionsTest extends BrowserTestCase
{
    use TokensOfASession;

    #[Test]
    public function thePageListsTheSessionsOpenInTheirName(): void
    {
        // Given
        $alice = self::user('alice');
        $current = $this->signIn($alice);
        self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $page = $this->sessionsPage();

        // Then
        static::assertSame('2', $page->filter('table[data-sessions]')->attr('data-sessions'));
        static::assertSame('yes', $page->filter('tr[data-session="' . $current->id . '"]')->attr('data-current'));
    }

    #[Test]
    public function endingAnotherSessionEndsItAndSaysSoOnce(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $other = self::session($alice, self::currentSecond()->modify('-1 hour'));
        $token = $this->token($other);

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke', ['_token' => $token]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/account/sessions', $response->headers->get('Location'));
        static::assertTrue(self::reread($other)->hasEnded());
        static::assertSame(SessionEnd::User, self::reread($other)->endedBy);
        static::assertCount(1, self::events(AuthenticationSessionEnded::class));
    }

    #[Test]
    public function endingASessionRevokesTheTokensIssuedUnderIt(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $other = self::session($alice, self::currentSecond()->modify('-1 hour'));
        $tokens = self::tokensIssuedIn($other);
        $token = $this->token($other);

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke', ['_token' => $token]);

        // Then
        self::assertTheTokensAreRevoked($tokens);
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function theTokensTheEndOfASessionRevokedAreAnActOfThePersonThatNamesTheClient(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $other = self::session($alice, self::currentSecond()->modify('-1 hour'));
        self::tokensIssuedIn($other);
        $token = $this->token($other);

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke', ['_token' => $token]);

        // Then
        static::assertEquals([[$alice->subject->value, 'oidc-demo', new ThePerson()]], array_map(
            static fn (JournalEntry $act): array => [$act->subject?->value, $act->client, $act->author],
            self::entityManager()->getRepository(JournalEntry::class)->findBy(['act' => SessionTokensRevoked::NAME]),
        ));
    }

    #[Test]
    public function endingTheirOwnSessionSignsThemOut(): void
    {
        // Given
        $current = $this->signIn(self::user('alice'));
        $token = $this->token($current);

        // When
        $crawler = $this->browser->request('POST', '/account/sessions/' . $current->id . '/revoke', ['_token' => $token]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('yes', $crawler->filter('[data-logged-out]')->attr('data-logged-out'));
        static::assertTrue(self::reread($current)->hasEnded());
    }

    #[Test]
    public function aBrowserWhoseSessionItEndedIsAskedToSignInAgain(): void
    {
        // Given
        $current = $this->signIn(self::user('alice'));
        $token = $this->token($current);
        $this->browser->request('POST', '/account/sessions/' . $current->id . '/revoke', ['_token' => $token]);

        // When
        $crawler = $this->browser->request('GET', '/account/sessions');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function theSessionOfSomebodyElseIsNotFound(): void
    {
        // Given
        $current = $this->signIn(self::user('alice'));
        $token = $this->token($current);
        $theirs = self::session(self::user('bob', 'bob-subject'));

        // When
        $this->browser->request('POST', '/account/sessions/' . $theirs->id . '/revoke', ['_token' => $token]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::reread($theirs)->hasEnded());
    }

    #[Test]
    public function aSessionEndedWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $other = self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke');

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::reread($other)->hasEnded());
        static::assertSame([], self::events(AuthenticationSessionEnded::class));
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function endingEveryOtherSessionLeavesTheOneBeingReadFrom(): void
    {
        // Given
        $alice = self::user('alice');
        $current = $this->signIn($alice);
        $elsewhere = self::session($alice, self::currentSecond()->modify('-1 hour'));
        $again = self::session($alice, self::currentSecond()->modify('-2 hours'));

        // When
        $this->endEveryOther();

        // Then
        static::assertTrue(self::reread($elsewhere)->hasEnded());
        static::assertTrue(self::reread($again)->hasEnded());
        static::assertFalse(self::reread($current)->hasEnded());
    }

    #[Test]
    public function eachSessionEndedThatWayIsSaidOnce(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::session($alice, self::currentSecond()->modify('-1 hour'));
        self::session($alice, self::currentSecond()->modify('-2 hours'));

        // When
        $this->endEveryOther();

        // Then
        static::assertCount(2, self::events(AuthenticationSessionEnded::class));
    }

    #[Test]
    public function aPersonSignedInNowhereElseIsOfferedNothing(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->sessionsPage();

        // Then
        static::assertCount(0, $page->filter('form[data-sessions="revoke-others"]'));
    }

    #[Test]
    public function endingEveryOtherSessionWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $elsewhere = self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $this->browser->request('POST', '/account/sessions/revoke-others', []);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::reread($elsewhere)->hasEnded());
    }

    /**
     * Architecture §3.5
     */
    #[Test]
    public function theLineSaysTheBrowserAndNotTheWholeUserAgent(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $page = $this->sessionsPage();

        // Then
        $agent = $page->filter('tr[data-session] span[data-user-agent]');
        static::assertSame('Firefox on Linux', $agent->text());
        static::assertStringContainsString('X11; Linux x86_64', self::string($agent->attr('title')));
        static::assertSame('Place unknown', $page->filter('tr[data-session] span[data-place="unknown"]')->text());
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function thePeriodNarrowsTheSessionsToTheDaysItNames(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $page = $this->browser->request('GET', '/account/sessions?to=' . self::currentSecond()->modify('-1 day')->format('Y-m-d'));

        // Then
        static::assertCount(0, $page->filter('tbody tr[data-session]'));
        static::assertCount(1, $page->filter('tbody tr[data-empty]'));
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    #[DataProvider('provideVisits')]
    public function theDaysOfTheLastVisitAreTheOnesRead(string $from, string $to, bool $readsTheCurrent): void
    {
        // Given
        $alice = self::user('alice');
        $current = $this->signIn($alice);
        $earlier = self::anEarlierSession($alice, [AuthenticationMethod::password()]);

        // When
        $page = $this->browser->request('GET', '/account/sessions', [
            SessionsPage::SEEN_FROM => self::currentSecond()->modify($from)->format('Y-m-d'),
            SessionsPage::SEEN_TO => self::currentSecond()->modify($to)->format('Y-m-d'),
        ]);

        // Then
        static::assertSame([(string) ($readsTheCurrent ? $current->id : $earlier->id)], $page->filter('tbody tr[data-session]')->extract(['data-session']));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function provideVisits(): iterable
    {
        yield 'today' => ['now', 'now', true];
        yield 'the days before' => ['-1 week', '-2 days', false];
    }

    /**
     * RFC 8176 §2
     */
    #[Test]
    public function theMethodAskedForIsTheOnlyOneRead(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $proved = self::anEarlierSession($alice, [new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY)]);

        // When
        $page = $this->browser->request('GET', '/account/sessions', [
            SessionsPage::PROOF => AuthenticationMethod::HARDWARE_KEY,
        ]);

        // Then
        static::assertSame([(string) $proved->id], $page->filter('tbody tr[data-session]')->extract(['data-session']));
    }

    /**
     * RFC 8176 §2
     */
    #[Test]
    public function theMethodsOfferedAreThoseTheSessionsOfThePersonProved(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        self::anEarlierSession($alice, [new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY)]);

        // When
        $page = $this->sessionsPage();

        // Then
        static::assertSame(
            ['', AuthenticationMethod::HARDWARE_KEY, AuthenticationMethod::PASSWORD],
            $page->filter('select[name="proof"] option')->extract(['value']),
        );
    }

    private function endEveryOther(): void
    {
        $token = self::string(
            $this->sessionsPage()->filter('form[data-sessions="revoke-others"] input[name="_token"]')->attr('value'),
        );
        $this->browser->request('POST', '/account/sessions/revoke-others', [
            '_token' => $token,
        ]);
    }

    private function sessionsPage(): Crawler
    {
        return $this->browser->request('GET', '/account/sessions');
    }

    private function token(AuthenticationSession $session): string
    {
        return self::string(
            $this->sessionsPage()
                ->filter('tr[data-session="' . $session->id . '"] input[name="_token"]')
                ->attr('value'),
        );
    }

    /**
     * A session opened three days ago and kept alive since, last seen on the day it was opened.
     *
     * @param non-empty-list<AuthenticationMethod> $proved
     */
    private static function anEarlierSession(User $user, array $proved): AuthenticationSession
    {
        $openedAt = self::currentSecond()->modify('-3 days');
        $proofs = AuthenticationProofs::of($proved[0], $openedAt);
        foreach ($proved as $method) {
            $proofs = $proofs->with($method, $openedAt);
        }
        $session = new AuthenticationSession(Uuid::v7(), $user->tenant, $user, $openedAt, $proofs, self::context($openedAt), $openedAt->modify('+12 hours'));
        $session->touch(self::context($openedAt->modify('+1 hour')), self::currentSecond()->modify('+1 day'));
        self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->save($session);
        self::reload();

        return $session;
    }

    private static function reread(AuthenticationSession $session): AuthenticationSession
    {
        $reread = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $reread);

        return $reread;
    }
}
