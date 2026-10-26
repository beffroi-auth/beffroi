<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #450, architecture §5.2: a person sees the sessions open in their name and ends one. What ending
 * one does to the relying parties is the end of a session of the core, said once
 * (AuthenticationSessionEnded), which is what the back-channel logout reads; the command that ends one
 * calls the same use case.
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

    /**
     * Issue #741: the tokens issued under a session a person ends here are revoked with it, as those of a
     * session the end session endpoint ends are, the revocation being made on the end and not on the request
     * that asked for it.
     */
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
     * Architecture §5.2: one act for what somebody would otherwise do a line at a time, and the browser
     * they are reading from stays signed in.
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

    /**
     * Each one leaves the trace every ended session leaves, which is what the back-channel reads.
     */
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

    /**
     * A person signed in nowhere else is offered nothing: there is nothing to end.
     */
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
     * Architecture §3.5: what a person reads of where a session came from is the browser and the system,
     * not the sixteen tokens their browser sent, which stay in the document for whoever wants them. A
     * place nothing could put on a map is unknown and never absent.
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
     * Architecture §5.2: every table of this plane is read over the stretch of time that was asked for,
     * and a table that holds nothing of those days keeps its head and says so.
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
     * The act is offered at the head of the page, and what it posts is the token that page renders.
     */
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

    private static function reread(AuthenticationSession $session): AuthenticationSession
    {
        $reread = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $reread);

        return $reread;
    }
}
