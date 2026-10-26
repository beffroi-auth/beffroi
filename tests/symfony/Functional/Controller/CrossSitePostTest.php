<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml, spec/saml.md S-28, the acceptance of issue #739 on the authorization endpoint of OpenID Connect, which
 * a client may post to (OIDC Core §3.1.2.1), and on its end session endpoint (RP-Initiated Logout §2): a request posted
 * from another site reaches the provider without the session cookie, which "SameSite=Lax" keeps from a cross-site post,
 * and is posted again from the origin of the provider, which the cookie accompanies. The browser of these tests is
 * signed in, and a post from another site is played without its cookies (postedFromAnotherSite()).
 */
final class CrossSitePostTest extends BrowserTestCase
{
    private const string POSTED_AGAIN = '/authorize?' . CrossSitePost::MARKER . '=1';

    private const string ENGLISH_BROWSER = 'en-US,en;q=0.9';

    /**
     * A logout the client oidc-demo asks for without a hint, which the user is asked to confirm (RP-Initiated Logout
     * §2).
     */
    private const string LOGOUT = 'client_id=oidc-demo&post_logout_redirect_uri=https%3A%2F%2Fdemo.test%2F&state=after-logout';

    /**
     * What the page says in French: its language, its title, the sentence and the button a browser without scripting
     * is shown.
     */
    private const array FRENCH_PAGE = [
        'fr',
        'Connexion en cours',
        "Votre navigateur arrive d\u{2019}un autre site sans votre session. Utilisez le bouton ci-dessous pour continuer.",
        'Continuer',
    ];

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        parent::setUp();
        $this->session = $this->signIn(self::user('alice'));
    }

    /**
     * The acceptance of issue #739, S-28: a signed-in browser whose client posts its request from another site is
     * answered from the session it holds, without a login, once the page has posted the request again.
     */
    #[Test]
    public function aRequestPostedFromAnotherSiteIsAnsweredFromTheSession(): void
    {
        // Given
        $this->postedFromAnotherSite('/authorize', self::body());

        // When
        $this->postedAgain();

        // Then
        static::assertStringStartsWith(
            'https://demo.test/login/check?code=',
            (string) $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * S-28: what is posted again is the body as it came, pair by pair, in its order, a repeated name included, to the
     * endpoint it was posted to, marked in the query of the action.
     */
    #[Test]
    public function thePagePostsTheBodyAsItCame(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . '&state=second+state&caf%C3%A9=a%20%3C%22value%22%3E');

        // Then
        static::assertSame(
            [
                self::POSTED_AGAIN,
                [...self::pairs(), ['state', 'second state'], ["caf\u{e9}", 'a <"value">']],
            ],
            $this->page(),
        );
    }

    /**
     * S-28: the page sets no cookie, which would replace the one the browser holds.
     */
    #[Test]
    public function thePageSetsNoCookie(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body());

        // Then
        static::assertSame([], $this->browser->getResponse()->headers->getCookies());
    }

    /**
     * S-28, bindings.md section 6.7: the page names its one script by its hash, loads nothing, is never framed and
     * never cached.
     */
    #[Test]
    public function thePageCarriesItsPolicyAndIsNeverCached(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [
                "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; base-uri 'none'; frame-ancestors 'none'",
                true,
                true,
                'no-cache',
                CrossSitePost::SCRIPT,
                1,
            ],
            [
                $response->headers->get('Content-Security-Policy'),
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
                $this->browser->getCrawler()->filter('script')->text(),
                $this->browser->getCrawler()->filter('noscript button[type="submit"]')->count(),
            ],
        );
    }

    /**
     * S-28, architecture §5.7: the page speaks the language the browser asks for ("Accept-Language"), as every page of
     * the interaction plane does.
     */
    #[Test]
    public function thePageSpeaksTheLanguageOfTheBrowser(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body(), ['HTTP_ACCEPT_LANGUAGE' => 'fr']);

        // Then
        static::assertSame(self::FRENCH_PAGE, $this->words());
    }

    /**
     * S-28, OIDC Core §3.1.2.1, architecture §5.7: the "ui_locales" of the posted body comes before the language of
     * the browser, as it does for the pages of the interaction it opens.
     */
    #[Test]
    public function theUiLocalesOfThePostedBodyComeBeforeTheBrowser(): void
    {
        // When
        $this->postedFromAnotherSite(
            '/authorize',
            http_build_query(self::authorizationParameters('oidc-demo', ['ui_locales' => 'fr'])),
            ['HTTP_ACCEPT_LANGUAGE' => self::ENGLISH_BROWSER],
        );

        // Then
        static::assertSame(self::FRENCH_PAGE, $this->words());
    }

    /**
     * S-28: a "ui_locales" the endpoint would refuse leaves the page in the language of the browser, and the refusal
     * to the second post, which reads the body as it came.
     */
    #[Test]
    #[DataProvider('provideUiLocalesTheEndpointRefuses')]
    public function aUiLocalesTheEndpointRefusesLeavesTheLanguageOfTheBrowser(string $tail): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . $tail, ['HTTP_ACCEPT_LANGUAGE' => 'fr']);

        // Then
        static::assertSame(self::FRENCH_PAGE, $this->words());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUiLocalesTheEndpointRefuses(): iterable
    {
        yield 'a value that is no language tag' => ['&ui_locales=en_GB'];
        yield 'a repeated parameter' => ['&ui_locales=en&ui_locales=en'];
    }

    /**
     * S-28: a post that came from the page is not posted a third time, the page posting from the origin of the
     * provider: a browser that still sends no cookie is served as it came, here sent to the login.
     */
    #[Test]
    public function aRequestPostedAgainIsNotPostedAThirdTime(): void
    {
        // When
        $this->postedFromAnotherSite(self::POSTED_AGAIN, self::body(), ['HTTP_SEC_FETCH_SITE' => 'same-origin']);

        // Then
        self::assertServedAsItCame();
    }

    /**
     * S-28, "The marker": a post from another site that forges the marker is posted again as one that does not carry
     * it, so that no post from another site starts an HTTP session, whose cookie would replace the one the browser
     * holds and sign it out of the provider.
     */
    #[Test]
    public function aPostFromAnotherSiteThatForgesTheMarkerIsPostedAgainWithoutASession(): void
    {
        // When
        $this->postedFromAnotherSite(self::POSTED_AGAIN, self::body());

        // Then
        static::assertSame([self::POSTED_AGAIN, []], [$this->page()[0], $this->browser->getResponse()->headers->getCookies()]);
    }

    /**
     * S-28: a logout a client posts from another site is answered with the page that posts it again to the end session
     * endpoint, and no cookie.
     */
    #[Test]
    public function aLogoutPostedFromAnotherSiteIsPostedAgain(): void
    {
        // When
        $this->postedFromAnotherSite('/logout', self::LOGOUT);

        // Then
        static::assertSame(
            ['/logout?' . CrossSitePost::MARKER . '=1', []],
            [$this->page()[0], $this->browser->getResponse()->headers->getCookies()],
        );
    }

    /**
     * S-28, RP-Initiated Logout §2: the logout posted again finds the session the browser holds, and asks its user to
     * confirm, where a browser without one would be told it is signed out already.
     */
    #[Test]
    public function aLogoutPostedAgainAsksTheUserOfTheSession(): void
    {
        // Given
        $this->postedFromAnotherSite('/logout', self::LOGOUT);

        // When
        $this->postedAgain();

        // Then
        static::assertSame(
            [Response::HTTP_OK, 'no_hint'],
            [$this->browser->getResponse()->getStatusCode(), $this->browser->getCrawler()->filter('[data-reason]')->attr('data-reason')],
        );
    }

    /**
     * S-28: a confirmation forged on another site is posted again, and the second post carries no token of the form
     * the browser was given: the session is not ended.
     */
    #[Test]
    public function aConfirmationForgedOnAnotherSiteEndsNothing(): void
    {
        // Given
        $this->postedFromAnotherSite('/logout', self::LOGOUT . '&confirm=yes&_token=forged');

        // When
        $this->postedAgain();

        // Then
        $kept = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($this->session->id) ?? static::fail('The session is gone.');
        static::assertSame([Response::HTTP_FORBIDDEN, false], [$this->browser->getResponse()->getStatusCode(), $kept->hasEnded()]);
    }

    /**
     * S-28: the marker is added after the query the request was posted with, once.
     */
    #[Test]
    public function theMarkerIsAddedAfterTheQueryOfTheRequest(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize?x=y', self::body());

        // Then
        static::assertSame('/authorize?x=y&' . CrossSitePost::MARKER . '=1', $this->page()[0]);
    }

    /**
     * S-28: a post the browser does not say came from another site is served as it came: from this site or a sibling,
     * which the cookie accompanies, and from a browser that sends no "Sec-Fetch-Site" at all.
     */
    #[Test]
    #[DataProvider('provideSitesThatAreNotAnother')]
    public function aPostNotFromAnotherSiteIsServedAsItCame(?string $site): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body(), ['HTTP_SEC_FETCH_SITE' => $site]);

        // Then
        self::assertServedAsItCame();
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideSitesThatAreNotAnother(): iterable
    {
        yield 'same-origin' => ['same-origin'];
        yield 'same-site' => ['same-site'];
        yield 'none' => ['none'];
        yield 'no header' => [null];
    }

    /**
     * S-28: a form posted from another site that carries the session cookie, its body as the other site encoded it, is
     * served from the session at once, and not posted again.
     */
    #[Test]
    public function aPostCarryingTheCookieIsServedDirectly(): void
    {
        // When
        $this->postedFromAnotherSiteWithTheCookie('/authorize', self::body());

        // Then
        static::assertStringStartsWith(
            'https://demo.test/login/check?code=',
            (string) $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * S-28: a body a browser would not post back as it came is served as it came, so that nothing the endpoint reads
     * differs between the first post and the second.
     */
    #[Test]
    #[DataProvider('provideBodiesThatDoNotComeBack')]
    public function aBodyThatWouldNotComeBackIsServedAsItCame(string $tail): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . $tail);

        // Then
        self::assertServedAsItCame();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBodiesThatDoNotComeBack(): iterable
    {
        yield 'a line feed alone' => ['&x=a%0Ab'];
        yield 'a carriage return alone' => ['&x=a%0Db'];
        yield 'a NUL' => ['&x=a%00b'];
        yield 'a delete' => ['&x=a%7Fb'];
        yield 'bytes that are not UTF-8' => ['&x=%C3%28'];
        yield 'a name that is not UTF-8' => ['&%C3%28=b'];
        yield 'a name with a control character' => ['&a%01=b'];
        yield 'a field the browser names its encoding in' => ['&_charset_=b'];
        yield 'a field without a name' => ['&=b'];
    }

    /**
     * S-28: a line break written as CR LF, which a browser reads as a line feed and writes back as CR LF (HTML,
     * "preprocessing the input stream" and "converting an entry list to a list of name-value pairs"), and a tab, which it keeps, are posted again as they came.
     */
    #[Test]
    public function aLineBreakWrittenAsCrLfIsPostedAgain(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . '&login_hint=a%0D%0Ab%09c');

        // Then
        static::assertStringContainsString(
            "<input type=\"hidden\" name=\"login_hint\" value=\"a\r\nb\tc\">",
            self::string($this->browser->getResponse()->getContent()),
        );
    }

    /**
     * S-28: a pair without "=" is the name with an empty value, as PHP reads it, and an empty pair is nothing.
     */
    #[Test]
    public function aPairWithoutValueIsPostedAgainEmpty(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . '&&display');

        // Then
        static::assertSame(['display', ''], $this->page()[1][8] ?? null);
    }

    /**
     * S-28: the media type of a form is read as RFC 9110 §8.3.1 writes it, its case and its parameters aside.
     */
    #[Test]
    #[DataProvider('provideMediaTypesOfAForm')]
    public function aFormIsKnownByItsMediaTypeAlone(string $contentType): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body(), ['CONTENT_TYPE' => $contentType]);

        // Then
        static::assertSame(self::POSTED_AGAIN, $this->page()[0]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMediaTypesOfAForm(): iterable
    {
        yield 'in capitals' => ['Application/X-WWW-Form-Urlencoded'];
        yield 'with a charset' => [' application/x-www-form-urlencoded ; charset=UTF-8'];
    }

    /**
     * S-28: a post whose body is not a form, or is empty, is served as it came.
     */
    #[Test]
    #[DataProvider('provideBodiesThatAreNotForms')]
    public function aBodyThatIsNotAFormIsServedAsItCame(string $contentType, string $body): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', $body, ['CONTENT_TYPE' => $contentType]);

        // Then
        static::assertNotSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBodiesThatAreNotForms(): iterable
    {
        yield 'plain text' => ['text/plain', self::body()];
        yield 'multipart' => ['multipart/form-data; boundary=x', "--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--x--\r\n"];
        yield 'an empty form' => ['application/x-www-form-urlencoded', ''];
    }

    /**
     * S-28: a request from another site that is not a post is a top-level navigation, which a "Lax" cookie
     * accompanies, and is served as it came.
     */
    #[Test]
    public function aGetFromAnotherSiteIsServedAsItCame(): void
    {
        // Given
        $this->browser->getCookieJar()->clear();

        // When
        $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('oidc-demo'),
            [],
            [
                'HTTP_SEC_FETCH_SITE' => 'cross-site',
            ],
        );

        // Then
        self::assertServedAsItCame();
    }

    private function assertServedAsItCame(): void
    {
        static::assertStringStartsWith('/login?interaction=', (string) $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * The form of the page, as a browser reads it: where it posts, and its fields in their order.
     *
     * @return array{string, list<array{string, string}>}
     */
    private function page(): array
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $form = $this->browser->getCrawler()->filter('form')->first();
        $fields = $form->filter('input[type="hidden"]')->each(
            static fn (Crawler $input): array => [(string) $input->attr('name'), (string) $input->attr('value')],
        );

        return [(string) $form->attr('action'), $fields];
    }

    /**
     * The words of the page: its language, its title, and what a browser without scripting reads.
     *
     * @return array{string, string, string, string}
     */
    private function words(): array
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $crawler = $this->browser->getCrawler();

        return [
            (string) $crawler->filter('html')->attr('lang'),
            $crawler->filter('title')->text(),
            $crawler->filter('noscript p')->text(),
            $crawler->filter('noscript button')->text(),
        ];
    }

    private static function body(): string
    {
        return http_build_query(self::authorizationParameters('oidc-demo'));
    }

    /**
     * @return list<array{string, string}>
     */
    private static function pairs(): array
    {
        $pairs = [];
        foreach (self::authorizationParameters('oidc-demo') as $name => $value) {
            $pairs[] = [$name, $value];
        }

        return $pairs;
    }
}
