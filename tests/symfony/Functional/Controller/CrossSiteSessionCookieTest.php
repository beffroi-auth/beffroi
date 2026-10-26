<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Session\SessionFactoryInterface;

/**
 * beffroi/saml, spec/saml.md S-28, "The plane": a request of the interaction plane that a browser sent from another site
 * by a method other than GET or HEAD, which a session cookie set "SameSite=Lax" does not accompany, is answered with no
 * session cookie, whatever the endpoint wrote in the session it started: that cookie would replace the one the browser
 * holds, and any page of another site would sign the browser out of the provider. The browser of these tests is signed
 * in, and a post from another site is played without its cookies (postedFromAnotherSite()).
 */
final class CrossSiteSessionCookieTest extends BrowserTestCase
{
    /**
     * What a page of another site posts: a form whose fields mean nothing to the endpoint it reaches.
     */
    private const string BODY = '_token=forged&SAMLResponse=PHNhbWw%2B&confirm=yes&field=value';

    protected function setUp(): void
    {
        parent::setUp();
        $this->signIn(self::user('alice'));
    }

    /**
     * S-28, "The plane": every endpoint of the interaction plane a browser posts to, posted from another site without
     * the session cookie, answers with no session cookie, the single sign-on service, the authorization endpoint, the
     * single logout service and the end session endpoint by the page that posts the request again, the others by the
     * rule of the plane.
     */
    #[Test]
    #[DataProvider('provideEndpointsOfTheInteractionPlane')]
    public function aPostFromAnotherSiteIsAnsweredWithoutASessionCookie(string $path): void
    {
        // When
        $this->postedFromAnotherSite($path, self::BODY);

        // Then
        static::assertNotContains($this->sessionName(), $this->cookiesSet());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEndpointsOfTheInteractionPlane(): iterable
    {
        yield 'the approvals of the account' => ['/account/approvals'];
        yield 'the archive of the account' => ['/account/archive'];
        yield 'the password of the account' => ['/account/password'];
        yield 'the other sessions of the account' => ['/account/sessions/revoke-others'];
        yield 'the consent' => ['/consent'];
        yield 'the verification of a device' => ['/device'];
        yield 'the choice of a language' => ['/locale'];
        yield 'the login' => ['/login'];
        yield 'the login by a code' => ['/login/code'];
        yield 'the login by a passkey' => ['/login/passkey'];
        yield 'the single sign-on service' => ['/saml/sso'];
        yield 'the single logout service' => ['/saml/slo'];
        yield 'the authorization endpoint' => ['/authorize'];
        yield 'the end session endpoint' => ['/logout'];
    }

    /**
     * S-28, "The plane": the same post from the provider's own origin, which the cookie accompanies, is answered with
     * the session the endpoint started, a browser that holds none being given one.
     */
    #[Test]
    public function aPostFromTheSameOriginWithoutASessionIsGivenOne(): void
    {
        // When
        $this->postedFromAnotherSite('/login', self::BODY, ['HTTP_SEC_FETCH_SITE' => 'same-origin']);

        // Then
        static::assertContains($this->sessionName(), $this->cookiesSet());
    }

    /**
     * S-28, "The plane": a GET from another site is a top-level navigation, which the cookie accompanies, so one that
     * comes without it is a browser that holds no session, and the authorization endpoint starts one for the request
     * that waits for its login.
     */
    #[Test]
    public function aGetFromAnotherSiteWithoutASessionIsGivenOne(): void
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
        static::assertContains($this->sessionName(), $this->cookiesSet());
    }

    /**
     * The name of the session cookie, which the storage of the kernel gives it.
     */
    private function sessionName(): string
    {
        return self::service('session.factory', SessionFactoryInterface::class)->createSession()->getName();
    }

    /**
     * The names of the cookies the last response sets or clears.
     *
     * @return list<string>
     */
    private function cookiesSet(): array
    {
        $names = [];
        foreach ($this->browser->getResponse()->headers->getCookies() as $cookie) {
            $names[] = $cookie->getName();
        }

        return $names;
    }
}
