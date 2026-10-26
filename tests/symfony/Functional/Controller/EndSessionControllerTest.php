<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function array_filter;
use function base64_encode;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use function count;
use const DATE_ATOM;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC RP-Initiated Logout 1.0 §2 to §4 and architecture §4.9, §5.2: the end session endpoint, its
 * confirmation page, and what the browser holds afterwards.
 */
final class EndSessionControllerTest extends BrowserTestCase
{
    use TokensOfASession;

    /**
     * §4: a logout request from a browser that holds no session is honoured as is.
     */
    #[Test]
    public function aBrowserWithoutASessionIsLoggedOutAlready(): void
    {
        // When
        $this->browser->request('GET', '/logout');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertStringContainsString('data-logged-out="yes"', self::string($response->getContent()));
    }

    /**
     * §2: without a hint the user is asked; the confirmation form carries the parameters over.
     */
    #[Test]
    public function withoutAHintTheUserIsAsked(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('no_hint', $crawler->filter('[data-reason]')->attr('data-reason'));
        static::assertSame('after-logout', $crawler->filter('input[name="state"]')->attr('value'));
        static::assertSame('oidc-demo', $crawler->filter('input[name="client_id"]')->attr('value'));
    }

    /**
     * §2, §3: on yes the session ends and the browser goes where the client asked, with the state.
     */
    #[Test]
    public function aConfirmedLogoutEndsTheSessionAndRedirectsWithTheState(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        $crawler = $this->confirmationPage();

        // When
        $this->browser->submit($crawler->selectButton('Sign out')->form());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://demo.test/?state=after-logout', $response->headers->get('Location'));
        $ended = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertTrue($ended->hasEnded());
    }

    /**
     * After the logout the browser is not bound to anything any more: an authorization request needs a login.
     */
    #[Test]
    public function aLoggedOutBrowserNeedsALoginAgain(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->browser->submit($this->confirmationPage()->selectButton('Sign out')->form());

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));

        // Then
        static::assertStringStartsWith('/login?interaction=', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * §2: the user may refuse; nothing ends and the browser goes nowhere.
     */
    #[Test]
    public function theUserMayStaySignedIn(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        $crawler = $this->confirmationPage();

        // When
        $this->browser->submit($crawler->selectButton('Stay signed in')->form());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-logged-out="no"', self::string($response->getContent()));
        $kept = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertFalse($kept->hasEnded());
    }

    /**
     * §2: a hint that names the session the browser holds ends it without a question, the way
     * oidc_login sends it: id_token_hint and post_logout_redirect_uri, nothing else.
     */
    #[Test]
    public function aHintNamingTheSessionEndsItWithoutAQuestion(): void
    {
        // Given
        $idToken = $this->idTokenOf(self::user('alice'));

        // When
        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://demo.test/', $response->headers->get('Location'));
        self::assertInteractionHeaders($response);
    }

    /**
     * Issue #741, decision 0006: the tokens issued under the session the endpoint ends are revoked with it,
     * on the event every end of a session announces and not by the endpoint itself.
     */
    #[Test]
    public function aLogoutRevokesTheTokensIssuedUnderTheSession(): void
    {
        // Given
        self::signingKey();
        $session = $this->signIn(self::user('alice'));
        $tokens = self::tokensIssuedIn($session);
        $idToken = $this->idTokenOfTheBoundBrowser();

        // When
        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        // Then
        self::assertTheTokensAreRevoked($tokens);
    }

    /**
     * Issue #741, S-25, RFC 6749 §5.2: a refresh token saved under the session after its tokens were revoked, which a
     * refresh in flight when the session ended does, is refused at its first use, and that use revokes what the
     * session still holds, dated by the end of the session, once the event it announces is handled.
     */
    #[Test]
    public function aRefreshTokenSavedAfterTheRevocationIsRevokedAtItsFirstUse(): void
    {
        // Given
        self::signingKey();
        $session = $this->signIn(self::user('alice'));
        $idToken = $this->idTokenOfTheBoundBrowser();
        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);
        self::reload();
        $late = self::tokensIssuedIn(self::sessions()->find($session->id) ?? static::fail('The session is gone.'))['refresh'];

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $late,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        // Then
        $error = self::json($this->browser->getResponse())['error'] ?? null;
        self::reload();
        $refreshTokens = self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class);
        static::assertSame(
            [
                'the error' => 'invalid_grant',
                'the refresh tokens of the session left active' => 0,
                'the late one revoked at' => self::sessions()->find($session->id)?->endedAt?->format(DATE_ATOM),
            ],
            [
                'the error' => $error,
                'the refresh tokens of the session left active' => count(array_filter(
                    $refreshTokens->findBySession($session->id),
                    static fn (RefreshToken $token): bool => ! $token->isRevoked(),
                )),
                'the late one revoked at' => $refreshTokens->findByTokenHash(DrawnSecret::digestOf($late))?->revokedAt?->format(DATE_ATOM),
            ],
        );
    }

    /**
     * §2: a hint of the same user but of another session asks first.
     */
    #[Test]
    public function aHintOfAnotherSessionAsksFirst(): void
    {
        // Given
        $user = self::user('alice');
        $idToken = $this->idTokenOf($user);
        $this->signIn($user);

        // When
        $crawler = $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('different_session', $crawler->filter('[data-reason]')->attr('data-reason'));
    }

    /**
     * OIDC Core §10.1.1 and architecture §3.3: a hint signed before a rotation still proves the session
     * while its key is retiring; what oidc_login sends after a rotation ends the session without a
     * question.
     */
    #[Test]
    public function aHintSignedByARetiringKeyEndsTheSessionWithoutAQuestion(): void
    {
        // Given
        $previous = self::signingKey();
        $idToken = $this->idTokenOf(self::user('alice'));
        self::signingKey();

        // When
        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame($previous->kid, self::kidOf($idToken));
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://demo.test/', $response->headers->get('Location'));
    }

    /**
     * §2, §6: a hint signed by a retired key is an invalid hint; the provider asks the user instead of
     * failing, and drops the redirect the hint came with.
     */
    #[Test]
    public function aHintSignedByARetiredKeyAsksTheUser(): void
    {
        // Given
        $previous = self::signingKey();
        $idToken = $this->idTokenOf(self::user('alice'));
        self::signingKey();
        self::retireKey($previous);

        // When
        $crawler = $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertSame('invalid_hint', $crawler->filter('[data-reason]')->attr('data-reason'));
    }

    /**
     * §2: on yes the session ends; §3: the browser goes nowhere, the hint having identified no client.
     */
    #[Test]
    public function aConfirmedLogoutWithAHintSignedByARetiredKeyEndsTheSessionAndRedirectsNowhere(): void
    {
        // Given
        $previous = self::signingKey();
        $session = $this->signIn(self::user('alice'));
        $idToken = $this->idTokenOfTheBoundBrowser();
        self::signingKey();
        self::retireKey($previous);
        $crawler = $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://demo.test/',
        ]);

        // When
        $this->browser->submit($crawler->selectButton('Sign out')->form());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-logged-out="yes"', self::string($response->getContent()));
        $ended = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertTrue($ended->hasEnded());
    }

    /**
     * §4: a request found wrong is shown to the user, never redirected.
     */
    #[Test]
    public function anUnregisteredRedirectUriIsShownToTheUser(): void
    {
        // When
        $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://attacker.example/',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * The confirmation form is protected against cross-site submission: a forged "yes" ends nothing.
     */
    #[Test]
    public function aForgedConfirmationEndsNothing(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));

        // When
        $this->browser->request('POST', '/logout', [
            'confirm' => 'yes',
            '_token' => 'forged',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        $kept = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertFalse($kept->hasEnded());
    }

    /**
     * The confirmation page of a logout asked by oidc-demo without a hint, with a state.
     */
    private function confirmationPage(): Crawler
    {
        return $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);
    }

    /**
     * An ID token issued to oidc-demo for a session of the user, obtained through the code flow, which
     * leaves the browser bound to that session. The tenant signs with the key active at that moment.
     */
    private function idTokenOf(User $user): string
    {
        if (self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findActive(self::tenant(), Algorithms::rs256()) === null) {
            self::signingKey();
        }
        $this->signIn($user);

        return $this->idTokenOfTheBoundBrowser();
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class);
    }

    /**
     * An ID token issued to oidc-demo for the session the browser is bound to.
     */
    private function idTokenOfTheBoundBrowser(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );
        $tokens = self::json($this->browser->getResponse());
        static::assertIsString($tokens['id_token'] ?? null, self::string($this->browser->getResponse()->getContent()));

        return $tokens['id_token'];
    }
}
