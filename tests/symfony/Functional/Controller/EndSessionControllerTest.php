<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_filter;
use function array_map;
use function base64_encode;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use function count;
use const DATE_ATOM;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * OIDC RP-Initiated Logout 1.0 §2 to §4, Architecture §4.9, §5.2
 */
final class EndSessionControllerTest extends BrowserTestCase
{
    use TokensOfASession;

    /**
     * RP-Initiated Logout 1.0 §4
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
     * RP-Initiated Logout 1.0 §2
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
     * RP-Initiated Logout 1.0 §2
     */
    #[Test]
    public function aRequestThatNamesNoClientIsAttributedToNoApplication(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/logout');

        // Then
        static::assertSame('You are signed in as alice. Do you want to sign out?', $crawler->filter('[data-reason]')->text());
    }

    /**
     * RP-Initiated Logout 1.0 §2, §3
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
     * RP-Initiated Logout 1.0 §2
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
     * RP-Initiated Logout 1.0 §2
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
     * Decision 0006
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
     * beffroi/saml S-25, RFC 6749 §5.2
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
     * Decision 0022, beffroi/saml S-25
     */
    #[Test]
    public function aLateRefreshTokenRevokedAtItsFirstUseIsAnnouncedByNoAct(): void
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
        self::forgetEvents();

        // When
        $this->refresh($late);

        // Then
        static::assertSame([], self::events(SessionTokensRevoked::class));
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theEndHandledAfterARefreshNamesTheAdministratorWhoEndedTheSession(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        $tokens = self::tokensIssuedIn($session);
        $ended = self::sessions()->find($session->id) ?? static::fail('The session is gone.');
        $ended->end(SessionEnd::Administrator, self::currentSecond());
        self::sessions()->save($ended);
        self::reload();
        $this->refresh($tokens['refresh']);
        self::forgetEvents();

        // When
        self::service('event.bus', MessageBusInterface::class)
            ->dispatch(new AuthenticationSessionEnded(
                $ended,
                self::currentSecond(),
                self::context(),
                new Subject('administrator-subject'),
            ));

        // Then
        static::assertSame([['oidc-demo', 1, 1, 'administrator-subject']], array_map(
            static fn (SessionTokensRevoked $act): array => [$act->clientId, $act->refreshTokens, $act->accessTokens, $act->author()?->value],
            self::events(SessionTokensRevoked::class),
        ));
    }

    /**
     * RP-Initiated Logout 1.0 §2
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
     * OIDC Core §10.1.1, Architecture §3.3
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
     * RP-Initiated Logout 1.0 §2, §6
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
     * RP-Initiated Logout 1.0 §2, §3
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
     * RP-Initiated Logout 1.0 §4
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

    private function confirmationPage(): Crawler
    {
        return $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);
    }

    private function idTokenOf(User $user): string
    {
        if (self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findActive(self::tenant(), Algorithms::rs256()) === null) {
            self::signingKey();
        }
        $this->signIn($user);

        return $this->idTokenOfTheBoundBrowser();
    }

    private function refresh(string $refreshToken): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class);
    }

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
