<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Architecture §3.2 and §4.3: the cookie side of a session of the core, and the interactions a browser
 * may resume.
 */
final class BrowserSessionTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryInteractionRepository $interactions;

    private BrowserSession $browser;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->interactions = new InMemoryInteractionRepository();
        $this->browser = new BrowserSession($this->sessions, $this->interactions, new MockClock(Fixtures::now()->modify('+1 minute')));
    }

    #[Test]
    public function aRequestWithoutASessionCookieIsNotAuthenticated(): void
    {
        // Given
        $request = Request::create('/authorize');
        $request->setSession(new Session(new MockArraySessionStorage()));

        // When / Then
        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
    }

    #[Test]
    public function aRequestWithoutASessionCookieStartsNoSession(): void
    {
        // Given
        $request = Request::create('/authorize');
        $request->setSession(new Session(new MockArraySessionStorage()));

        // When
        $this->browser->authenticationSession($request, $this->tenant);

        // Then
        static::assertFalse($request->getSession()->isStarted());
    }

    #[Test]
    public function aBoundBrowserIsAuthenticated(): void
    {
        // Given
        $session = $this->session();
        $request = self::request();
        $this->browser->bind($request->getSession(), $session);

        // When / Then
        static::assertSame($session, $this->browser->authenticationSession($request, $this->tenant));
    }

    /**
     * An identifier fixed before the login opens nothing after it.
     */
    #[Test]
    public function bindingRegeneratesTheHttpSessionIdentifier(): void
    {
        // Given
        $request = self::request();
        $before = $request->getSession()->getId();

        // When
        $this->browser->bind($request->getSession(), $this->session());

        // Then
        static::assertNotSame($before, $request->getSession()->getId());
    }

    #[Test]
    public function anEndedSessionIsNotAuthenticated(): void
    {
        // Given
        $session = $this->session();
        $request = self::request();
        $this->browser->bind($request->getSession(), $session);
        $session->end(SessionEnd::User, Fixtures::now());

        // When / Then
        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
    }

    #[Test]
    public function anEndedSessionIsForgotten(): void
    {
        // Given
        $session = $this->session();
        $request = self::request();
        $this->browser->bind($request->getSession(), $session);
        $session->end(SessionEnd::User, Fixtures::now());

        // When
        $this->browser->authenticationSession($request, $this->tenant);

        // Then
        static::assertFalse($request->getSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
    }

    #[Test]
    public function aSessionOfAnotherTenantIsNotThisBrowsers(): void
    {
        // Given
        $request = self::request();
        $this->browser->bind($request->getSession(), $this->session());

        // When / Then
        static::assertNull($this->browser->authenticationSession($request, Fixtures::tenant('other', 'https://other.example')));
    }

    #[Test]
    #[DataProvider('provideBindingsToNothing')]
    public function aBindingToNothingIsNotAuthenticated(string $bound): void
    {
        // Given
        $request = self::request();
        $request->getSession()->set(BrowserSession::AUTHENTICATION_SESSION_KEY, $bound);

        // When / Then
        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBindingsToNothing(): iterable
    {
        yield 'not a UUID' => ['not-a-uuid'];
        yield 'an unknown session' => ['019968a0-0000-7000-8000-000000000000'];
    }

    #[Test]
    public function unbindingInvalidatesTheHttpSession(): void
    {
        // Given
        $request = self::request();
        $this->browser->bind($request->getSession(), $this->session());
        $interaction = $this->interaction();
        $this->browser->begin($request->getSession(), $interaction);

        // When
        $this->browser->unbind($request->getSession());

        // Then
        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));
    }

    #[Test]
    public function anInteractionNotBegunByThisBrowserIsNotPending(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();

        // When / Then
        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));
    }

    #[Test]
    public function anInteractionIsPendingForTheBrowserThatBeganIt(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();

        // When
        $this->browser->begin($request->getSession(), $interaction);

        // Then
        static::assertSame($interaction, $this->browser->pending($request, $this->tenant, $interaction->id));
    }

    #[Test]
    #[DataProvider('provideIdentifiersOfNoPendingInteraction')]
    public function nothingIsPendingForAnIdentifierThatIsNotOneOfThisBrowser(?string $id): void
    {
        // Given
        $request = self::request();
        $this->browser->begin($request->getSession(), $this->interaction());

        // When / Then
        static::assertNull($this->browser->pending($request, $this->tenant, $id));
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideIdentifiersOfNoPendingInteraction(): iterable
    {
        yield 'none' => [null];
        yield 'empty' => [''];
        yield 'unknown' => ['unknown'];
    }

    #[Test]
    public function anInteractionIsNotPendingForAnotherTenant(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();
        $this->browser->begin($request->getSession(), $interaction);

        // When / Then
        static::assertNull($this->browser->pending($request, Fixtures::tenant('other', 'https://other.example'), $interaction->id));
    }

    #[Test]
    public function anInteractionThatIsOverIsNotPendingAnyMore(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();
        $this->browser->begin($request->getSession(), $interaction);

        // When
        $this->browser->forget($request->getSession(), $interaction);

        // Then
        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));
        static::assertFalse($request->getSession()->has(BrowserSession::INTERACTIONS_KEY));
    }

    /**
     * beffroi/saml S-68: an interaction that is over takes with it the address the step of the address kept for a
     * sign-on it never reached, which the HTTP session holds no longer than the interaction.
     */
    #[Test]
    public function anInteractionThatIsOverTakesTheAddressKeptForItWithIt(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();
        $this->browser->begin($request->getSession(), $interaction);
        new LoginAddresses()->sendOn($request->getSession(), $interaction, 'alice@example.org', Fixtures::now());

        // When
        $this->browser->forget($request->getSession(), $interaction);

        // Then
        static::assertSame([], $request->getSession()->get(LoginAddresses::SENT_SESSION_KEY));
    }

    /**
     * One tab per interaction, the oldest forgotten first.
     */
    #[Test]
    public function aBrowserHoldsABoundedNumberOfInteractions(): void
    {
        // Given
        $request = self::request();
        $first = $this->interaction();
        $second = $this->interaction();
        $this->browser->begin($request->getSession(), $first);
        $this->browser->begin($request->getSession(), $second);
        for ($i = 2; $i < BrowserSession::MAX_PENDING_INTERACTIONS; $i++) {
            $this->browser->begin($request->getSession(), $this->interaction());
        }
        $last = $this->interaction();

        // When
        $this->browser->begin($request->getSession(), $last);

        // Then
        static::assertNull($this->browser->pending($request, $this->tenant, $first->id));
        static::assertSame($second, $this->browser->pending($request, $this->tenant, $second->id));
        static::assertSame($last, $this->browser->pending($request, $this->tenant, $last->id));
    }

    #[Test]
    public function aCorruptedListOfInteractionsIsAnEmptyOne(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();
        $request->getSession()->set(BrowserSession::INTERACTIONS_KEY, 'not-a-list');

        // When / Then
        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));
    }

    #[Test]
    public function aListOfInteractionsWithAForeignEntryStillHoldsTheOthers(): void
    {
        // Given
        $interaction = $this->interaction();
        $request = self::request();
        $request->getSession()->set(BrowserSession::INTERACTIONS_KEY, [$interaction->id, 42]);

        // When / Then
        static::assertSame($interaction, $this->browser->pending($request, $this->tenant, $interaction->id));
    }

    /**
     * A request that carries the cookie of the session.
     */
    private static function request(): Request
    {
        $request = Request::create('/authorize');
        $session = new Session(new MockArraySessionStorage());
        $request->setSession($session);
        $request->cookies->set($session->getName(), 'cookie');

        return $request;
    }

    private function session(): AuthenticationSession
    {
        $session = Fixtures::session(Fixtures::user($this->tenant), Fixtures::now());
        $this->sessions->save($session);

        return $session;
    }

    private function interaction(): Interaction
    {
        $request = Requests::authorization(Clients::public($this->tenant));
        $interaction = new Interaction(Secrets::draw(), $this->tenant, $request, null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $this->interactions->save($interaction);

        return $interaction;
    }
}
