<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\EndSession\FrontChannelLogout;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Front-Channel Logout 1.0 §2 and §3: which clients of an ended session the logout page loads.
 */
final class FrontChannelLogoutTest extends TestCase
{
    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private FrontChannelLogout $logout;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->logout = new FrontChannelLogout($this->grants);
    }

    /**
     * §2: one frame per client of the session that registered a URI, in the order they signed in.
     */
    #[Test]
    public function eachClientOfTheSessionThatRegisteredAUriGetsAFrame(): void
    {
        // Given
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'second', 'https://second.example/logout'));

        // When
        $page = $this->logout->pageFor([$this->session], null);

        // Then
        static::assertSame(['https://first.example/logout', 'https://second.example/logout'], $page?->frames);
    }

    /**
     * §3: a client that registered nothing is not loaded, and the clients after it still are.
     */
    #[Test]
    public function aClientWithoutAUriIsNotLoaded(): void
    {
        // Given
        $this->signedIn(Clients::public($this->session->tenant, 'silent'));
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'loaded', 'https://loaded.example/logout'));

        // When
        $page = $this->logout->pageFor([$this->session], null);

        // Then
        static::assertSame(['https://loaded.example/logout'], $page?->frames);
    }

    /**
     * A session no such client signed in has no page: the logout answers as it did before this page
     * existed.
     */
    #[Test]
    public function aSessionWithNoSuchClientHasNoPage(): void
    {
        // Given
        $this->signedIn(Clients::public($this->session->tenant, 'silent'));

        // When / Then
        static::assertNull($this->logout->pageFor([$this->session], null));
    }

    /**
     * RP-Initiated Logout §3: where the browser goes once the frames are done is carried by the page.
     */
    #[Test]
    public function thePageCarriesWhereTheBrowserGoesNext(): void
    {
        // Given
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));

        // When
        $page = $this->logout->pageFor([$this->session], 'https://demo.example/?state=x');

        // Then
        static::assertSame('https://demo.example/?state=x', $page?->continueTo);
    }

    /**
     * §2, beffroi/saml S-35: a logout that ended several sessions loads the clients of each, session by
     * session.
     */
    #[Test]
    public function theClientsOfEverySessionEndedGetTheirFrames(): void
    {
        // Given
        $second = Fixtures::session($this->session->user);
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'second', 'https://second.example/logout'), $second);

        // When
        $page = $this->logout->pageFor([$this->session, $second], null);

        // Then
        static::assertSame(['https://first.example/logout', 'https://second.example/logout'], $page?->frames);
    }

    /**
     * A client that obtained a token in the session: a grant of the session, exchanged.
     */
    private function signedIn(Client $client, ?AuthenticationSession $session = null): void
    {
        $grant = Tokens::code('code-of-' . $client->registration->clientId, $client, $session ?? $this->session, Fixtures::now());
        $grant->consume(Fixtures::now());
        $this->grants->save($grant);
    }
}
