<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\EndSession\FrontChannelLogoutRenderer;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\LogoutChainCookie;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Beffroi\Bundle\Saml\SamlPostPage;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\EndSession\FrontChannelLogout;
use Beffroi\Oidc\Port\LoggedInClientsInterface;
use Beffroi\Saml\Application\SingleLogout\ProviderLogout;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\FixedSalt;
use Beffroi\Saml\Tests\Fixture\InMemoryLogoutChains;
use Beffroi\Saml\Tests\Fixture\InMemorySessionParticipations;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutNotifier;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutResponder;
use function array_map;
use function http_build_query;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Uid\Uuid;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

/**
 * beffroi/saml, spec/saml.md S-32, S-35: a chain whose first step is resumed at once, no client of OpenID Connect of
 * its sessions being loaded by the page of Front-Channel Logout 1.0, and meets a KMS that does not answer sends the
 * browser to the route that resumes it, with its reference and the cookie of the chain, where the step is played
 * again.
 */
final class LogoutChainPagesTest extends TestCase
{
    private const string CONTINUE = 'https://op.test' . IdentityProviderRoutes::SINGLE_LOGOUT_CONTINUE_PATH;

    private const string SERVICE_PROVIDER = 'https://sp.example.org/saml';

    private Tenant $tenant;

    private RecordingSignOutNotifier $notifier;

    private ProviderLogout $logout;

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $chains = new InMemoryLogoutChains();
        $this->notifier = new RecordingSignOutNotifier();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $participations = new InMemorySessionParticipations();
        $this->session = Fixtures::session(Fixtures::user($this->tenant));
        $sessions->save($this->session);
        $participations->record(new SessionParticipation(Uuid::v7(), $this->tenant, $this->session, self::SERVICE_PROVIDER, Fixtures::now()));
        $this->logout = new ProviderLogout(
            $participations,
            $chains,
            $sessions,
            $this->notifier,
            new RecordingSignOutResponder(),
            new FixedSalt(),
            new FixedEndpoints(),
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * S-32, S-35: the first step resumed at once meets a KMS that does not answer: the browser is sent to the route
     * that resumes the chain, with its reference.
     */
    #[Test]
    public function aFirstStepThatMeetsAnOutageSendsTheBrowserToTheRouteThatResumesTheChain(): void
    {
        // Given
        $started = $this->started();
        $this->notifier->failure = new KmsUnavailableException('The KMS did not answer.');

        // When
        $response = $this->pages()->started($this->tenant, $started);

        // Then
        static::assertSame(
            [Response::HTTP_FOUND, self::CONTINUE . '?' . http_build_query([IdentityProviderRoutes::CHAIN_PARAMETER => $started->reference])],
            [$response->getStatusCode(), $response->headers->get('Location')],
        );
    }

    /**
     * S-32, S-35: the redirection to the route that resumes the chain after an outage gives the browser the cookie of
     * the chain, without which that route resumes nothing.
     */
    #[Test]
    public function aFirstStepThatMeetsAnOutageGivesTheBrowserTheCookieOfTheChain(): void
    {
        // Given
        $started = $this->started();
        $this->notifier->failure = new KmsUnavailableException('The KMS did not answer.');

        // When
        $response = $this->pages()->started($this->tenant, $started);

        // Then
        static::assertSame(
            [[LogoutChainCookie::NAME, $started->secret->value]],
            array_map(static fn (Cookie $cookie): array => [$cookie->getName(), $cookie->getValue()], $response->headers->getCookies()),
        );
    }

    /**
     * S-32: a first step resumed at once that fails for another reason than an outage of the KMS fails as it came.
     */
    #[Test]
    public function aFirstStepThatFailsOtherwiseFailsAsItCame(): void
    {
        // Given
        $started = $this->started();
        $this->notifier->failure = new RuntimeException('The salt of the tenant can neither be read nor drawn.');

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The salt of the tenant can neither be read nor drawn.');

        // When
        $this->pages()->started($this->tenant, $started);
    }

    private function started(): LogoutChainStarted
    {
        $started = $this->logout->begin($this->tenant, [$this->session], null, null);
        static::assertInstanceOf(LogoutChainStarted::class, $started);

        return $started;
    }

    private function pages(): LogoutChainPages
    {
        $urls = static::createStub(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturnCallback(
            static fn (string $route, array $parameters): string => self::CONTINUE . '?' . http_build_query($parameters),
        );
        $pages = new InteractionPages(new Environment(new ArrayLoader()), $urls);

        return new LogoutChainPages(
            $this->logout,
            new FrontChannelLogoutRenderer(new FrontChannelLogout(static::createStub(LoggedInClientsInterface::class)), $pages),
            $pages,
            new SamlPostPage($pages),
            $urls,
            new FormTarget(),
            new LogoutChainCookie(new MockClock(Fixtures::now())),
        );
    }
}
