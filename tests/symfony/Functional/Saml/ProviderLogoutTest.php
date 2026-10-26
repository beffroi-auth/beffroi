<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\LogoutChainCookie;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Bundle\Tests\Functional\Key\KmsOutage;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutRequest;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Writing\Signing;
use Closure;
use function http_build_query;
use function parse_url;
use function sprintf;
use function strlen;
use const PHP_URL_HOST;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use const PHP_URL_SCHEME;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\BrowserKit\Cookie as BrowserCookie;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md section 6.6, the acceptance of issue #735: the service provider https://sp.example.org/saml
 * of the configuration of the test signs the user in over HTTP-Redirect, then the provider starts the logout, at its
 * end session endpoint, on the page of the account, or for another service provider of the session: the service
 * provider is sent a LogoutRequest saml2-model accepts under the certificate the tenant publishes, the session of the
 * provider having ended before, and its LogoutResponse ends the chain where the starter of the logout said.
 */
final class ProviderLogoutTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = ServiceProviderDocuments::SIGNED;

    private const string ASSERTION_CONSUMER = ServiceProviderDocuments::SIGNED . '/acs';

    private const string SINGLE_LOGOUT = ServiceProviderDocuments::SIGNED . '/slo';

    /**
     * The second service provider of the session, the SimpleSAMLphp one the configuration of the test declares, its
     * metadata here a document of the test key "idp" of saml2-model, so that its answers can be signed.
     */
    private const string OTHER = 'https://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp';

    private const string OTHER_SINGLE_LOGOUT = 'https://default-sp.test/slo';

    private const string SINGLE_SIGN_ON = 'https://op.test/saml/sso';

    private const string IDENTITY_PROVIDER_SINGLE_LOGOUT = 'https://op.test/saml/slo';

    private const string LOGOUT_REQUEST_ID = '_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b';

    private const string AFTER_LOGOUT = 'https://demo.test/?state=after-logout';

    /**
     * The policy of the page that posts a form (spec/saml.md section 6.8), its "form-action" left to the test.
     */
    private const string POLICY = "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; form-action %s; base-uri 'none'; frame-ancestors 'none'";

    private User $alice;

    private KmsOutage $kms;

    protected function setUp(): void
    {
        $this->kms = new KmsOutage();
        parent::setUp();
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(0, $tester->getStatusCode(), $tester->getDisplay());
        $this->accept(self::SERVICE_PROVIDER, ServiceProviderDocuments::exampleOrgWithSingleLogout([
            [Binding::HttpRedirect->value, self::SINGLE_LOGOUT, null],
        ]));
        $this->alice = self::userWithPassword('alice', 'correct horse battery staple');
    }

    protected function configureContainer(): Closure
    {
        return $this->kms->takeOver(...);
    }

    /**
     * The acceptance of issue #735, S-29, S-31: a logout at the end session endpoint, confirmed, sends the browser to
     * the single logout service of the service provider with a LogoutRequest the service provider accepts under the
     * certificate the tenant publishes, naming the NameID of the assertion and its SessionIndex.
     */
    #[Test]
    public function aLogoutAtTheEndSessionEndpointTellsTheServiceProvider(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->logOut();

        // Then
        $request = $this->told(self::SINGLE_LOGOUT)->request;
        $nameId = $assertion->assertion->nameId;
        static::assertEquals(
            [new NameId($nameId->value, $nameId->format, $nameId->nameQualifier, $nameId->spNameQualifier), [self::sessionIndex($assertion)]],
            [$request->nameId, $request->sessionIndexes],
        );
    }

    /**
     * The acceptance of issue #735, S-29: the session of the provider has ended before the service provider answers,
     * whatever it answers, or if it never does.
     */
    #[Test]
    public function theSessionHasEndedBeforeTheServiceProviderAnswers(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->logOut();

        // Then
        static::assertSame(
            [Response::HTTP_FOUND, true],
            [$this->browser->getResponse()->getStatusCode(), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-33, S-34: the LogoutResponse of the service provider, signed with the key of its metadata, ends the chain at
     * the post_logout_redirect_uri of the client, with its state.
     */
    #[Test]
    public function theAnswerOfTheServiceProviderEndsTheChainWhereTheClientAsked(): void
    {
        // Given
        $this->signedOn();
        $this->logOut();
        $told = $this->told(self::SINGLE_LOGOUT);

        // When
        $this->browser->request('GET', self::pathOf($this->answered($told, self::SERVICE_PROVIDER, 'sp')));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame([Response::HTTP_FOUND, self::AFTER_LOGOUT], [$response->getStatusCode(), $response->headers->get('Location')]);
    }

    /**
     * S-32, S-33, M-11: the same answer presented again is refused, with the page of a refusal.
     */
    #[Test]
    public function theSameAnswerIsRefusedTheSecondTime(): void
    {
        // Given
        $this->signedOn();
        $this->logOut();
        $answer = self::pathOf($this->answered($this->told(self::SINGLE_LOGOUT), self::SERVICE_PROVIDER, 'sp'));
        $this->browser->request('GET', $answer);

        // When
        $this->browser->request('GET', $answer);

        // Then
        $this->assertRefused();
    }

    /**
     * S-33: an answer to a request no chain waits for is refused, with the page of a refusal.
     */
    #[Test]
    public function anAnswerToNoRequestIsRefused(): void
    {
        // Given
        $this->signedOn();
        $response = new LogoutResponse(
            '_2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c',
            self::currentSecond(),
            new Issuer(self::SERVICE_PROVIDER),
            self::IDENTITY_PROVIDER_SINGLE_LOGOUT,
            self::LOGOUT_REQUEST_ID,
            new Status(StatusCode::Success),
        );

        // When
        $this->browser->request('GET', self::pathOf(new RedirectSender()->logoutResponse($response, self::signing('sp'))));

        // Then
        $this->assertRefused();
    }

    /**
     * S-29: the end of the session of the browser from the page of the account starts the same chain.
     */
    #[Test]
    public function aLogoutFromThePageOfTheAccountTellsTheServiceProvider(): void
    {
        // Given
        $assertion = $this->signedOn();
        $token = self::string(
            $this->browser
                ->request('GET', '/account/sessions')
                ->filter('tr[data-session="' . self::sessionIndex($assertion) . '"] input[name="_token"]')
                ->attr('value'),
        );

        // When
        $this->browser->request('POST', '/account/sessions/' . self::sessionIndex($assertion) . '/revoke', ['_token' => $token]);

        // Then
        static::assertSame([self::sessionIndex($assertion)], $this->told(self::SINGLE_LOGOUT)->request->sessionIndexes);
    }

    /**
     * S-35: a client of OpenID Connect of the session that registered a front-channel logout URI is given the page of
     * Front-Channel Logout 1.0 first, which resumes the chain at the route of the provider.
     */
    #[Test]
    public function aClientWithAFrontChannelLogoutUriIsGivenThePageFirst(): void
    {
        // Given
        $this->signedOn();
        self::signingKey();
        $this->signInClient('legacy-app', 'https://legacy.test/callback', 'legacy-secret-of-at-least-32-characters-long');

        // When
        $page = $this->logOut();

        // Then
        static::assertSame(
            [['https://legacy.test/frontchannel-logout?app=1'], '/saml/slo/continue'],
            [
                $page->filter('iframe')->each(static fn (Crawler $frame): string => self::string($frame->attr('src'))),
                parse_url(self::string($page->filter('main a')->attr('href')), PHP_URL_PATH),
            ],
        );
    }

    /**
     * S-32, S-35: the page resumes the chain once, and the browser is sent on to the service provider.
     */
    #[Test]
    public function thePageOfTheFrontChannelResumesTheChainOnce(): void
    {
        // Given
        $this->signedOn();
        self::signingKey();
        $this->signInClient('legacy-app', 'https://legacy.test/callback', 'legacy-secret-of-at-least-32-characters-long');
        $continue = self::string($this->logOut()->filter('main a')->attr('href'));
        $this->browser->request('GET', $continue);
        $this->told(self::SINGLE_LOGOUT);

        // When
        $this->browser->request('GET', $continue);

        // Then
        $this->assertRefused();
    }

    /**
     * S-30, S-34: a logout the service provider starts tells the other service provider of the session first, then is
     * answered Success, once that one answered Success.
     */
    #[Test]
    public function aLogoutAServiceProviderStartedTellsTheOtherOneBeforeItsAnswer(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth();
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));
        $told = $this->told(self::OTHER_SINGLE_LOGOUT, self::OTHER);

        // When
        $this->browser->request('GET', self::pathOf($this->answered($told, self::OTHER, 'idp')));

        // Then
        static::assertEquals(new Status(StatusCode::Success), $this->answerToTheRequester()->response->status);
    }

    /**
     * S-34, Core §3.7.3.2: when the other service provider does not answer Success, the one that asked is answered
     * Success with PartialLogout.
     */
    #[Test]
    public function aServiceProviderThatDidNotLogOutMakesTheAnswerPartial(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth();
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));
        $told = $this->told(self::OTHER_SINGLE_LOGOUT, self::OTHER);

        // When
        $this->browser->request('GET', self::pathOf($this->answered($told, self::OTHER, 'idp', new Status(StatusCode::Responder))));

        // Then
        static::assertEquals(
            new Status(StatusCode::Success, SecondLevelStatusCode::PartialLogout),
            $this->answerToTheRequester()->response->status,
        );
    }

    /**
     * S-36, section 6.8: the other service provider, told over HTTP-POST, is posted its request by the page whose
     * "form-action" names the origin of its single logout service, of the single logout service of the tenant, where
     * its answer comes back, and of the single logout service of the service provider that asked, where the chain ends.
     */
    #[Test]
    public function thePagePostingARequestNamesWhereTheChainGoesInItsPolicy(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth(Binding::HttpPost);

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame(
            sprintf(self::POLICY, 'https://default-sp.test https://op.test https://sp.example.org'),
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * S-36: at the end session endpoint, the other service provider, told over HTTP-POST once the first answered, is
     * posted its request by the page whose "form-action" names where the client asked the chain to end.
     */
    #[Test]
    public function thePagePostingARequestNamesWhereTheStarterOfTheLogoutGoes(): void
    {
        // Given
        $this->signedOnAtBoth(Binding::HttpPost);
        $this->logOut();

        // When
        $this->browser->request('GET', self::pathOf($this->answered($this->told(self::SINGLE_LOGOUT), self::SERVICE_PROVIDER, 'sp')));

        // Then
        static::assertSame(
            sprintf(self::POLICY, 'https://default-sp.test https://op.test https://demo.test'),
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * S-30, S-33, S-34: the other service provider, told over HTTP-POST, answers over HTTP-Redirect, and the chain goes
     * on to the service provider that asked, answered Success.
     */
    #[Test]
    public function aServiceProviderToldOverHttpPostCarriesTheChainOnWithItsAnswer(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth(Binding::HttpPost);
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));
        $told = $this->postedTo(self::OTHER_SINGLE_LOGOUT, self::OTHER);

        // When
        $this->browser->request('GET', self::pathOf($this->answered($told, self::OTHER, 'idp')));

        // Then
        static::assertEquals(new Status(StatusCode::Success), $this->answerToTheRequester()->response->status);
    }

    /**
     * S-32, S-33: the answer of the outstanding request, presented by a client that is not the browser that began the
     * chain, the server of the service provider itself or a browser holding the cookie of another chain, is refused
     * with the page of a refusal, before it is read: no request to the next service provider is handed to it.
     */
    #[Test]
    #[DataProvider('provideClientsThatDidNotBeginTheChain')]
    public function anAnswerIsRefusedToAClientThatDidNotBeginTheChain(?string $cookie): void
    {
        // Given
        $this->signedOnAtBoth();
        $this->logOut();
        $answer = self::pathOf($this->answered($this->told(self::SINGLE_LOGOUT), self::SERVICE_PROVIDER, 'sp'));
        $this->browser->getCookieJar()->clear();
        $this->holding($cookie);

        // When
        $this->browser->request('GET', $answer);

        // Then
        $this->assertRefused();
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideClientsThatDidNotBeginTheChain(): iterable
    {
        yield 'without the cookie of the chain' => [null];
        yield 'with the cookie of another chain' => ['GJx3sTZ1n3W0pQm7e2Lr9VbY4kCq8HfA6dUoE5iNwXs'];
    }

    /**
     * S-32, S-33: an answer refused to another client leaves the chain as it was, the answer unread: the browser that
     * began the chain, presenting the same answer, is sent on to the next service provider.
     */
    #[Test]
    public function anAnswerRefusedToAnotherClientIsLeftToTheBrowserThatBeganTheChain(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth();
        $this->logOut();
        $answer = self::pathOf($this->answered($this->told(self::SINGLE_LOGOUT), self::SERVICE_PROVIDER, 'sp'));
        $this->fromAnotherClient(fn () => $this->browser->request('GET', $answer));

        // When
        $this->browser->request('GET', $answer);

        // Then
        static::assertSame([self::sessionIndex($assertion)], $this->told(self::OTHER_SINGLE_LOGOUT, self::OTHER)->request->sessionIndexes);
    }

    /**
     * S-32, S-35: the reference of a chain written back after a KMS that did not answer, which the URL of the route
     * that resumes the chain carries and an access log keeps, resumes nothing for a client that is not the browser that
     * began the chain: the page of a refusal.
     */
    #[Test]
    #[DataProvider('provideClientsThatDidNotBeginTheChain')]
    public function aReferenceIsRefusedToAClientThatDidNotBeginTheChain(?string $cookie): void
    {
        // Given
        $this->signedOn();
        $continue = $this->loggedOutDuringAnOutage();
        $this->browser->getCookieJar()->clear();
        $this->holding($cookie);

        // When
        $this->browser->request('GET', $continue);

        // Then
        $this->assertRefused();
    }

    /**
     * S-32, S-35: a reference refused to another client leaves the chain as it was: the browser that began it, at the
     * same URL, is sent on to the service provider.
     */
    #[Test]
    public function aReferenceRefusedToAnotherClientIsLeftToTheBrowserThatBeganTheChain(): void
    {
        // Given
        $assertion = $this->signedOn();
        $continue = $this->loggedOutDuringAnOutage();
        $this->fromAnotherClient(fn () => $this->browser->request('GET', $continue));

        // When
        $this->browser->request('GET', $continue);

        // Then
        static::assertSame([self::sessionIndex($assertion)], $this->told(self::SINGLE_LOGOUT)->request->sessionIndexes);
    }

    /**
     * S-32: the browser that begins the chain is given the secret of the chain in a cookie of the provider: its name
     * "__Host-", Secure, HttpOnly, the path "/" and no domain, so that only the origin of the provider sets it and
     * reads it; SameSite=None, so that the answer a service provider posts from its site comes with it; open the ten
     * minutes the chain is; the secret 32 bytes in base64url.
     */
    #[Test]
    public function theBrowserThatBeginsTheChainIsGivenItsCookie(): void
    {
        // Given
        $this->signedOn();
        $now = self::currentSecond();
        self::mockTime($now);

        // When
        $this->logOut();

        // Then
        $cookie = $this->cookieOfTheChain();
        static::assertSame(
            ['__Host-beffroi_saml_logout', true, true, Cookie::SAMESITE_NONE, '/', null, $now->getTimestamp() + 600, 43],
            [
                $cookie->getName(),
                $cookie->isSecure(),
                $cookie->isHttpOnly(),
                $cookie->getSameSite(),
                $cookie->getPath(),
                $cookie->getDomain(),
                $cookie->getExpiresTime(),
                strlen((string) $cookie->getValue()),
            ],
        );
    }

    /**
     * S-32: each step of the chain gives its cookie the ten minutes the chain is open from that step.
     */
    #[Test]
    public function eachStepGivesTheCookieTheTenMinutesOfTheChainAgain(): void
    {
        // Given
        $this->signedOnAtBoth();
        $this->logOut();
        $held = $this->cookieOfTheChain()->getValue();
        $answer = self::pathOf($this->answered($this->told(self::SINGLE_LOGOUT), self::SERVICE_PROVIDER, 'sp'));
        $later = self::currentSecond()->modify('+60 seconds');
        self::mockTime($later);

        // When
        $this->browser->request('GET', $answer);

        // Then
        $cookie = $this->cookieOfTheChain();
        static::assertSame([$held, $later->getTimestamp() + 600], [$cookie->getValue(), $cookie->getExpiresTime()]);
    }

    /**
     * S-32, S-34: the cookie of the chain is cleared where the chain ends, at the end session endpoint as for a service
     * provider that asked.
     */
    #[Test]
    #[DataProvider('provideEnds')]
    public function theCookieOfTheChainIsClearedWhereTheChainEnds(string $end): void
    {
        // Given
        if ($end === 'requester') {
            $assertion = $this->signedOnAtBoth();
            $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));
            $answer = $this->answered($this->told(self::OTHER_SINGLE_LOGOUT, self::OTHER), self::OTHER, 'idp');
        } else {
            $this->signedOn();
            $this->logOut();
            $answer = $this->answered($this->told(self::SINGLE_LOGOUT), self::SERVICE_PROVIDER, 'sp');
        }

        // When
        $this->browser->request('GET', self::pathOf($answer));

        // Then
        $cookie = $this->cookieOfTheChain();
        static::assertSame([true, '/', null, true, Cookie::SAMESITE_NONE], [
            $cookie->isCleared(),
            $cookie->getPath(),
            $cookie->getDomain(),
            $cookie->isSecure(),
            $cookie->getSameSite(),
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEnds(): iterable
    {
        yield 'where the client asked' => ['client'];
        yield 'with the answer to the service provider that asked' => ['requester'];
    }

    /**
     * S-32, S-28, section 6.8: the answer a service provider posts from its site over HTTP-POST, which the session cookie
     * of the provider does not accompany, comes with the cookie of the chain, SameSite=None, and, posted again from the
     * origin of the provider, carries the chain on.
     */
    #[Test]
    public function anAnswerPostedFromTheSiteOfTheServiceProviderCarriesTheChainOn(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth();
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));
        $told = $this->told(self::OTHER_SINGLE_LOGOUT, self::OTHER);
        $form = new PostSender()->logoutResponse($this->answer($told, self::OTHER), self::signing('idp'));

        // When
        $this->postedFromAnotherSite('/saml/slo', http_build_query($form->fields));
        $this->postedAgain();

        // Then
        static::assertEquals(new Status(StatusCode::Success), $this->answerToTheRequester()->response->status);
    }

    /**
     * S-28: a LogoutRequest a service provider posts from its site over HTTP-POST, which the session cookie of the
     * provider does not accompany, is answered with the page that posts it again from the origin of the provider,
     * before anything of it is read: the session it names is not ended, and the answer sets no cookie.
     */
    #[Test]
    public function aLogoutRequestPostedFromTheSiteOfTheServiceProviderIsPostedAgain(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth();
        $form = new PostSender()->logoutRequest($this->logoutRequest($assertion), self::signing('sp'), 'state-2');

        // When
        $this->postedFromAnotherSite('/saml/slo', http_build_query($form->fields));

        // Then
        static::assertSame(
            [IdentityProviderRoutes::SINGLE_LOGOUT_PATH . '?' . CrossSitePost::MARKER . '=1', [], false],
            [
                $this->browser->getCrawler()->filter('form')->attr('action'),
                $this->browser->getResponse()->headers->getCookies(),
                $this->sessionOf($assertion)->hasEnded(),
            ],
        );
    }

    /**
     * S-28, S-29, S-32: the LogoutRequest posted again from the origin of the provider ends the session it names and
     * begins the chain, the other service provider of the session told first and the browser given the cookie of the
     * chain; the first post read nothing of it, which the store of S-23 would otherwise refuse as a replay.
     */
    #[Test]
    public function aLogoutRequestPostedAgainEndsTheSessionAndBeginsTheChain(): void
    {
        // Given
        $assertion = $this->signedOnAtBoth();
        $form = new PostSender()->logoutRequest($this->logoutRequest($assertion), self::signing('sp'), 'state-2');
        $this->postedFromAnotherSite('/saml/slo', http_build_query($form->fields));

        // When
        $this->postedAgain();

        // Then
        $cookie = $this->cookieOfTheChain();
        $this->told(self::OTHER_SINGLE_LOGOUT, self::OTHER);
        static::assertSame([true, false], [$this->sessionOf($assertion)->hasEnded(), $cookie->isCleared()]);
    }

    /**
     * The metadata of a service provider accepted for the tenant.
     */
    private function accept(string $entityId, string $document): void
    {
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(Uuid::v7(), self::tenant(), $entityId, $document, null, self::currentSecond()));
    }

    /**
     * The browser signed in, sent by the service provider with a request over HTTP-Redirect, and the assertion the page
     * of the provider posts back, as the service provider accepts it; its part in the session recorded (S-26).
     */
    private function signedOn(): AcceptedAssertion
    {
        $this->signIn($this->alice);
        $request = new AuthnRequest(
            '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b',
            self::currentSecond(),
            new Issuer(self::SERVICE_PROVIDER),
            self::SINGLE_SIGN_ON,
            self::ASSERTION_CONSUMER,
        );
        $this->browser->request('GET', self::pathOf(new RedirectSender()->authnRequest($request, self::signing('sp'), 'state-1')));
        $form = $this->browser->getCrawler()->filter('form')->first();
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });

        return new PostReceiver(SamlLoader::create())
            ->response($fields)
            ->validate(
                new ResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
                $this->identityProvider(),
                ExpectedResponse::toRequest('_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b', self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER),
            );
    }

    /**
     * signedOn(), and the other service provider signed in to the same session after it, its single logout service on
     * $binding.
     */
    private function signedOnAtBoth(Binding $binding = Binding::HttpRedirect): AcceptedAssertion
    {
        $assertion = $this->signedOn();
        $this->accept(self::OTHER, ServiceProviderDocuments::of(self::OTHER, 'idp', [new Endpoint($binding, self::OTHER_SINGLE_LOGOUT)]));
        self::service('test.beffroi.saml_session_participants', SessionParticipationRepositoryInterface::class)
            ->record(new SessionParticipation(Uuid::v7(), self::tenant(), $this->sessionOf($assertion), self::OTHER, self::currentSecond()));

        return $assertion;
    }

    /**
     * A logout at the end session endpoint, by the client of the configuration, confirmed by the browser.
     */
    private function logOut(): Crawler
    {
        return $this->browser->submit($this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ])->selectButton('Sign out')->form());
    }

    /**
     * The LogoutRequest the provider redirected the browser to $location with, as the service provider $entityId
     * validates it, at that single logout service, under the certificate the tenant publishes.
     */
    private function told(string $location, string $entityId = self::SERVICE_PROVIDER): AcceptedLogoutRequest
    {
        $redirected = $this->browser->getResponse()->headers->get('Location') ?? '';
        static::assertSame(
            $location,
            parse_url($redirected, PHP_URL_SCHEME) . '://' . parse_url($redirected, PHP_URL_HOST) . parse_url($redirected, PHP_URL_PATH),
        );
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage((string) parse_url($redirected, PHP_URL_QUERY));
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);

        return $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
            $this->identityProvider(),
            self::role($entityId, $location),
            $location,
        );
    }

    /**
     * The LogoutRequest the page of the provider posts to $location, as the service provider $entityId validates it at
     * that single logout service, under the certificate the tenant publishes.
     */
    private function postedTo(string $location, string $entityId): AcceptedLogoutRequest
    {
        $form = $this->browser->getCrawler()->filter('form')->first();
        static::assertSame($location, $form->attr('action'));
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });
        $received = new PostReceiver(SamlLoader::create())->logoutMessage($fields);
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);

        return $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
            $this->identityProvider(),
            self::role($entityId, $location),
            $location,
        );
    }

    /**
     * The LogoutResponse of the service provider $entityId to a request it accepted, signed with the test key $key of
     * its metadata, over HTTP-Redirect to the single logout service of the tenant.
     *
     * @param 'idp'|'sp' $key
     */
    private function answered(AcceptedLogoutRequest $told, string $entityId, string $key, Status $status = new Status(StatusCode::Success)): string
    {
        return new RedirectSender()->logoutResponse($this->answer($told, $entityId, $status), self::signing($key));
    }

    /**
     * The LogoutResponse of the service provider $entityId to a request it accepted, to the single logout service of
     * the tenant.
     */
    private function answer(AcceptedLogoutRequest $told, string $entityId, Status $status = new Status(StatusCode::Success)): LogoutResponse
    {
        return new LogoutResponse(
            '_3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d',
            self::currentSecond(),
            new Issuer($entityId),
            self::IDENTITY_PROVIDER_SINGLE_LOGOUT,
            $told->request->id,
            $status,
        );
    }

    /**
     * A logout at the end session endpoint confirmed while the KMS does not answer, a SAML key the process has not
     * opened yet being the one the first request of the chain is signed with: the session ended, the chain written back
     * (S-32), and the browser sent to the route that resumes it with its reference (S-35), whose path is returned, once
     * the KMS answers again.
     */
    private function loggedOutDuringAnOutage(): string
    {
        $form = $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ])->selectButton('Sign out')->form();
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(0, $tester->getStatusCode(), $tester->getDisplay());
        $this->kms->down = true;
        $this->browser->submit($form);
        $this->kms->down = false;
        $continue = $this->browser->getResponse()->headers->get('Location') ?? '';
        static::assertSame([Response::HTTP_FOUND, IdentityProviderRoutes::SINGLE_LOGOUT_CONTINUE_PATH], [
            $this->browser->getResponse()->getStatusCode(),
            parse_url($continue, PHP_URL_PATH),
        ]);

        return self::pathOf($continue);
    }

    /**
     * The cookie of a chain the client holds, the secret of another chain, or none.
     */
    private function holding(?string $secret): void
    {
        if ($secret !== null) {
            $this->browser->getCookieJar()->set(new BrowserCookie(LogoutChainCookie::NAME, $secret));
        }
    }

    /**
     * What another client does, which holds the cookie of another chain and none of the cookies of the browser: the jar
     * of the browser emptied for it, and given back.
     *
     * @param Closure(): mixed $request
     */
    private function fromAnotherClient(Closure $request): void
    {
        $jar = $this->browser->getCookieJar();
        $cookies = $jar->all();
        $jar->clear();
        $this->holding('GJx3sTZ1n3W0pQm7e2Lr9VbY4kCq8HfA6dUoE5iNwXs');
        $request();
        $this->assertRefused();
        $jar->clear();
        foreach ($cookies as $cookie) {
            $jar->set($cookie);
        }
    }

    /**
     * The cookie of the chain the last response sets or clears.
     */
    private function cookieOfTheChain(): Cookie
    {
        foreach ($this->browser->getResponse()->headers->getCookies() as $cookie) {
            if ($cookie->getName() === LogoutChainCookie::NAME) {
                return $cookie;
            }
        }

        return static::fail('The response sets no cookie of the chain of logout.');
    }

    /**
     * The LogoutRequest the first service provider writes from the assertion it holds: its NameID as received and its
     * SessionIndex, to the single logout service of the tenant.
     */
    private function logoutUrl(AcceptedAssertion $assertion): string
    {
        return new RedirectSender()->logoutRequest($this->logoutRequest($assertion), self::signing('sp'), 'state-2');
    }

    /**
     * The LogoutRequest the first service provider writes from the assertion it holds, whatever binding carries it.
     */
    private function logoutRequest(AcceptedAssertion $assertion): LogoutRequest
    {
        $nameId = $assertion->assertion->nameId;

        return new LogoutRequest(
            self::LOGOUT_REQUEST_ID,
            self::currentSecond(),
            new Issuer(self::SERVICE_PROVIDER),
            self::IDENTITY_PROVIDER_SINGLE_LOGOUT,
            null,
            new NameId($nameId->value, $nameId->format, $nameId->nameQualifier, $nameId->spNameQualifier),
            [self::sessionIndex($assertion)],
        );
    }

    /**
     * The answer the provider redirected the browser to the single logout service of the first service provider with,
     * as that service provider validates it.
     */
    private function answerToTheRequester(): AcceptedLogoutResponse
    {
        $location = $this->browser->getResponse()->headers->get('Location') ?? '';
        static::assertSame(
            self::SINGLE_LOGOUT,
            parse_url($location, PHP_URL_SCHEME) . '://' . parse_url($location, PHP_URL_HOST) . parse_url($location, PHP_URL_PATH),
        );
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage((string) parse_url($location, PHP_URL_QUERY));
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);

        return $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
            $this->identityProvider(),
            self::role(self::SERVICE_PROVIDER, self::SINGLE_LOGOUT),
            self::SINGLE_LOGOUT,
            self::LOGOUT_REQUEST_ID,
        );
    }

    private function assertRefused(): void
    {
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 1],
            [$this->browser->getResponse()->getStatusCode(), $this->browser->getCrawler()->filter('[data-error="saml_logout_refused"]')->count()],
        );
    }

    private function sessionOf(AcceptedAssertion $assertion): AuthenticationSession
    {
        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString(self::sessionIndex($assertion))) ?? static::fail('The session of the assertion is gone.')
        );
    }

    private function identityProvider(): IdentityProvider
    {
        $this->browser->request('GET', '/saml/metadata');

        return (
            new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
                SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
            )->identityProvider ?? static::fail('The tenant serves no identity provider.')
        );
    }

    /**
     * The service provider $entityId as its own validator knows itself, its single logout service at $location.
     */
    private static function role(string $entityId, string $location): ServiceProvider
    {
        return new ServiceProvider(
            $entityId,
            [],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, $entityId . '/acs', 0)]),
            [new Endpoint(Binding::HttpRedirect, $location)],
        );
    }

    /**
     * The SessionIndex of the assertion, the ID of the session of the provider (spec/saml.md section 6.4 step 7).
     */
    private static function sessionIndex(AcceptedAssertion $assertion): string
    {
        return $assertion->assertion->authnStatement->sessionIndex ?? static::fail('The assertion carries no SessionIndex.');
    }

    private static function pathOf(string $url): string
    {
        return parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY);
    }

    /**
     * @param 'idp'|'sp' $key
     */
    private static function signing(string $key): Signing
    {
        return new Signing(MetadataFixtures::signingKey($key));
    }
}
