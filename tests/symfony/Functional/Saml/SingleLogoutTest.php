<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Key\KmsUnavailableListener;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Bundle\Tests\Functional\Controller\TokensOfASession;
use Beffroi\Bundle\Tests\Functional\Key\KmsOutage;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
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
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Writing\Signing;
use function array_map;
use Closure;
use function explode;
use function parse_url;
use function sprintf;
use const PHP_URL_HOST;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use const PHP_URL_SCHEME;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md section 6.5, the acceptance of issue #734: the service provider https://sp.example.org/saml
 * of the configuration of the test, its metadata accepted with a single logout service on each binding, signs the user
 * in over HTTP-Redirect, then sends the LogoutRequest its assertion lets it write, signed with the test key of a
 * service provider of saml2-model: the session of the provider ends, and the LogoutResponse comes back signed to the
 * single logout service of the metadata, which saml2-model's validator accepts under the certificate the metadata of
 * the tenant publish. The KMS of the kernel is behind the switch of KmsOutage, up unless a test takes it down.
 */
final class SingleLogoutTest extends ConsoleTestCase
{
    use TokensOfASession;

    private const string SERVICE_PROVIDER = ServiceProviderDocuments::SIGNED;

    private const string ASSERTION_CONSUMER = ServiceProviderDocuments::SIGNED . '/acs';

    private const string SINGLE_LOGOUT = ServiceProviderDocuments::SIGNED . '/slo';

    private const string SINGLE_LOGOUT_POST = ServiceProviderDocuments::SIGNED . '/slo/post';

    private const string SINGLE_SIGN_ON = 'https://op.test/saml/sso';

    private const string IDENTITY_PROVIDER_SINGLE_LOGOUT = 'https://op.test/saml/slo';

    private const string LOGOUT_REQUEST_ID = '_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b';

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
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(
                Uuid::v7(),
                self::tenant(),
                self::SERVICE_PROVIDER,
                ServiceProviderDocuments::exampleOrgWithSingleLogout([
                    [Binding::HttpRedirect->value, self::SINGLE_LOGOUT, null],
                    [Binding::HttpPost->value, self::SINGLE_LOGOUT_POST, null],
                ]),
                null,
                self::currentSecond(),
            ));
        $this->alice = self::userWithPassword('alice', 'correct horse battery staple');
    }

    protected function configureContainer(): Closure
    {
        return $this->kms->takeOver(...);
    }

    /**
     * The acceptance of issue #734, S-22, S-27, B-12: a LogoutRequest signed over HTTP-Redirect is answered with a 302
     * to the single logout service of the metadata on HTTP-Redirect, a LogoutResponse signed over its query string that
     * says Success.
     */
    #[Test]
    public function aLogoutOverHttpRedirectIsAnsweredSuccessAtTheSingleLogoutService(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, StatusCode::Success],
            [$response->getStatusCode(), $this->answer($response->headers->get('Location') ?? '')[0]->response->status->code],
        );
    }

    /**
     * B-9, section 6.8: the RelayState the request carried comes back with the answer, byte for byte.
     */
    #[Test]
    public function theRelayStateComesBackWithTheAnswer(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame('state-2', $this->answer($this->browser->getResponse()->headers->get('Location') ?? '')[1]);
    }

    /**
     * SAML Bindings §3.4.5.1: the redirection carries the caching headers of the binding.
     */
    #[Test]
    public function theRedirectionCarriesTheCachingOfTheBinding(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [true, true, 'no-cache'],
            [
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
            ],
        );
    }

    /**
     * The acceptance of issue #734, S-24, S-25: the session of the provider the assertion was written from has ended,
     * by the service provider.
     */
    #[Test]
    public function theSessionOfTheProviderEnds(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame(SessionEnd::RelyingParty, $this->sessionOf($assertion)->endedBy);
    }

    /**
     * The acceptance of issue #734, S-25, Back-Channel Logout 1.0 §2.6: a client of OpenID Connect the same session
     * signed in, which registered a back-channel logout URI, is given a logout token, as a logout at the end session
     * endpoint gives it one.
     */
    #[Test]
    public function aClientOfOpenIdConnectOfTheSessionIsToldByTheBackChannel(): void
    {
        // Given
        $assertion = $this->signedOn();
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $told = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LogoutTokenIssued) {
                $told[] = [$event->clientId, $event->sessionId->toRfc4122()];
            }
        }
        static::assertSame([['oidc-demo', self::sessionIndex($assertion)]], $told);
    }

    /**
     * Issue #741, S-25: the tokens of OpenID Connect issued under the session a service provider ends are
     * revoked with it, as those of a session ended at the end session endpoint are.
     */
    #[Test]
    public function theTokensIssuedUnderTheSessionAreRevoked(): void
    {
        // Given
        $assertion = $this->signedOn();
        $tokens = self::tokensIssuedIn($this->sessionOf($assertion));

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        self::assertTheTokensAreRevoked($tokens);
    }

    /**
     * S-25: the browser that held the session is not signed in any more: a request of the service provider is sent to
     * the login of the provider.
     */
    #[Test]
    public function theBrowserIsSignedOut(): void
    {
        // Given
        $assertion = $this->signedOn();
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // When
        $this->browser->request(
            'GET',
            self::pathOf(new RedirectSender()->authnRequest(self::authnRequest('_5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c'), self::signing(), 'state-3')),
        );

        // Then
        static::assertSame(
            [Response::HTTP_FOUND, '/login'],
            [$this->browser->getResponse()->getStatusCode(), parse_url($this->browser->getResponse()->headers->get('Location') ?? '', PHP_URL_PATH)],
        );
    }

    /**
     * S-27, M-2: a LogoutRequest signed in its XML over HTTP-POST is answered with the page that posts a LogoutResponse
     * signed in its XML to the single logout service of the metadata on HTTP-POST.
     */
    #[Test]
    public function aLogoutOverHttpPostIsAnsweredWithThePageThatPostsTheResponse(): void
    {
        // Given
        $assertion = $this->signedOn();
        $form = new PostSender()->logoutRequest($this->logoutRequest($assertion), self::signing(), 'state-2');

        // When
        $this->browser->request('POST', '/saml/slo', $form->fields, [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']);

        // Then
        $posted = $this->form();
        $response = new PostReceiver(SamlLoader::create())->logoutMessage($posted['fields']);
        static::assertInstanceOf(ReceivedLogoutResponse::class, $response);
        static::assertSame(
            [self::SINGLE_LOGOUT_POST, StatusCode::Success],
            [$posted['action'], $this->validated($response, self::SINGLE_LOGOUT_POST)->response->status->code],
        );
    }

    /**
     * S-36, section 6.8: the page that posts the LogoutResponse over HTTP-POST, a response nobody answers, names in its
     * "form-action" the origin of the single logout service it posts to and nothing else.
     */
    #[Test]
    public function thePagePostingTheResponseNamesTheOriginOfItsActionAloneInItsPolicy(): void
    {
        // Given
        $assertion = $this->signedOn();
        $form = new PostSender()->logoutRequest($this->logoutRequest($assertion), self::signing(), 'state-2');

        // When
        $this->browser->request('POST', '/saml/slo', $form->fields, [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']);

        // Then
        static::assertSame(
            sprintf(self::POLICY, 'https://sp.example.org'),
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * The acceptance of issue #734, S-23, issue #708: the same URL presented again inside its window is refused, with
     * the page of a refusal and no SAML answer.
     */
    #[Test]
    public function theSameLogoutRequestIsRefusedTheSecondTime(): void
    {
        // Given
        $url = self::pathOf($this->logoutUrl($this->signedOn()));
        $this->browser->request('GET', $url);

        // When
        $this->browser->request('GET', $url);

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 1],
            [$this->browser->getResponse()->getStatusCode(), $this->browser->getCrawler()->filter('[data-error="saml_logout_refused"]')->count()],
        );
    }

    /**
     * S-22, M-2: a LogoutRequest whose query string carries no signature ends nothing and gets no SAML answer.
     */
    #[Test]
    public function anUnsignedLogoutRequestIsRefused(): void
    {
        // Given
        $assertion = $this->signedOn();
        [$unsigned] = explode('&SigAlg=', self::pathOf($this->logoutUrl($assertion)));

        // When
        $this->browser->request('GET', $unsigned);

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, false],
            [$this->browser->getResponse()->getStatusCode(), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-25, S-27, section 6.5 step 1: a tenant whose SAML key is no longer active ends no session, the key that would
     * sign the answer being opened before the request is read; the page of a tenant that serves no identity provider.
     */
    #[Test]
    public function aTenantWithoutItsKeyEndsNoSession(): void
    {
        // Given
        $assertion = $this->signedOn();
        self::withoutActiveKey();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, false],
            [$this->browser->getResponse()->getStatusCode(), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-23, section 6.5 step 1: a request a tenant without its key could not answer was not remembered, and the same URL
     * is answered Success once the tenant holds an active key again.
     */
    #[Test]
    public function theSameRequestIsAnsweredOnceTheKeyIsBack(): void
    {
        // Given
        $url = self::pathOf($this->logoutUrl($this->signedOn()));
        self::withoutActiveKey();
        $this->browser->request('GET', $url);
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        // When
        $this->browser->request('GET', $url);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, StatusCode::Success],
            [$response->getStatusCode(), $this->answer($response->headers->get('Location') ?? '')[0]->response->status->code],
        );
    }

    /**
     * S-25, S-27, section 6.5 step 1, architecture §5.4: a KMS that does not answer to open the SAML key, one this
     * process has not opened yet, ends no session: a 503 with a Retry-After.
     */
    #[Test]
    public function aKmsThatDoesNotAnswerEndsNoSession(): void
    {
        // Given
        $assertion = $this->signedOn();
        self::withAKeyNotOpenedYet();
        $this->kms->down = true;

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_SERVICE_UNAVAILABLE, (string) KmsUnavailableListener::RETRY_AFTER, false],
            [$response->getStatusCode(), $response->headers->get('Retry-After'), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-23, section 6.5 step 1: a request the KMS left unanswered was not remembered, and the same URL is answered
     * Success once the KMS is back.
     */
    #[Test]
    public function theSameRequestIsAnsweredOnceTheKmsIsBack(): void
    {
        // Given
        $url = self::pathOf($this->logoutUrl($this->signedOn()));
        self::withAKeyNotOpenedYet();
        $this->kms->down = true;
        $this->browser->request('GET', $url);
        $this->kms->down = false;

        // When
        $this->browser->request('GET', $url);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, StatusCode::Success],
            [$response->getStatusCode(), $this->answer($response->headers->get('Location') ?? '')[0]->response->status->code],
        );
    }

    /**
     * S-26: the sign-on recorded the service provider's part in the session, which the logout the identity provider
     * starts reads (issue #735).
     */
    #[Test]
    public function theSignOnRecordsTheServiceProviderOfTheSession(): void
    {
        // When
        $assertion = $this->signedOn();

        // Then
        static::assertSame(
            [self::SERVICE_PROVIDER],
            array_map(
                static fn (SessionParticipation $participation): string => $participation->serviceProvider,
                self::service('test.beffroi.saml_session_participants', SessionParticipationRepositoryInterface::class)
                    ->ofSession(Uuid::fromString(self::sessionIndex($assertion))),
            ),
        );
    }

    /**
     * The browser signed in, sent by the service provider with a request over HTTP-Redirect, and the assertion the page
     * of the provider posts back, as the service provider accepts it.
     */
    private function signedOn(): AcceptedAssertion
    {
        $this->signIn($this->alice);
        $this->browser->request('GET', self::pathOf(new RedirectSender()->authnRequest(self::authnRequest(), self::signing(), 'state-1')));
        $form = $this->form();
        static::assertSame(self::ASSERTION_CONSUMER, $form['action']);

        return new PostReceiver(SamlLoader::create())
            ->response($form['fields'])
            ->validate(
                new ResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
                $this->identityProvider(),
                ExpectedResponse::toRequest('_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b', self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER),
            );
    }

    /**
     * The LogoutRequest the service provider writes from the assertion it holds: its NameID as received and its
     * SessionIndex, to the single logout service of the tenant.
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

    private function logoutUrl(AcceptedAssertion $assertion): string
    {
        return new RedirectSender()->logoutRequest($this->logoutRequest($assertion), self::signing(), 'state-2');
    }

    /**
     * The LogoutResponse of a URL the provider redirected to, as the service provider validates it, and its RelayState.
     *
     * @return array{AcceptedLogoutResponse, ?string}
     */
    private function answer(string $location): array
    {
        static::assertSame(
            self::SINGLE_LOGOUT,
            parse_url($location, PHP_URL_SCHEME) . '://' . parse_url($location, PHP_URL_HOST) . parse_url($location, PHP_URL_PATH),
        );
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage((string) parse_url($location, PHP_URL_QUERY));
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);

        return [$this->validated($received, self::SINGLE_LOGOUT), $received->relayState];
    }

    private function validated(ReceivedLogoutResponse $received, string $location): AcceptedLogoutResponse
    {
        return $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
            $this->identityProvider(),
            new ServiceProvider(
                self::SERVICE_PROVIDER,
                [],
                [],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ASSERTION_CONSUMER, 0)]),
                [new Endpoint(Binding::HttpRedirect, $location)],
            ),
            $location,
            self::LOGOUT_REQUEST_ID,
        );
    }

    /**
     * The active SAML key of the tenant retiring, with no key active in its place: what the tenant holds once an
     * operator took it out without a successor.
     */
    private static function withoutActiveKey(): void
    {
        $keys = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class);
        $key = $keys->findActive(self::tenant(), new SamlSigning()) ?? static::fail('The tenant holds no active SAML key.');
        $key->startRetiring(self::currentSecond(), self::currentSecond()->modify('+1 day'));
        $keys->save($key);
    }

    /**
     * A second SAML key generated after the sign-on, active at once: the process opened the key that signed the
     * assertion, and has not opened this one.
     */
    private static function withAKeyNotOpenedYet(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    private function sessionOf(AcceptedAssertion $assertion): AuthenticationSession
    {
        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString(self::sessionIndex($assertion))) ?? static::fail('The session of the assertion is gone.')
        );
    }

    /**
     * The form of the page, as a browser reads it.
     *
     * @return array{action: string, fields: array<string, string>}
     */
    private function form(): array
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $form = $this->browser->getCrawler()->filter('form')->first();
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });

        return [
            'action' => (string) $form->attr('action'),
            'fields' => $fields,
        ];
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

    private static function authnRequest(string $id = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b'): AuthnRequest
    {
        return new AuthnRequest($id, self::currentSecond(), new Issuer(self::SERVICE_PROVIDER), self::SINGLE_SIGN_ON, self::ASSERTION_CONSUMER);
    }

    private static function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('sp'));
    }
}
