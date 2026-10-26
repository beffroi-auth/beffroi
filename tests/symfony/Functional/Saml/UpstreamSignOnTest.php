<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\UpstreamSignOnReferences;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use DateTimeImmutable;
use function count;
use function parse_str;
use function parse_url;
use function strtok;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-48 to S-51, section 6.11, the acceptance of issue #783: in a deployment whose tenant is
 * a service provider (tests/symfony/config/config_test_service_provider.yml), the SimpleSAMLphp identity provider of
 * the judge declared and its document accepted, an interaction begun at the authorization endpoint is sent to that
 * provider with an AuthnRequest signed by the SAML key of the tenant, which saml2-model's validator accepts on the side
 * of the provider under the metadata the service provider serves, in each binding. The sign-on is started as a person
 * starts it, from the step of the address of the login page (SignOnFromTheLoginPage), and a sign-on reached any other
 * way starts nothing (S-51, issue #820).
 */
final class UpstreamSignOnTest extends ConsoleTestCase
{
    use SignOnFromTheLoginPage;

    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string SIGN_ON = '/saml/sp/sign-on';

    /**
     * An address of example.org, a domain of the identity provider of the judge.
     */
    private const string ADDRESS = 'alice@example.org';

    /**
     * The reference the step of the address drew, which a case of a data provider cannot know.
     */
    private const string DRAWN = 'the reference the step of the address drew';

    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * The acceptance of issue #783, S-48: over HTTP-Redirect, the binding of the single sign-on service of the
     * document, the interaction is answered with a redirection to that service, whose request the provider accepts
     * signed over its query string.
     */
    #[Test]
    public function overHttpRedirectTheProviderAcceptsTheRequestSignedOverItsQueryString(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame(Authentication::Binding, $this->acceptedRequest()->authentication);
    }

    /**
     * The acceptance of issue #783, S-48: the document listing its single sign-on service on HTTP-POST alone, the
     * interaction is answered with the page whose form posts to that service a request the provider accepts signed in
     * its XML.
     */
    #[Test]
    public function overHttpPostTheProviderAcceptsTheRequestSignedInItsXml(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame(Authentication::XmlSignature, $this->acceptedRequest(Binding::HttpPost)->authentication);
    }

    /**
     * S-48: the request is issued by the service provider of the tenant, to the single sign-on service of the
     * document, and asks for the response at the assertion consumer service its metadata announce, over HTTP-POST,
     * with a persistent identifier the provider may create.
     */
    #[Test]
    public function theRequestIsTheOneOfTheServiceProviderOfTheTenant(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->signOn($interaction);

        // When
        $request = $this->acceptedRequest()->request;

        // Then
        static::assertEquals(
            [
                new Issuer('https://op.test/saml/sp/metadata'),
                self::SINGLE_SIGN_ON,
                'https://op.test/saml/sp/acs',
                Binding::HttpPost->value,
                new NameIdPolicy(NameIdFormat::Persistent->value, null, true),
            ],
            [
                $request->issuer,
                $request->destination,
                $request->assertionConsumerServiceUrl,
                $request->protocolBinding,
                $request->nameIdPolicy,
            ],
        );
    }

    /**
     * The acceptance of issue #783, S-50: the RelayState is a reference of 43 characters of base64url, the one key of
     * what the HTTP session of the browser remembers, under which are the ID of the request, the provider it was sent
     * to, whether it carried ForceAuthn and the instant it was issued, the interaction it serves and the tenant, and
     * nothing else.
     */
    #[Test]
    public function theRelayStateNamesTheRememberedRequestAndNothingElse(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->signOn($interaction);
        $relayState = $this->received()->relayState ?? static::fail('The request carries no RelayState.');
        $request = $this->acceptedRequest()->request;

        // When
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);

        // Then
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $relayState);
        static::assertSame(
            [
                $relayState => [
                    'tenant' => self::tenant()->id->toRfc4122(),
                    'interaction' => $interaction,
                    'request' => $request->id,
                    'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
                    'force_authn' => false,
                    'issued_at' => $request->issueInstant->getTimestamp(),
                ],
            ],
            $remembered,
        );
    }

    /**
     * S-50, section 7: a browser remembers eight requests at most, the oldest forgotten first.
     */
    #[Test]
    public function aBrowserRemembersEightRequestsAtMost(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->signOn($interaction);
        $first = $this->received()->relayState;

        // When
        for ($signOn = 0; $signOn < UpstreamSignOns::MAX_KEPT; ++$signOn) {
            $this->signOn($interaction);
        }

        // Then
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);
        static::assertIsArray($remembered);
        static::assertCount(UpstreamSignOns::MAX_KEPT, $remembered);
        static::assertArrayNotHasKey((string) $first, $remembered);
    }

    /**
     * The acceptance of issue #783, S-49: an authorization request that asks for a fresh login, by prompt=login or by a
     * max_age the session of the browser exceeds, sets ForceAuthn; one that asks for neither does not.
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideFreshLogins')]
    public function aFreshLoginTheClientAsksForSetsForceAuthn(array $parameters, bool $signedIn, bool $forceAuthn): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        if ($signedIn) {
            $this->signIn(self::user('alice'), new DateTimeImmutable('-1 hour'));
        }
        $interaction = $this->beginAuthorization($parameters);

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame($forceAuthn, $this->acceptedRequest()->request->forceAuthn);
    }

    /**
     * @return iterable<string, array{array<string, string>, bool, bool}>
     */
    public static function provideFreshLogins(): iterable
    {
        yield 'prompt=login' => [['prompt' => 'login'], false, true];
        yield 'a max_age the session exceeds' => [['max_age' => '60'], true, true];
        yield 'a max_age and no session' => [['max_age' => '60'], false, false];
        yield 'neither' => [[], false, false];
    }

    /**
     * S-51, bindings.md section 6.7, SAML Bindings §3.5.5.1: the page that posts the request names its one script by
     * its hash, loads nothing, is framed by nothing, names no "form-action", the single sign-on service sending the
     * browser on to its login page, and is never cached.
     */
    #[Test]
    public function thePageCarriesItsPolicyAndTheCachingOfTheBinding(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [
                "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; base-uri 'none'; frame-ancestors 'none'",
                true,
                true,
                'no-cache',
            ],
            [
                $response->headers->get('Content-Security-Policy'),
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
            ],
        );
    }

    /**
     * S-51, architecture §5.7: the page says the browser goes to the sign-in of its organisation, and not back to an
     * application.
     */
    #[Test]
    public function thePageSaysWhereTheBrowserGoes(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();

        // When
        $crawler = $this->signOn($interaction);

        // Then
        static::assertSame('Signing in with your organisation', $crawler->filter('title')->text());
    }

    /**
     * S-51, SAML Bindings §3.4.5.1: the redirection is never cached.
     */
    #[Test]
    public function theRedirectionCarriesTheCachingOfTheBinding(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, true, true, 'no-cache'],
            [
                $response->getStatusCode(),
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
            ],
        );
    }

    /**
     * The acceptance of issue #783, S-48, S-51: a provider the tenant declares whose document was never accepted is the
     * page of a refusal, and the browser is sent nowhere.
     */
    #[Test]
    public function aProviderWhoseDocumentWasNeverAcceptedIsRefused(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOnAs($interaction, 'carol@encrypting.example');

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * The acceptance of issue #820, S-51: a sign-on of an interaction that does not present the reference the login
     * page drew for it, one it presents another, or the reference drawn for another provider, starts nothing: no
     * request is signed and nothing is remembered.
     */
    #[Test]
    #[DataProvider('provideReferencesNotDrawnForTheSignOn')]
    public function aSignOnWithoutItsReferenceStartsNothing(?string $reference, string $identityProvider): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeTheAddress($interaction, self::ADDRESS);
        $drawn = $this->presentedReference();

        // When
        $this->browser->request('GET', self::SIGN_ON, [
            'interaction' => $interaction,
            'identity_provider' => $identityProvider,
            ...($reference === null ? [] : ['reference' => $reference === self::DRAWN ? $drawn : $reference]),
        ]);

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function provideReferencesNotDrawnForTheSignOn(): iterable
    {
        yield 'none' => [null, IdentityProviderDocuments::SIMPLESAMLPHP];
        yield 'another' => ['Ab3xQ0kQ1n0oG2d9V5m8Zr4wY7tL6pHcEeFsUjKiN1o', IdentityProviderDocuments::SIMPLESAMLPHP];
        yield 'drawn for another provider' => [self::DRAWN, IdentityProviderDocuments::SIGNED];
    }

    /**
     * The acceptance of issue #820, S-51, the login CSRF of the security review of sub-spike 9d: a page of the provider
     * that waits for a login, which a page of another site can have the browser reach, then the sign-on of a provider
     * the tenant declares, without the reference the login page draws, starts nothing.
     */
    #[Test]
    public function theLoginAPageWaitsForStartsNoSignOnWithoutItsReference(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $this->browser->request('GET', '/account');

        // When
        $this->browser->request('GET', self::SIGN_ON, [
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * The acceptance of issue #820, S-51: the reference starts one sign-on, and the same sign-on presented again starts
     * nothing more.
     */
    #[Test]
    public function aReferencePresentedTwiceStartsOneSignOn(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeTheAddress($interaction, self::ADDRESS);
        $signOn = self::string($this->browser->getResponse()->headers->get('Location'));
        $this->browser->followRedirect();

        // When
        $this->browser->request('GET', $signOn);

        // Then
        $response = $this->browser->getResponse();
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);
        static::assertIsArray($remembered);
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'saml_upstream_sign_on_refused', 1],
            [$response->getStatusCode(), $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'), count($remembered)],
        );
    }

    /**
     * The acceptance of issue #820, S-51, section 7: a reference presented more than a minute after it was drawn,
     * which no redirection followed at once takes, starts nothing.
     */
    #[Test]
    public function aReferenceOlderThanItsLifeStartsNothing(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeTheAddress($interaction, self::ADDRESS);
        self::mockTime(Clock::get()->now()->modify('+' . (UpstreamSignOnReferences::LIFE + 1) . ' seconds'));

        // When
        $this->browser->followRedirect();

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * S-51, section 6.11 step 5: a tenant that holds no SAML key signs no request, and serves no service provider.
     */
    #[Test]
    public function aTenantWithoutASamlKeyStartsNoSignOn(): void
    {
        // Given
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The acceptance of issue #783, S-51: an interaction this browser did not begin is the page of an unknown
     * interaction.
     */
    #[Test]
    public function anUnknownInteractionIsRefused(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $this->beginAuthorization();

        // When
        $this->browser->request('GET', self::SIGN_ON, [
            'interaction' => 'an-interaction-nobody-began',
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('unknown_interaction', $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'));
    }

    /**
     * An interaction begun at the authorization endpoint, which sends the browser to the login.
     *
     * @param array<string, string> $parameters
     */
    private function beginAuthorization(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));

        return self::redirectedInteraction($response);
    }

    /**
     * The sign-on of the interaction at the identity provider of the judge, started from the login page as a person
     * starts it.
     */
    private function signOn(string $interaction): Crawler
    {
        return $this->signOnAs($interaction, self::ADDRESS);
    }

    /**
     * The reference the redirection to the sign-on carries.
     */
    private function presentedReference(): string
    {
        $query = [];
        parse_str((string) parse_url(self::string($this->browser->getResponse()->headers->get('Location')), PHP_URL_QUERY), $query);

        return self::string($query['reference'] ?? null);
    }

    /**
     * Refused with the page of a refusal, no request sent to a provider and none remembered in the HTTP session.
     */
    private function assertRefusedAndRemembersNothing(): void
    {
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'saml_upstream_sign_on_refused', null, null],
            [
                $response->getStatusCode(),
                $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'),
                $response->headers->get('Location'),
                $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY),
            ],
            self::string($response->getContent()),
        );
    }

    /**
     * The SAML key of the tenant, drawn as an operator draws it.
     */
    private static function generate(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * The document of the identity provider of the judge accepted for the tenant.
     */
    private static function accept(string $document): void
    {
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                $document,
                null,
                self::currentSecond(),
            ));
    }

    /**
     * The request the answer carries to the provider, received as the provider receives it: from the query string of
     * the redirection, or from the form of the page.
     */
    private function received(): ReceivedAuthnRequest
    {
        $response = $this->browser->getResponse();
        if ($response->isRedirection()) {
            $location = $response->headers->get('Location') ?? static::fail('The redirection names no location.');
            static::assertStringStartsWith(self::SINGLE_SIGN_ON . '?', $location);

            return new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));
        }
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $form = $this->browser->getCrawler()->filter('form')->first();
        // the address of S-68 in the query of the action, the message in the body
        static::assertSame(self::SINGLE_SIGN_ON, strtok((string) $form->attr('action'), '?'));
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });

        return new PostReceiver(SamlLoader::create())->authnRequest($fields);
    }

    /**
     * The request as the provider validates it, at its single sign-on service, under the certificate the metadata of
     * the service provider of the tenant publish.
     */
    private function acceptedRequest(Binding $binding = Binding::HttpRedirect): AcceptedAuthnRequest
    {
        $received = $this->received();

        return $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), Clock::get()),
            $this->serviceProvider(),
            $this->identityProvider($binding),
            self::SINGLE_SIGN_ON,
        );
    }

    private function serviceProvider(): ServiceProvider
    {
        $this->browser->request('GET', '/saml/sp/metadata');

        return (
            new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
                SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
            )->serviceProvider ?? static::fail('The tenant serves no service provider.')
        );
    }

    private function identityProvider(Binding $binding): IdentityProvider
    {
        $document = $binding === Binding::HttpPost ? IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost() : IdentityProviderDocuments::simpleSamlPhp();

        return (
            new MetadataReader(
                SamlLoader::create(),
                new MockClock(),
            )->readTrusted(SamlLoader::create()->load($document))->identityProvider ?? static::fail('The document holds no identity provider.')
        );
    }
}
