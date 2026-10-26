<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use function array_map;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use function explode;
use function file_get_contents;
use function parse_str;
use function parse_url;
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
 * beffroi/saml, spec/saml.md S-68, the acceptance of issue #816: in a deployment whose tenant is a service provider
 * (tests/symfony/config/config_test_service_provider.yml), the SimpleSAMLphp identity provider of the judge declared
 * with the parameter of its single sign-on service that takes the address, login_hint, as Entra reads it, the address
 * a person typed on the login page reaches that provider in that parameter over both bindings, the request still
 * signed as it was; a provider declared without it, and a sign-on started without an address, send none.
 */
final class AddressHintTest extends ConsoleTestCase
{
    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    private const string ENCRYPTING_SINGLE_SIGN_ON = 'https://idp.example.org/saml/sso';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_service_provider',
        ];
    }

    /**
     * The acceptance of issue #816, S-68, Bindings §3.4.4.1: over HTTP-Redirect, the address typed reaches the single
     * sign-on service of the provider in the parameter its declaration names, after the Signature.
     */
    #[Test]
    public function overHttpRedirectTheAddressTypedFollowsTheSignature(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIMPLESAMLPHP, IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, 'alice@example.org');

        // When
        $this->browser->followRedirect();

        // Then
        $location = $this->redirection(self::SINGLE_SIGN_ON);
        static::assertSame(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature', 'login_hint'], self::parameterNames($location));
        static::assertSame('alice@example.org', self::query($location)['login_hint'] ?? null);
    }

    /**
     * The acceptance of issue #816, S-68, S-48: over HTTP-Redirect, the request that carries the address is still the
     * one the provider accepts signed over its query string, the address outside what the signature covers.
     */
    #[Test]
    public function overHttpRedirectTheRequestCarryingTheAddressIsStillAcceptedSigned(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIMPLESAMLPHP, IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, 'alice@example.org');
        $this->browser->followRedirect();
        $location = $this->redirection(self::SINGLE_SIGN_ON);

        // When
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));

        // Then
        static::assertSame(
            Authentication::Binding,
            $received->validate(
                new AuthnRequestValidator(SamlLoader::create(), Clock::get()),
                $this->serviceProvider(),
                self::identityProvider(IdentityProviderDocuments::simpleSamlPhp()),
                self::SINGLE_SIGN_ON,
            )->authentication,
        );
    }

    /**
     * The acceptance of issue #816, S-68: over HTTP-POST, the address typed is in the query of the action of the form,
     * and the request it posts is still the one the provider accepts signed in its XML.
     */
    #[Test]
    public function overHttpPostTheAddressTypedIsInTheQueryOfTheAction(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIMPLESAMLPHP, IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, 'alice@example.org');

        // When
        $crawler = $this->browser->followRedirect();

        // Then
        $form = $crawler->filter('form')->first();
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });
        static::assertSame(self::SINGLE_SIGN_ON . '?login_hint=alice%40example.org', $form->attr('action'));
        static::assertSame(
            Authentication::XmlSignature,
            new PostReceiver(SamlLoader::create())
                ->authnRequest($fields)
                ->validate(
                    new AuthnRequestValidator(SamlLoader::create(), Clock::get()),
                    $this->serviceProvider(),
                    self::identityProvider(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost()),
                    self::SINGLE_SIGN_ON,
                )
                ->authentication,
        );
    }

    /**
     * S-68, S-60: an address typed in capitals or with its domain in a U-label reaches the provider with its domain
     * written as its A-label, its local part as it was typed.
     */
    #[Test]
    #[DataProvider('provideSpellings')]
    public function theAddressReachesTheProviderWithItsDomainAsItsALabel(string $typed, string $hinted): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIMPLESAMLPHP, IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, $typed);

        // When
        $this->browser->followRedirect();

        // Then
        static::assertSame($hinted, self::query($this->redirection(self::SINGLE_SIGN_ON))['login_hint'] ?? null);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSpellings(): iterable
    {
        yield 'in capitals' => ['Alice@EXAMPLE.org', 'Alice@example.org'];
        yield 'in a U-label' => ['alice@Bücher.example', 'alice@xn--bcher-kva.example'];
    }

    /**
     * S-68, S-62: the login_hint of a client that skips the page reaches the provider as an address typed there does.
     */
    #[Test]
    public function theLoginHintThatSkipsThePageReachesTheProvider(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIMPLESAMLPHP, IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization([
            'login_hint' => 'alice@example.org',
        ]);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // When
        $this->browser->followRedirect();

        // Then
        static::assertSame('alice@example.org', self::query($this->redirection(self::SINGLE_SIGN_ON))['login_hint'] ?? null);
    }

    /**
     * The acceptance of issue #816, S-68: a provider whose declaration names no parameter of the address is sent none
     * for an address of its domain.
     */
    #[Test]
    public function aProviderDeclaredWithoutTheParameterIsSentNoAddress(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIGNED, self::string(file_get_contents(IdentityProviderDocuments::signedPath())));
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, 'carol@encrypting.example');

        // When
        $this->browser->followRedirect();

        // Then
        static::assertSame(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'], self::parameterNames($this->redirection(self::ENCRYPTING_SINGLE_SIGN_ON)));
    }

    /**
     * S-68: the address kept for a sign-on is taken by it, which the HTTP session holds no longer; the same sign-on
     * presented again starts nothing (S-51, UpstreamSignOnTest).
     */
    #[Test]
    public function theAddressIsTakenByTheSignOnItWasKeptFor(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::SIMPLESAMLPHP, IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, 'alice@example.org');

        // When
        $this->browser->followRedirect();

        // Then
        static::assertSame([], $this->readHttpSession()->get(LoginAddresses::SENT_SESSION_KEY));
    }

    /**
     * S-68, section 7: an interaction that ends before its sign-on is reached, here once its ten minutes
     * are over, takes the address kept for that sign-on with it, which the HTTP session holds no longer.
     */
    #[Test]
    public function anInteractionThatEndsTakesTheAddressItsSignOnNeverTookWithIt(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $this->typeAddress($interaction, 'alice@example.org');
        self::mockTime(Clock::get()->now()->modify('+11 minutes'));

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], $this->readHttpSession()->get(LoginAddresses::SENT_SESSION_KEY));
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
     * The address typed on the login page of the interaction and posted, as a person posts it: the browser is sent to
     * the sign-on of its provider.
     */
    private function typeAddress(string $interaction, string $address): void
    {
        $form = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ])->filter('form[data-step="address"]')->form();
        $form['_address'] = $address;
        $this->browser->submit($form);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
    }

    /**
     * Where the answer redirects the browser, the single sign-on service named.
     */
    private function redirection(string $singleSignOn): string
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $location = (string) $response->headers->get('Location');
        static::assertStringStartsWith($singleSignOn . '?', $location);

        return $location;
    }

    /**
     * The names of the parameters of the query of a URL, in their order.
     *
     * @return list<string>
     */
    private static function parameterNames(string $url): array
    {
        return array_map(
            static fn (string $segment): string => explode('=', $segment, 2)[0],
            explode('&', (string) parse_url($url, PHP_URL_QUERY)),
        );
    }

    /**
     * The query of a URL, decoded.
     *
     * @return array<array-key, mixed>
     */
    private static function query(string $url): array
    {
        $query = [];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return $query;
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
     * The document of a declared identity provider accepted for the tenant.
     */
    private static function accept(string $entityId, string $document): void
    {
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(Uuid::v7(), self::tenant(), $entityId, $document, null, self::currentSecond()));
    }

    /**
     * The service provider of the tenant, as the provider reads the metadata it serves.
     */
    private function serviceProvider(): ServiceProvider
    {
        $this->browser->request('GET', '/saml/sp/metadata');

        return (
            new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
                SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
            )->serviceProvider ?? static::fail('The tenant serves no service provider.')
        );
    }

    private static function identityProvider(string $document): IdentityProvider
    {
        return (
            new MetadataReader(
                SamlLoader::create(),
                new MockClock(),
            )->readTrusted(SamlLoader::create()->load($document))->identityProvider ?? static::fail('The document holds no identity provider.')
        );
    }
}
