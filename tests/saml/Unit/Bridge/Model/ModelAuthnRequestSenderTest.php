<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use function array_map;
use function base64_decode;
use function chunk_split;
use function explode;
use function sprintf;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestSender;
use Beffroi\Saml\Bridge\Model\ModelUpstreamMetadataReader;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\Upstream\AddressHint;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\SignatureCertificates;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Xml\Core\Document;
use const OPENSSL_ALGO_SHA256;
use function openssl_pkey_get_public;
use function openssl_verify;
use function parse_url;
use const PHP_URL_QUERY;
use function rawurldecode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-48, S-49, S-50, section 6.11 steps 4 and 5: the request the service provider of a tenant sends an
 * upstream identity provider, written with the model's objects, signed by the SAML key of the tenant, sent to a single
 * sign-on service of the accepted document of that provider, and read back as the provider reads it: by the receiver
 * of its binding and saml2-model's AuthnRequestValidator under the certificate the metadata of the service provider
 * publish.
 */
final class ModelAuthnRequestSenderTest extends TestCase
{
    private const string SERVICE_PROVIDER = 'https://id.acme.example/saml/sp/metadata';

    private const string ASSERTION_CONSUMER_SERVICE = 'https://id.acme.example/saml/sp/acs';

    private const string SINGLE_SIGN_ON = IdentityProviderDocuments::SIGNED . '/sso';

    private const string REFERENCE = 'Zm9yIHRoZSB0ZXN0IG9mIHRoZSByZWxheSBzdGF0ZSBvbmx5';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private TenantKey $key;

    private InMemoryAcceptedMetadata $accepted;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($this->key);
        $this->accepted = new InMemoryAcceptedMetadata();
        $this->accept([new Endpoint(Binding::HttpRedirect, self::SINGLE_SIGN_ON)]);
    }

    /**
     * S-48, B-12: over HTTP-Redirect, the URL of the single sign-on service carries an AuthnRequest signed over its
     * query string, which the provider accepts under the certificate the metadata of the service provider publish.
     */
    #[Test]
    public function overHttpRedirectTheRequestIsSignedOverItsQueryString(): void
    {
        // When
        $sent = $this->sent();

        // Then
        static::assertSame(Authentication::Binding, $this->acceptedBy($sent, Binding::HttpRedirect)->authentication);
    }

    /**
     * S-48, M-2: over HTTP-POST, the form posts to the single sign-on service an AuthnRequest signed in its XML.
     */
    #[Test]
    public function overHttpPostTheRequestIsSignedInItsXml(): void
    {
        // Given
        $this->accept([new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON)]);

        // When
        $sent = $this->sent();

        // Then
        static::assertSame(
            [self::SINGLE_SIGN_ON, Authentication::XmlSignature],
            [$sent->message instanceof PostedForm ? $sent->message->action : null, $this->acceptedBy($sent, Binding::HttpPost)->authentication],
        );
    }

    /**
     * S-37, S-48: over HTTP-POST, the signature of the request carries, in its KeyInfo, the one certificate the
     * metadata publish for the key that signed it.
     */
    #[Test]
    public function overHttpPostTheSignatureCarriesTheCertificateOfTheMetadata(): void
    {
        // Given
        $published = SamlKeys::published($this->keys, $this->tenant);
        $this->accept([new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON)]);

        // When
        $request = self::posted($this->sent());

        // Then
        static::assertSame([$published], SignatureCertificates::of($request));
    }

    /**
     * S-48: the request goes to the single sign-on service of the accepted document, is issued by the service
     * provider of the tenant at the instant it is written from, its ID the one the sign-on is remembered by, and asks
     * for the response at the assertion consumer service of the metadata of the service provider, over HTTP-POST.
     */
    #[Test]
    public function theRequestIsAddressedToTheSingleSignOnService(): void
    {
        // Given
        $sent = $this->sent();

        // When
        $request = $this->acceptedBy($sent, Binding::HttpRedirect)->request;

        // Then
        static::assertEquals(
            [
                self::SINGLE_SIGN_ON,
                new Issuer(self::SERVICE_PROVIDER),
                Fixtures::now(),
                $sent->id,
                self::ASSERTION_CONSUMER_SERVICE,
                Binding::HttpPost->value,
                null,
            ],
            [
                $request->destination,
                $request->issuer,
                $request->issueInstant,
                $request->id,
                $request->assertionConsumerServiceUrl,
                $request->protocolBinding,
                $request->assertionConsumerServiceIndex,
            ],
        );
    }

    /**
     * S-48: the request asks for a persistent identifier the provider may create, and neither a passive login nor a
     * class of authentication.
     */
    #[Test]
    public function theRequestAsksForAPersistentIdentifierTheProviderMayCreate(): void
    {
        // When
        $request = $this->acceptedBy($this->sent(), Binding::HttpRedirect)->request;

        // Then
        static::assertEquals(
            [new NameIdPolicy(NameIdFormat::Persistent->value, null, true), false, null],
            [$request->nameIdPolicy, $request->isPassive, $request->requestedAuthnContext],
        );
    }

    /**
     * S-49: ForceAuthn is written when the request asks for a fresh login, and not otherwise.
     */
    #[Test]
    #[DataProvider('provideForceAuthn')]
    public function forceAuthnIsWrittenAsTheRequestAsks(bool $forceAuthn): void
    {
        // When
        $request = $this->acceptedBy($this->sent(self::request($forceAuthn)), Binding::HttpRedirect)->request;

        // Then
        static::assertSame($forceAuthn, $request->forceAuthn);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideForceAuthn(): iterable
    {
        yield 'a fresh login' => [true];
        yield 'any login' => [false];
    }

    /**
     * S-50: the RelayState of the message is the reference of the request, and nothing else, over either binding.
     */
    #[Test]
    #[DataProvider('provideBindings')]
    public function theRelayStateIsTheReference(Binding $binding): void
    {
        // Given
        $this->accept([new Endpoint($binding, self::SINGLE_SIGN_ON)]);

        // When
        $received = self::received($this->sent());

        // Then
        static::assertSame(self::REFERENCE, $received->relayState);
    }

    /**
     * S-48: the single sign-on service on HTTP-Redirect is the one the request goes to when the document lists both
     * bindings, whatever their order.
     *
     * @param list<Endpoint> $singleSignOnServices
     */
    #[Test]
    #[DataProvider('provideBothBindings')]
    public function theServiceOnHttpRedirectIsChosen(array $singleSignOnServices): void
    {
        // Given
        $this->accept($singleSignOnServices);

        // When
        $message = $this->sent()->message;

        // Then
        static::assertInstanceOf(RedirectedMessage::class, $message);
        static::assertStringStartsWith(self::SINGLE_SIGN_ON . '/redirect?SAMLRequest=', $message->url);
    }

    /**
     * @return iterable<string, array{list<Endpoint>}>
     */
    public static function provideBothBindings(): iterable
    {
        yield 'HTTP-Redirect first' => [[
            new Endpoint(Binding::HttpRedirect, self::SINGLE_SIGN_ON . '/redirect'),
            new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON . '/post'),
        ]];
        yield 'HTTP-POST first' => [[
            new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON . '/post'),
            new Endpoint(Binding::HttpRedirect, self::SINGLE_SIGN_ON . '/redirect'),
        ]];
    }

    /**
     * S-61, S-48: the destination a page names in its "form-action" is the single sign-on service the request is written
     * to, the one on HTTP-Redirect whatever the order of the document.
     *
     * @param list<Endpoint> $singleSignOnServices
     */
    #[Test]
    #[DataProvider('provideBothBindings')]
    public function theDestinationIsTheServiceTheRequestIsWrittenTo(array $singleSignOnServices): void
    {
        // Given
        $this->accept($singleSignOnServices);

        // When / Then
        static::assertSame(self::SINGLE_SIGN_ON . '/redirect', $this->sender()->destination($this->tenant, IdentityProviderDocuments::SIGNED));
    }

    /**
     * S-61, S-48: a provider with no accepted document has no destination, a sign-on of it being refused.
     */
    #[Test]
    public function aProviderWithNoAcceptedDocumentHasNoDestination(): void
    {
        // Given
        $this->accepted = new InMemoryAcceptedMetadata();

        // Then
        $this->expectException(UpstreamSignOnRefusedException::class);
        $this->expectExceptionMessageIs('The identity provider has no metadata accepted yet (spec/saml.md S-48).');

        // When
        $this->sender()->destination($this->tenant, IdentityProviderDocuments::SIGNED);
    }

    /**
     * S-48: the first single sign-on service on HTTP-POST is the one the request goes to when the document lists no
     * other binding.
     */
    #[Test]
    public function theFirstServiceOnHttpPostIsChosenWhenThereIsNoOther(): void
    {
        // Given
        $this->accept([
            new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON . '/first'),
            new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON . '/second'),
        ]);

        // When
        $message = $this->sent()->message;

        // Then
        static::assertInstanceOf(PostedForm::class, $message);
        static::assertSame(self::SINGLE_SIGN_ON . '/first', $message->action);
    }

    /**
     * S-48: a provider with no accepted document is sent nothing.
     */
    #[Test]
    public function aProviderWithNoAcceptedDocumentIsRefused(): void
    {
        // Given
        $this->accepted = new InMemoryAcceptedMetadata();

        // Then
        $this->expectException(UpstreamSignOnRefusedException::class);
        $this->expectExceptionMessageIs('The identity provider has no metadata accepted yet (spec/saml.md S-48).');

        // When
        $this->sender()->send($this->tenant, self::request());
    }

    /**
     * S-43, S-48: a document accepted before that the reading back refuses now is sent nothing, the refusal of the
     * reading given as it is.
     */
    #[Test]
    public function aDocumentTheReadingBackRefusesIsRefused(): void
    {
        // Given
        $this->acceptDocument(IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey());

        // Then
        $this->expectException(UpstreamSignOnRefusedException::class);
        $this->expectExceptionMessageIs('The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).');
        $this->expectExceptionCode(0);

        // When
        $this->sender()->send($this->tenant, self::request());
    }

    /**
     * S-48, section 6.3 of bindings.md: a single sign-on service the binding refuses to send a browser to, its query
     * holding a parameter of HTTP-Redirect, is sent nothing.
     */
    #[Test]
    public function aServiceTheBindingRefusesIsRefused(): void
    {
        // Given
        $this->accept([new Endpoint(Binding::HttpRedirect, self::SINGLE_SIGN_ON . '?SAMLRequest=planted')]);

        // Then
        $this->expectException(UpstreamSignOnRefusedException::class);
        $this->expectExceptionMessageIs('The request to the identity provider is one the model or the binding refuses to write (spec/saml.md S-48).');
        $this->expectExceptionCode(0);

        // When
        $this->sender()->send($this->tenant, self::request());
    }

    /**
     * D-16, S-48: a key Dsig refuses to sign with, under 2 048 bits, signs no request, over either binding.
     */
    #[Test]
    #[DataProvider('provideBindings')]
    public function aKeyDsigRefusesSignsNothing(Binding $binding): void
    {
        // Given
        $this->accept([new Endpoint($binding, self::SINGLE_SIGN_ON)]);
        $weak = SamlKeys::weakPair();
        $key = new TenantKey(
            $weak->kid,
            $this->tenant,
            SamlKeys::algorithm(),
            $weak->publicJwk,
            Keys::sealer()->seal($this->tenant, $weak->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($key);

        // Then
        $this->expectException(UpstreamSignOnRefusedException::class);
        $this->expectExceptionMessageIs('The request to the identity provider is one the model or the binding refuses to write (spec/saml.md S-48).');
        $this->expectExceptionCode(0);

        // When
        $this->sender()->send($this->tenant, self::request());
    }

    /**
     * S-48, section 6.11 step 5: a key of the tenant whose private half is not the one of its public JWK is a fault of
     * the deployment, which goes on as it is, and never a request refused as one the model refuses to write, which
     * would answer a person with a page and write nothing to the log.
     */
    #[Test]
    public function aKeyWhosePrivateHalfIsNotItsOwnIsNoRequestRefused(): void
    {
        // Given
        $pair = SamlKeys::pair();
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            SamlKeys::algorithm(),
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, SamlKeys::otherPair()->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($key);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The private half of the key "%s" is not the one of its public JWK: its "n" differs (spec/saml.md section 6.1 step 2).',
            $pair->kid,
        ));

        // When
        $this->sender()->send($this->tenant, self::request());
    }

    /**
     * @return iterable<string, array{Binding}>
     */
    public static function provideBindings(): iterable
    {
        yield 'HTTP-Redirect' => [Binding::HttpRedirect];
        yield 'HTTP-POST' => [Binding::HttpPost];
    }

    /**
     * S-68, Bindings §3.4.4.1: over HTTP-Redirect, the hint of the address comes after the Signature, the last
     * parameter of the URL, its value percent-encoded.
     */
    #[Test]
    public function overHttpRedirectTheHintComesAfterTheSignature(): void
    {
        // When
        $url = self::redirected($this->sent(self::hinted()));

        // Then
        static::assertSame(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature', 'login_hint'], self::parameterNames($url));
        static::assertStringEndsWith('&login_hint=alice%40acme.example', $url);
    }

    /**
     * S-68, S-48: over HTTP-Redirect, the request carrying a hint is still accepted signed over its query string, the
     * hint outside the octets the signature covers.
     */
    #[Test]
    public function overHttpRedirectTheRequestCarryingAHintIsStillAcceptedSigned(): void
    {
        // When
        $sent = $this->sent(self::hinted());

        // Then
        static::assertSame(Authentication::Binding, $this->acceptedBy($sent, Binding::HttpRedirect)->authentication);
    }

    /**
     * S-68, Bindings §3.4.4.1, bindings.md section 9.1: OpenSSL verifies the signature of the URL carrying a hint over
     * the octets the oracle of saml2-bindings rebuilds from it, the raw values of SAMLRequest, RelayState and SigAlg
     * taken by name and every other parameter skipped (tests/saml2-bindings/Fixture/oracle/read-redirect-url.py),
     * under the certificate of the key of the tenant.
     */
    #[Test]
    public function overHttpRedirectOpenSslVerifiesTheOctetsTheOracleRebuilds(): void
    {
        // Given
        $raw = [];
        foreach (explode('&', (string) parse_url(self::redirected($this->sent(self::hinted())), PHP_URL_QUERY)) as $segment) {
            [$name, $value] = explode('=', $segment, 2);
            $raw[$name] = $value;
        }
        $octets = sprintf('SAMLRequest=%s&RelayState=%s&SigAlg=%s', $raw['SAMLRequest'] ?? '', $raw['RelayState'] ?? '', $raw['SigAlg'] ?? '');
        $certificate = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key));
        $public = openssl_pkey_get_public(sprintf("-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n", chunk_split($certificate->base64, 64, "\n")));
        static::assertNotFalse($public);

        // When
        $verified = openssl_verify($octets, (string) base64_decode(rawurldecode($raw['Signature'] ?? ''), true), $public, OPENSSL_ALGO_SHA256);

        // Then
        static::assertSame(1, $verified);
    }

    /**
     * S-68: over HTTP-POST, the hint of the address is in the query of the action of the form, after the query the
     * single sign-on service holds, and the request posted is still accepted signed in its XML.
     */
    #[Test]
    #[DataProvider('provideSingleSignOnServicesOverPost')]
    public function overHttpPostTheHintIsInTheQueryOfTheAction(string $location, string $action): void
    {
        // Given
        $this->accept([new Endpoint(Binding::HttpPost, $location)]);

        // When
        $sent = $this->sent(self::hinted());

        // Then
        static::assertSame($action, $sent->message instanceof PostedForm ? $sent->message->action : null);
        static::assertSame(Authentication::XmlSignature, $this->acceptedBy($sent, Binding::HttpPost, $location)->authentication);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSingleSignOnServicesOverPost(): iterable
    {
        yield 'a service without a query' => [self::SINGLE_SIGN_ON, self::SINGLE_SIGN_ON . '?login_hint=alice%40acme.example'];
        yield 'a service with a query' => [self::SINGLE_SIGN_ON . '?tenant=acme', self::SINGLE_SIGN_ON . '?tenant=acme&login_hint=alice%40acme.example'];
    }

    /**
     * S-68: a request without a hint is sent as the binding wrote it, the Signature last over HTTP-Redirect and the
     * single sign-on service the action over HTTP-POST.
     */
    #[Test]
    public function withoutAHintTheMessageIsTheOneTheBindingWrote(): void
    {
        // Given
        $redirected = self::redirected($this->sent());
        $this->accept([new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON)]);

        // When
        $posted = $this->sent();

        // Then
        static::assertSame(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'], self::parameterNames($redirected));
        static::assertSame(self::SINGLE_SIGN_ON, $posted->message instanceof PostedForm ? $posted->message->action : null);
    }

    /**
     * The metadata of the provider accepted for the tenant, listing the single sign-on services given.
     *
     * @param list<Endpoint> $singleSignOnServices
     */
    private function accept(array $singleSignOnServices): void
    {
        $this->acceptDocument(IdentityProviderDocuments::signingOnAt($singleSignOnServices));
    }

    private function acceptDocument(string $document): void
    {
        $this->accepted->save(new AcceptedUpstreamMetadata(
            Uuid::v7(),
            $this->tenant,
            IdentityProviderDocuments::SIGNED,
            $document,
            null,
            Fixtures::now(),
        ));
    }

    private function sender(): ModelAuthnRequestSender
    {
        return new ModelAuthnRequestSender(
            $this->accepted,
            new ModelUpstreamMetadataReader(new MockClock(Fixtures::now())),
            SamlKeys::signing($this->keys),
        );
    }

    private static function request(bool $forceAuthn = false, ?AddressHint $addressHint = null): UpstreamAuthnRequest
    {
        return new UpstreamAuthnRequest(
            IdentityProviderDocuments::SIGNED,
            new ServiceProviderEndpoints(self::SERVICE_PROVIDER, self::SERVICE_PROVIDER, self::ASSERTION_CONSUMER_SERVICE),
            $forceAuthn,
            self::REFERENCE,
            Fixtures::now(),
            $addressHint,
        );
    }

    private static function hinted(): UpstreamAuthnRequest
    {
        return self::request(addressHint: new AddressHint('login_hint', new EmailAddress('alice@acme.example')));
    }

    /**
     * The URL of HTTP-Redirect the request was sent with.
     */
    private static function redirected(SentAuthnRequest $sent): string
    {
        $message = $sent->message;
        static::assertInstanceOf(RedirectedMessage::class, $message);

        return $message->url;
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

    private function sent(?UpstreamAuthnRequest $request = null): SentAuthnRequest
    {
        return $this->sender()->send($this->tenant, $request ?? self::request());
    }

    /**
     * The AuthnRequest the form of HTTP-POST carries, loaded as the provider loads it.
     */
    private static function posted(SentAuthnRequest $sent): Document
    {
        $message = $sent->message;
        static::assertInstanceOf(PostedForm::class, $message);

        return SamlLoader::create()->load((string) base64_decode($message->fields['SAMLRequest'] ?? '', true));
    }

    private static function received(SentAuthnRequest $sent): ReceivedAuthnRequest
    {
        $message = $sent->message;

        return $message instanceof RedirectedMessage
            ? new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($message->url, PHP_URL_QUERY))
            : new PostReceiver(SamlLoader::create())->authnRequest($message->fields);
    }

    /**
     * The request as the provider validates it, at its single sign-on service, under the certificate of the key of the
     * tenant the metadata of the service provider publish.
     */
    private function acceptedBy(SentAuthnRequest $sent, Binding $binding, string $location = self::SINGLE_SIGN_ON): AcceptedAuthnRequest
    {
        $certificate = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key));

        return self::received($sent)
            ->validate(
                new AuthnRequestValidator(SamlLoader::create(), new FrozenClock(Fixtures::now())),
                new ServiceProvider(
                    self::SERVICE_PROVIDER,
                    [$certificate->base64],
                    [],
                    new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ASSERTION_CONSUMER_SERVICE, 0)]),
                ),
                new IdentityProvider(
                    IdentityProviderDocuments::SIGNED,
                    [MetadataFixtures::certificate('idp')],
                    [],
                    [new Endpoint($binding, $location)],
                ),
                $location,
            );
    }
}
