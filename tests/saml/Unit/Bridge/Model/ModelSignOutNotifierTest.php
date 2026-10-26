<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Exception\SignOutNoticeRefusedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\DeclaredServiceProviderReader;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Bridge\Model\ModelSignOutNotifier;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignatureCertificates;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Xml\Core\Document;
use function base64_decode;
use function parse_url;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-31, section 6.6 step 3: the request the identity provider sends a service provider of an ended
 * session, written with the model's objects, signed by the SAML key of the tenant, sent to the first single logout
 * service of the accepted metadata of that service provider, and read back as the service provider reads it: by the
 * receiver of its binding and saml2-model's LogoutRequestValidator under the certificate the metadata publish.
 */
final class ModelSignOutNotifierTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example/saml/metadata';

    private const string SINGLE_LOGOUT = ServiceProviderDocuments::SIGNED . '/slo';

    private const string UNREGISTERED = 'https://unregistered.example.org/saml';

    private const string SESSION = '0199e8a4-6f00-7000-8000-000000000001';

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
        $this->accept([new Endpoint(Binding::HttpRedirect, self::SINGLE_LOGOUT, self::SINGLE_LOGOUT . '/response')]);
    }

    /**
     * S-31, B-12: over HTTP-Redirect, the URL of the single logout service carries a LogoutRequest signed over its
     * query string, which the service provider accepts under the certificate of the key of the tenant.
     */
    #[Test]
    public function overHttpRedirectTheRequestIsSignedOverItsQueryString(): void
    {
        // When
        $sent = $this->notified();

        // Then
        static::assertSame(Authentication::Binding, $this->accepted($sent)->authentication);
    }

    /**
     * S-31, M-9, Metadata §2.2.2: the request goes to the Location of the single logout service, never its
     * ResponseLocation; it is issued by the identity provider of the tenant at the instant of the notice, valid five
     * minutes, its ID the one the chain waits for.
     */
    #[Test]
    public function theRequestIsAddressedToTheSingleLogoutService(): void
    {
        // Given
        $sent = $this->notified();

        // When
        $request = $this->accepted($sent)->request;

        // Then
        static::assertEquals(
            [self::SINGLE_LOGOUT, new Issuer(self::IDENTITY_PROVIDER), Fixtures::now(), Fixtures::now()->modify('+300 seconds'), $sent->id],
            [$request->destination, $request->issuer, $request->issueInstant, $request->notOnOrAfter, $request->id],
        );
    }

    /**
     * S-31, S-13, S-14: the NameID is the persistent one of the notice, qualified by the two entities as the assertion
     * carried it, and the one SessionIndex is the ID of the session.
     */
    #[Test]
    public function theRequestNamesThePrincipalAndTheSession(): void
    {
        // When
        $request = $this->accepted($this->notified())->request;

        // Then
        static::assertEquals(
            [new NameId('alice-at-sp', NameIdFormat::Persistent, self::IDENTITY_PROVIDER, ServiceProviderDocuments::SIGNED), [self::SESSION]],
            [$request->nameId, $request->sessionIndexes],
        );
    }

    /**
     * S-31: the request carries no RelayState: its answer is found by its InResponseTo.
     */
    #[Test]
    public function theRequestCarriesNoRelayState(): void
    {
        // When / Then
        static::assertNull($this->received($this->notified())->relayState);
    }

    /**
     * S-31, M-2: over HTTP-POST, the form posts to the single logout service a LogoutRequest signed in its XML.
     */
    #[Test]
    public function overHttpPostTheRequestIsSignedInItsXml(): void
    {
        // Given
        $this->accept([new Endpoint(Binding::HttpPost, self::SINGLE_LOGOUT . '/post')]);

        // When
        $sent = $this->notified();

        // Then
        static::assertSame(
            [self::SINGLE_LOGOUT . '/post', Authentication::XmlSignature],
            [$sent->message instanceof PostedForm ? $sent->message->action : null, $this->accepted($sent, self::SINGLE_LOGOUT . '/post')->authentication],
        );
    }

    /**
     * S-37: over HTTP-POST, the signature of the request carries, in its KeyInfo, the one certificate the metadata
     * publish for the key that signed it.
     */
    #[Test]
    public function overHttpPostTheSignatureCarriesTheCertificateOfTheMetadata(): void
    {
        // Given
        $published = SamlKeys::published($this->keys, $this->tenant);
        $this->accept([new Endpoint(Binding::HttpPost, self::SINGLE_LOGOUT . '/post')]);

        // When
        $request = self::posted($this->notified());

        // Then
        static::assertSame([$published], SignatureCertificates::of($request));
    }

    /**
     * S-31: the first single logout service listed is the one told, whatever its binding.
     */
    #[Test]
    public function theFirstSingleLogoutServiceIsTold(): void
    {
        // Given
        $this->accept([
            new Endpoint(Binding::HttpPost, self::SINGLE_LOGOUT . '/post'),
            new Endpoint(Binding::HttpRedirect, self::SINGLE_LOGOUT),
        ]);

        // When / Then
        static::assertSame(self::SINGLE_LOGOUT . '/post', $this->notifier()->destination($this->tenant, ServiceProviderDocuments::SIGNED));
    }

    /**
     * S-30: a service provider nobody declared, one with no accepted document, and one whose metadata list no single
     * logout service, cannot be told.
     */
    #[Test]
    #[DataProvider('provideServiceProvidersThatCannotBeTold')]
    public function aServiceProviderThatCannotBeToldIsSentNothing(string $serviceProvider, bool $withoutSingleLogout): void
    {
        // Given
        if ($withoutSingleLogout) {
            $this->accept([]);
        }

        // When / Then
        static::assertSame(
            [null, null],
            [$this->notifier()->destination($this->tenant, $serviceProvider), $this->notifier()->notify($this->tenant, self::notice($serviceProvider))],
        );
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideServiceProvidersThatCannotBeTold(): iterable
    {
        yield 'a service provider nobody declared' => [self::UNREGISTERED . '/nobody', false];
        yield 'a service provider with no accepted document' => [self::UNREGISTERED, false];
        yield 'a service provider with no single logout service' => [ServiceProviderDocuments::SIGNED, true];
    }

    /**
     * D-16, S-30, S-31: a key Dsig refuses to sign with, under 2 048 bits, signs no request, over either binding: a
     * request the notifier cannot write, which passes its service provider over.
     */
    #[Test]
    #[DataProvider('provideBindings')]
    public function aKeyDsigRefusesSignsNothing(Binding $binding): void
    {
        // Given
        $this->accept([new Endpoint($binding, self::SINGLE_LOGOUT)]);
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
        $this->expectException(SignOutNoticeRefusedException::class);
        $this->expectExceptionMessageIs('The logout request of the identity provider is one its own reader refuses (spec/saml.md S-31).');
        $this->expectExceptionCode(0);

        // When
        $this->notifier()->notify($this->tenant, self::notice());
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
     * The metadata of the signed service provider accepted for the tenant, listing the single logout services given.
     *
     * @param list<Endpoint> $singleLogoutServices
     */
    private function accept(array $singleLogoutServices): void
    {
        $this->accepted->save(new AcceptedServiceProviderMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIGNED,
            ServiceProviderDocuments::signed(null, 'sp', $singleLogoutServices),
            null,
            Fixtures::now(),
        ));
    }

    private function notified(): SentSignOutNotice
    {
        $sent = $this->notifier()->notify($this->tenant, self::notice());
        static::assertNotNull($sent);

        return $sent;
    }

    /**
     * The LogoutRequest the form of HTTP-POST carries, loaded as the service provider loads it.
     */
    private static function posted(SentSignOutNotice $sent): Document
    {
        $message = $sent->message;
        static::assertInstanceOf(PostedForm::class, $message);

        return SamlLoader::create()->load((string) base64_decode($message->fields['SAMLRequest'] ?? '', true));
    }

    private function received(SentSignOutNotice $sent): ReceivedLogoutRequest
    {
        $message = $sent->message;
        $received = $message instanceof RedirectedMessage
            ? new RedirectReceiver(SamlLoader::create())->logoutMessage((string) parse_url($message->url, PHP_URL_QUERY))
            : new PostReceiver(SamlLoader::create())->logoutMessage($message->fields);
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);

        return $received;
    }

    /**
     * The request as the service provider validates it, at its single logout service, under the certificate of the key
     * of the tenant.
     */
    private function accepted(SentSignOutNotice $sent, string $location = self::SINGLE_LOGOUT): AcceptedLogoutRequest
    {
        $certificate = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key));

        return $this->received($sent)->validate(
            new LogoutRequestValidator(SamlLoader::create(), new FrozenClock(Fixtures::now()), new InMemoryReplayGuard()),
            new IdentityProvider(
                self::IDENTITY_PROVIDER,
                [$certificate->base64],
                [],
                [new Endpoint(Binding::HttpRedirect, 'https://id.acme.example/saml/sso')],
            ),
            new ServiceProvider(
                ServiceProviderDocuments::SIGNED,
                [],
                [],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, ServiceProviderDocuments::SIGNED . '/acs', 0)]),
                [new Endpoint(Binding::HttpRedirect, $location)],
            ),
            $location,
        );
    }

    private function notifier(): ModelSignOutNotifier
    {
        return new ModelSignOutNotifier(
            new DeclaredServiceProviderReader(
                new ConfigurationServiceProviders(
                    'acme',
                    [
                        ServiceProviderDocuments::SIGNED => [
                            'metadata' => '/etc/saml/sp.xml',
                        ],
                        self::UNREGISTERED => [
                            'metadata' => '/etc/saml/unregistered.xml',
                        ],
                    ],
                    new FixedClaims(),
                ),
                $this->accepted,
                new ModelServiceProviderMetadataReader(new MockClock(Fixtures::now())),
            ),
            SamlKeys::signing($this->keys),
        );
    }

    private static function notice(string $serviceProvider = ServiceProviderDocuments::SIGNED): SignOutNotice
    {
        return new SignOutNotice(self::IDENTITY_PROVIDER, $serviceProvider, 'alice-at-sp', self::SESSION, Fixtures::now());
    }
}
