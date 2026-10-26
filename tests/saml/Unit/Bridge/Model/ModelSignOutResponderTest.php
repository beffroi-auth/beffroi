<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Bridge\Model\ModelSignOutResponder;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignatureCertificates;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Xml\Core\Document;
use function base64_decode;
use function parse_url;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 6.5 step 4, S-27: the answer to a logout request written with the model's objects, signed by
 * the SAML key of the tenant, and sent over the binding of the single logout service resolved when the request was
 * received, read back as the service provider reads it: by the receiver of that binding and saml2-model's
 * LogoutResponseValidator under the certificate the metadata publish.
 */
final class ModelSignOutResponderTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example/saml/metadata';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private TenantKey $key;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($this->key);
    }

    /**
     * S-27, B-12: over HTTP-Redirect, the URL of the single logout service carries a LogoutResponse signed over its
     * query string, which the service provider accepts under the certificate of the key of the tenant.
     */
    #[Test]
    public function overHttpRedirectTheAnswerIsSignedOverItsQueryString(): void
    {
        // When
        $answer = $this->responder()->answer($this->tenant, self::response());

        // Then
        static::assertSame(Authentication::Binding, $this->accepted($answer)->authentication);
    }

    /**
     * S-27, M-9, M-10: the answer goes to the single logout service resolved, answers the request, and is issued by the
     * identity provider of the tenant at the instant given.
     */
    #[Test]
    public function theAnswerIsAddressedToTheRequest(): void
    {
        // When
        $response = $this->accepted($this->responder()->answer($this->tenant, self::response()))->response;

        // Then
        static::assertEquals(
            [SignOutRequests::SINGLE_LOGOUT, SignOutRequests::ID, new Issuer(self::IDENTITY_PROVIDER), Fixtures::now()],
            [$response->destination, $response->inResponseTo, $response->issuer, $response->issueInstant],
        );
    }

    /**
     * B-9: the RelayState received comes back byte for byte.
     */
    #[Test]
    public function theRelayStateComesBack(): void
    {
        // Given
        $answer = $this->responder()->answer($this->tenant, self::response(relayState: "a state <with> & \u{e9}"));

        // When
        $received = $this->received($answer);

        // Then
        static::assertSame("a state <with> & \u{e9}", $received->relayState);
    }

    /**
     * S-27, M-2: over HTTP-POST, the form posts to the single logout service a LogoutResponse signed in its XML.
     */
    #[Test]
    public function overHttpPostTheAnswerIsSignedInItsXml(): void
    {
        // Given
        $response = self::response(answerBinding: SignOutRequests::POST, answerLocation: SignOutRequests::SINGLE_LOGOUT . '/post');

        // When
        $answer = $this->responder()->answer($this->tenant, $response);

        // Then
        static::assertSame(
            [SignOutRequests::SINGLE_LOGOUT . '/post', Authentication::XmlSignature],
            [$answer instanceof PostedForm ? $answer->action : null, $this->accepted($answer, SignOutRequests::SINGLE_LOGOUT . '/post')->authentication],
        );
    }

    /**
     * S-37: over HTTP-POST, the signature of the answer carries, in its KeyInfo, the one certificate the metadata
     * publish for the key that signed it.
     */
    #[Test]
    public function overHttpPostTheSignatureCarriesTheCertificateOfTheMetadata(): void
    {
        // Given
        $published = SamlKeys::published($this->keys, $this->tenant);

        // When
        $response = self::posted($this->responder()->answer($this->tenant, self::response(answerBinding: SignOutRequests::POST)));

        // Then
        static::assertSame([$published], SignatureCertificates::of($response));
    }

    /**
     * S-24, S-34, Core §3.2.2.2: the status of the answer, Success alone, Success above PartialLogout, or Requester
     * above the code of the refusal.
     */
    #[Test]
    #[DataProvider('provideStatuses')]
    public function theStatusSaysWhatEnded(SignOutStatus $status, Status $expected): void
    {
        // When
        $response = $this->accepted($this->responder()->answer($this->tenant, self::response($status)))->response;

        // Then
        static::assertEquals($expected, $response->status);
    }

    /**
     * @return iterable<string, array{SignOutStatus, Status}>
     */
    public static function provideStatuses(): iterable
    {
        yield 'every session ended' => [SignOutStatus::Success, new Status(StatusCode::Success)];
        yield 'a service provider of the session not told' => [
            SignOutStatus::PartialLogout,
            new Status(StatusCode::Success, SecondLevelStatusCode::PartialLogout),
        ];
        yield 'another principal' => [SignOutStatus::UnknownPrincipal, new Status(StatusCode::Requester, SecondLevelStatusCode::UnknownPrincipal)];
        yield 'no session index' => [SignOutStatus::RequestUnsupported, new Status(StatusCode::Requester, SecondLevelStatusCode::RequestUnsupported)];
    }

    /**
     * S-27, S-1: a tenant without an active SAML key cannot answer.
     */
    #[Test]
    public function aTenantWithoutAnActiveKeyCannotAnswer(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->responder()->answer(Fixtures::tenant('globex', 'https://id.globex.example'), self::response());
    }

    /**
     * S-27, section 6.5 step 1: a tenant without an active SAML key has none to open, before any request is read.
     */
    #[Test]
    public function aTenantWithoutAnActiveKeyHasNoneToOpen(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->responder()->open(Fixtures::tenant('globex', 'https://id.globex.example'));
    }

    /**
     * D-16, S-1, section 6.5 step 1: a key that cannot sign, one Dsig refuses under 2 048 bits or one whose private half
     * is not the one of its public JWK, is refused when it is opened, before any request is read.
     */
    #[Test]
    #[DataProvider('provideKeysThatCannotSign')]
    public function aKeyThatCannotSignIsRefusedWhenItIsOpened(GeneratedKeyPair $public, GeneratedKeyPair $private): void
    {
        // Given
        $key = new TenantKey(
            $public->kid,
            $this->tenant,
            SamlKeys::algorithm(),
            $public->publicJwk,
            Keys::sealer()->seal($this->tenant, $private->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($key);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The active SAML key of the tenant is one Dsig refuses to sign with (spec/saml.md section 6.5 step 1).');
        $this->expectExceptionCode(0);

        // When
        $this->responder()->open($this->tenant);
    }

    /**
     * @return iterable<string, array{GeneratedKeyPair, GeneratedKeyPair}>
     */
    public static function provideKeysThatCannotSign(): iterable
    {
        yield 'a key under 2 048 bits' => [SamlKeys::weakPair(), SamlKeys::weakPair()];
        yield 'a private half that is not the key\'s' => [SamlKeys::pair(), SamlKeys::otherPair()];
    }

    /**
     * D-16, section 6.5 step 4: a key Dsig refuses to sign with, under 2 048 bits, signs no answer, over either binding.
     */
    #[Test]
    #[DataProvider('provideBindings')]
    public function aKeyDsigRefusesSignsNothing(string $binding): void
    {
        // Given
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
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The answer of single logout is one its own reader refuses (spec/saml.md section 6.5 step 4).');
        $this->expectExceptionCode(0);

        // When
        $this->responder()->answer($this->tenant, self::response(answerBinding: $binding));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBindings(): iterable
    {
        yield 'HTTP-Redirect' => [SignOutRequests::REDIRECT];
        yield 'HTTP-POST' => [SignOutRequests::POST];
    }

    private function responder(): ModelSignOutResponder
    {
        return new ModelSignOutResponder(SamlKeys::signing($this->keys));
    }

    /**
     * The LogoutResponse the form of HTTP-POST carries, loaded as the service provider loads it.
     */
    private static function posted(PostedForm|RedirectedMessage $answer): Document
    {
        static::assertInstanceOf(PostedForm::class, $answer);

        return SamlLoader::create()->load((string) base64_decode($answer->fields['SAMLResponse'] ?? '', true));
    }

    private function received(PostedForm|RedirectedMessage $answer): ReceivedLogoutResponse
    {
        $received = $answer instanceof RedirectedMessage
            ? new RedirectReceiver(SamlLoader::create())->logoutMessage((string) parse_url($answer->url, PHP_URL_QUERY))
            : new PostReceiver(SamlLoader::create())->logoutMessage($answer->fields);
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);

        return $received;
    }

    /**
     * The answer as the service provider validates it, at its single logout service, under the certificate of the key
     * of the tenant.
     */
    private function accepted(PostedForm|RedirectedMessage $answer, string $location = SignOutRequests::SINGLE_LOGOUT): AcceptedLogoutResponse
    {
        $certificate = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key));

        return $this->received($answer)->validate(
            new LogoutResponseValidator(SamlLoader::create(), new FrozenClock(Fixtures::now()), new InMemoryReplayGuard()),
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
            SignOutRequests::ID,
        );
    }

    private static function response(
        SignOutStatus $status = SignOutStatus::Success,
        ?string $relayState = 'state-1',
        string $answerBinding = SignOutRequests::REDIRECT,
        string $answerLocation = SignOutRequests::SINGLE_LOGOUT,
    ): SignOutResponse {
        return new SignOutResponse(
            self::IDENTITY_PROVIDER,
            SignOutRequests::request(
                'alice-at-sp',
                ['the-session'],
                relayState: $relayState,
                answerBinding: $answerBinding,
                answerLocation: $answerLocation,
            )->requester(),
            $status,
            Fixtures::now(),
        );
    }
}
