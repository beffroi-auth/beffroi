<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use function base64_encode;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\DeclaredServiceProviderReader;
use Beffroi\Saml\Bridge\Model\ModelLogoutMessageReceiver;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\InMemoryLogoutChains;
use Beffroi\Saml\Tests\Fixture\InMemoryReplayStore;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use function explode;
use function parse_url;
use function str_replace;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.5 step 1, S-22, S-23, S-27: a logout request of a declared service provider received over
 * either binding, validated by the model at the URL of the single logout service of the tenant, remembered once, and
 * the single logout service its answer goes to resolved among those of the accepted metadata. Section 6.6 step 4, S-33:
 * the logout response of the request an open chain waits for, validated the same way under the metadata of the
 * service provider that request went to. Anything else refused without a SAML answer.
 */
final class ModelLogoutMessageReceiverTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    private const string SINGLE_LOGOUT = self::ISSUER . FixedEndpoints::SINGLE_LOGOUT;

    private const string UNREGISTERED = 'https://unregistered.example.org/saml';

    private const string POST_LOCATION = ServiceProviderDocuments::SIGNED . '/slo/post';

    private const string POST_RESPONSE_LOCATION = ServiceProviderDocuments::SIGNED . '/slo/post/response';

    private const string AWAITED = '_7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d';

    private const string RESPONSE_ID = '_1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e';

    private Tenant $tenant;

    private InMemoryAcceptedMetadata $accepted;

    private InMemoryReplayStore $replay;

    private MockClock $clock;

    private InMemoryLogoutChains $chains;

    /**
     * The secret of the browser the chains of the test are bound to (S-32).
     */
    private LogoutChainSecret $secret;

    protected function setUp(): void
    {
        $this->secret = LogoutChainSecret::draw();
        $this->tenant = Fixtures::tenant('acme', self::ISSUER);
        $this->accepted = new InMemoryAcceptedMetadata();
        $this->replay = new InMemoryReplayStore();
        $this->clock = new MockClock(Fixtures::now());
        $this->chains = new InMemoryLogoutChains();
        $this->accept([
            new Endpoint(Binding::HttpRedirect, SignOutRequests::SINGLE_LOGOUT),
            new Endpoint(Binding::HttpPost, self::POST_LOCATION, self::POST_RESPONSE_LOCATION),
        ]);
    }

    /**
     * S-22, B-2, S-27: a request signed over its query string is accepted, its NameID, its session indexes and its
     * RelayState as they were sent, its answer going to the single logout service of the metadata on HTTP-Redirect.
     */
    #[Test]
    public function aRequestSignedOverHttpRedirectIsAccepted(): void
    {
        // When
        $request = $this->receiver()->redirect($this->tenant, $this->redirected(), $this->secret);

        // Then
        static::assertEquals(
            SignOutRequests::request(
                'alice-at-sp',
                ['the-session'],
                PersistentNameId::FORMAT,
                self::ISSUER . FixedEndpoints::METADATA,
                ServiceProviderDocuments::SIGNED,
            ),
            $request,
        );
    }

    /**
     * S-22, M-2, S-27, SAML Metadata §2.2.2: a request signed in its XML over HTTP-POST is accepted, its answer going to
     * the ResponseLocation of the single logout service on HTTP-POST.
     */
    #[Test]
    public function aRequestSignedOverHttpPostIsAnsweredAtTheResponseLocation(): void
    {
        // When
        $request = self::acceptedRequest($this->receiver()->post($this->tenant, $this->posted(), $this->secret));

        // Then
        static::assertSame(
            [SignOutRequests::POST, self::POST_RESPONSE_LOCATION, 'state-1'],
            [$request->answerBinding, $request->answerLocation, $request->relayState],
        );
    }

    /**
     * S-27: without a single logout service on the binding of the request, the answer goes to the first one listed.
     */
    #[Test]
    public function withoutAServiceOnTheBindingOfTheRequestTheFirstListedAnswers(): void
    {
        // Given
        $this->accept([new Endpoint(Binding::HttpPost, self::POST_LOCATION)]);

        // When
        $request = self::acceptedRequest($this->receiver()->redirect($this->tenant, $this->redirected(), $this->secret));

        // Then
        static::assertSame([SignOutRequests::POST, self::POST_LOCATION], [$request->answerBinding, $request->answerLocation]);
    }

    /**
     * S-27: the first single logout service listed on the binding of the request answers, not a later one.
     */
    #[Test]
    public function theFirstServiceOnTheBindingOfTheRequestAnswers(): void
    {
        // Given
        $this->accept([
            new Endpoint(Binding::HttpPost, self::POST_LOCATION),
            new Endpoint(Binding::HttpRedirect, SignOutRequests::SINGLE_LOGOUT),
            new Endpoint(Binding::HttpRedirect, SignOutRequests::SINGLE_LOGOUT . '/other'),
        ]);

        // When
        $request = self::acceptedRequest($this->receiver()->redirect($this->tenant, $this->redirected(), $this->secret));

        // Then
        static::assertSame([SignOutRequests::REDIRECT, SignOutRequests::SINGLE_LOGOUT], [$request->answerBinding, $request->answerLocation]);
    }

    /**
     * S-22, S-27: a service provider whose metadata list no single logout service is refused: its answer could go
     * nowhere.
     */
    #[Test]
    public function aServiceProviderWithoutSingleLogoutServiceIsRefused(): void
    {
        // Given
        $this->accept([]);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The metadata of the service provider list no single logout service the answer could go to (spec/saml.md S-27).');

        // When
        $this->receiver()->redirect($this->tenant, $this->redirected(), $this->secret);
    }

    /**
     * S-23, M-11, issue #708: the same request received twice is refused the second time.
     */
    #[Test]
    public function theSameRequestIsRefusedTheSecondTime(): void
    {
        // Given
        $query = $this->redirected();
        $this->receiver()->redirect($this->tenant, $query, $this->secret);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The logout message was already accepted from its issuer (M-11).');

        // When
        $this->receiver()->redirect($this->tenant, $query, $this->secret);
    }

    /**
     * S-23, M-11: the store of the tenant remembers the issuer and the ID of the request until its IssueInstant plus
     * maxMessageAge and the skew.
     */
    #[Test]
    public function theRequestIsRememberedUnderTheTenant(): void
    {
        // When
        $this->receiver()->redirect($this->tenant, $this->redirected(), $this->secret);

        // Then
        static::assertEquals(
            Fixtures::now()->modify('+480 seconds'),
            $this->replay->expiresAt($this->tenant, ServiceProviderDocuments::SIGNED, SignOutRequests::ID),
        );
    }

    /**
     * S-22, M-2, SAML Profiles §4.4.4.1: a request whose query string carries no signature, and none in its XML.
     */
    #[Test]
    public function anUnsignedRequestOverHttpRedirectIsRefused(): void
    {
        // Given
        [$query] = explode('&SigAlg=', $this->redirected());

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->receiver()->redirect($this->tenant, $query, $this->secret);
    }

    /**
     * S-22, M-2: a request posted without its XML signature, from a provider that signs nothing else either.
     */
    #[Test]
    public function anUnsignedRequestOverHttpPostIsRefused(): void
    {
        // Given
        $document = new Serializer()->serialize(new LogoutRequestWriter()->write(self::request(), null));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->receiver()->post($this->tenant, ['SAMLRequest' => base64_encode($document)], $this->secret);
    }

    /**
     * S-22, section 6.3 step 1: an issuer nobody declared.
     */
    #[Test]
    public function anIssuerNobodyDeclaredIsRefused(): void
    {
        // Given
        $request = self::request(self::UNREGISTERED . '/nobody');

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The Issuer of the request is no service provider this tenant declares (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->post($this->tenant, new PostSender()->logoutRequest($request, self::signing(), 'state-1')->fields, $this->secret);
    }

    /**
     * S-22, section 6.3 step 1: a service provider declared whose metadata were never accepted.
     */
    #[Test]
    public function aServiceProviderWithoutAcceptedMetadataIsRefused(): void
    {
        // Given
        $request = self::request(self::UNREGISTERED);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The service provider of the request has no metadata accepted yet (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->post($this->tenant, new PostSender()->logoutRequest($request, self::signing(), 'state-1')->fields, $this->secret);
    }

    /**
     * S-33, B-2, section 6.6 step 4: the LogoutResponse of the request a chain waits for, signed over its query string
     * by the service provider that request went to, is accepted as the answer of that chain, Success.
     */
    #[Test]
    public function theAnswerOfTheRequestAwaitedOverHttpRedirectIsAccepted(): void
    {
        // Given
        $chain = $this->awaiting();

        // When
        $answer = $this->receiver()->redirect($this->tenant, self::answeredOverRedirect(self::response()), $this->secret);

        // Then
        static::assertEquals(new SignOutAnswer($chain, true, $this->secret), $answer);
    }

    /**
     * S-33, M-2, model.md section 6.4: the answer signed in its XML over HTTP-POST, its status other than Success, is
     * an answer and not a refusal.
     */
    #[Test]
    public function anAnswerOverHttpPostThatIsNotSuccessIsAccepted(): void
    {
        // Given
        $chain = $this->awaiting();
        $response = self::response(new Status(StatusCode::Responder, SecondLevelStatusCode::PartialLogout));

        // When
        $answer = $this->receiver()->post($this->tenant, new PostSender()->logoutResponse($response, self::signing())->fields, $this->secret);

        // Then
        static::assertEquals(new SignOutAnswer($chain, false, $this->secret), $answer);
    }

    /**
     * S-33: an answer naming no request is refused before any key is read.
     */
    #[Test]
    public function anAnswerNamingNoRequestIsRefused(): void
    {
        // Given
        $this->awaiting();
        $document = new Serializer()->serialize(new LogoutResponseWriter()->write(self::response(), null));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The LogoutResponse answers no request an open chain of logout waits for (spec/saml.md S-33).');

        // When
        $this->receiver()->post(
            $this->tenant,
            ['SAMLResponse' => base64_encode(str_replace(' InResponseTo="' . self::AWAITED . '"', '', $document))],
            $this->secret,
        );
    }

    /**
     * S-33, S-32: an answer naming a request no chain waits for, and the answer of a chain past its ten minutes, are
     * refused before any key is read.
     */
    #[Test]
    #[DataProvider('provideAnswersNobodyWaitsFor')]
    public function anAnswerNoOpenChainWaitsForIsRefused(string $inResponseTo, string $later): void
    {
        // Given
        $this->awaiting();
        $this->clock->modify($later);
        $response = new LogoutResponse(
            self::RESPONSE_ID,
            Fixtures::now(),
            new Issuer(ServiceProviderDocuments::SIGNED),
            self::SINGLE_LOGOUT,
            $inResponseTo,
            new Status(StatusCode::Success),
        );

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The LogoutResponse answers no request an open chain of logout waits for (spec/saml.md S-33).');

        // When
        $this->receiver()->redirect($this->tenant, self::answeredOverRedirect($response), $this->secret);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAnswersNobodyWaitsFor(): iterable
    {
        yield 'an answer to a request nobody waits for' => [SignOutRequests::ID, '+1 second'];
        yield 'the answer of a chain past its ten minutes' => [self::AWAITED, '+600 seconds'];
    }

    /**
     * S-32, S-33: the answer of the request a chain waits for, carried by a client that presents no secret of a chain
     * or the secret of another, is refused before any key is read.
     */
    #[Test]
    #[DataProvider('provideSecretsOfAnotherClient')]
    public function anAnswerCarriedByAnotherClientIsRefused(?LogoutChainSecret $secret): void
    {
        // Given
        $this->awaiting();

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The LogoutResponse answers no request an open chain of logout waits for (spec/saml.md S-33).');

        // When
        $this->receiver()->redirect($this->tenant, self::answeredOverRedirect(self::response()), $secret);
    }

    /**
     * @return iterable<string, array{LogoutChainSecret|null}>
     */
    public static function provideSecretsOfAnotherClient(): iterable
    {
        yield 'no secret' => [null];
        yield 'the secret of another chain' => [new LogoutChainSecret('GJx3sTZ1n3W0pQm7e2Lr9VbY4kCq8HfA6dUoE5iNwXs')];
    }

    /**
     * S-32, S-33, M-11: an answer refused to another client is not remembered, so that the browser the chain is bound
     * to, carrying the same answer, has it accepted.
     */
    #[Test]
    public function anAnswerRefusedToAnotherClientIsAcceptedFromTheBrowserOfTheChain(): void
    {
        // Given
        $chain = $this->awaiting();
        $query = self::answeredOverRedirect(self::response());
        try {
            $this->receiver()->redirect($this->tenant, $query, null);
        } catch (LogoutRefusedException) {
        }

        // When
        $answer = $this->receiver()->redirect($this->tenant, $query, $this->secret);

        // Then
        static::assertEquals(new SignOutAnswer($chain, true, $this->secret), $answer);
    }

    /**
     * S-33, M-8: an answer whose Issuer is another service provider than the one the request went to, signed by a key
     * of that other one, is refused.
     */
    #[Test]
    public function anAnswerOfAnotherIssuerIsRefused(): void
    {
        // Given
        $this->awaiting();
        $response = new LogoutResponse(
            self::RESPONSE_ID,
            Fixtures::now(),
            new Issuer(self::UNREGISTERED),
            self::SINGLE_LOGOUT,
            self::AWAITED,
            new Status(StatusCode::Success),
        );

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(M-8)');

        // When
        $this->receiver()->redirect($this->tenant, self::answeredOverRedirect($response), $this->secret);
    }

    /**
     * S-33, M-2, SAML Profiles §4.4.4.2: an answer whose query string carries no signature, and none in its XML.
     */
    #[Test]
    public function anUnsignedAnswerIsRefused(): void
    {
        // Given
        $this->awaiting();
        [$query] = explode('&SigAlg=', self::answeredOverRedirect(self::response()));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->receiver()->redirect($this->tenant, $query, $this->secret);
    }

    /**
     * S-33, M-11: the same answer received twice is refused the second time, by the store of S-23.
     */
    #[Test]
    public function theSameAnswerIsRefusedTheSecondTime(): void
    {
        // Given
        $this->awaiting();
        $query = self::answeredOverRedirect(self::response());
        $this->receiver()->redirect($this->tenant, $query, $this->secret);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The logout message was already accepted from its issuer (M-11).');

        // When
        $this->receiver()->redirect($this->tenant, $query, $this->secret);
    }

    /**
     * S-33, section 6.3 step 1: the service provider the request went to, its metadata no longer accepted, cannot
     * verify an answer.
     */
    #[Test]
    public function anAnswerOfAServiceProviderWithoutAcceptedMetadataIsRefused(): void
    {
        // Given
        $this->awaiting(self::UNREGISTERED);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The service provider of the request has no metadata accepted yet (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->redirect($this->tenant, self::answeredOverRedirect(self::response()), $this->secret);
    }

    /**
     * B-1: what the binding refuses of a query string is refused before anything else.
     */
    #[Test]
    public function aQueryStringTheBindingRefusesIsRefused(): void
    {
        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(B-1)');

        // When
        $this->receiver()->redirect($this->tenant, 'RelayState=state-1', $this->secret);
    }

    /**
     * B-1: what the binding refuses of a form is refused before anything else.
     */
    #[Test]
    public function aFormTheBindingRefusesIsRefused(): void
    {
        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(B-1)');

        // When
        $this->receiver()->post($this->tenant, ['RelayState' => 'state-1'], $this->secret);
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

    private function redirected(): string
    {
        return (string) parse_url(new RedirectSender()->logoutRequest(self::request(), self::signing(), 'state-1'), PHP_URL_QUERY);
    }

    /**
     * @return array<string, string>
     */
    private function posted(): array
    {
        return new PostSender()->logoutRequest(self::request(), self::signing(), 'state-1')->fields;
    }

    /**
     * An open chain of the tenant waiting for the answer of the request AWAITED, sent to $serviceProvider.
     */
    private function awaiting(string $serviceProvider = ServiceProviderDocuments::SIGNED): LogoutChain
    {
        $chain = new LogoutChain(
            LogoutChain::digestOf('reference'),
            $this->secret->digest(),
            $this->tenant,
            self::AWAITED,
            new LogoutProgress([], [], $serviceProvider, false, null, null),
            Fixtures::now()->modify('+600 seconds'),
        );
        $this->chains->save($chain);

        return $chain;
    }

    private static function response(Status $status = new Status(StatusCode::Success)): LogoutResponse
    {
        return new LogoutResponse(
            self::RESPONSE_ID,
            Fixtures::now(),
            new Issuer(ServiceProviderDocuments::SIGNED),
            self::SINGLE_LOGOUT,
            self::AWAITED,
            $status,
        );
    }

    private static function answeredOverRedirect(LogoutResponse $response): string
    {
        return (string) parse_url(new RedirectSender()->logoutResponse($response, self::signing()), PHP_URL_QUERY);
    }

    /**
     * The message received, a request as the tests of section 6.5 step 1 expect it.
     */
    private static function acceptedRequest(SignOutRequest|SignOutAnswer $received): SignOutRequest
    {
        static::assertInstanceOf(SignOutRequest::class, $received);

        return $received;
    }

    private function receiver(): ModelLogoutMessageReceiver
    {
        return new ModelLogoutMessageReceiver(
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
                new ModelServiceProviderMetadataReader($this->clock),
            ),
            new FixedEndpoints(),
            $this->replay,
            $this->clock,
            $this->chains,
        );
    }

    private static function request(string $issuer = ServiceProviderDocuments::SIGNED): LogoutRequest
    {
        return new LogoutRequest(
            SignOutRequests::ID,
            Fixtures::now(),
            new Issuer($issuer),
            self::SINGLE_LOGOUT,
            null,
            new NameId('alice-at-sp', NameIdFormat::Persistent, self::ISSUER . FixedEndpoints::METADATA, ServiceProviderDocuments::SIGNED),
            ['the-session'],
        );
    }

    private static function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('sp'));
    }
}
