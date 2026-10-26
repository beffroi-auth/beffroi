<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleSignOn;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Saml\Application\SingleSignOn\AttributeRelease;
use Beffroi\Saml\Application\SingleSignOn\SingleSignOn;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Domain\Event\ServiceProviderSignedIn;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Domain\SingleSignOn\SignOnStatus;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\FixedSalt;
use Beffroi\Saml\Tests\Fixture\GivenRequests;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\RecordingLogger;
use Beffroi\Saml\Tests\Fixture\RecordingResponder;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.4: what a request accepted is answered with, from the session the browser holds, after a
 * login, or with a failure.
 */
final class SingleSignOnTest extends TestCase
{
    /**
     * The service provider declared with encrypt_assertions: the SimpleSAMLphp one, whose metadata hold a key for it.
     */
    private const string ENCRYPTING = ServiceProviderDocuments::SIMPLESAMLPHP;

    private Tenant $tenant;

    private MockClock $clock;

    private RecordingResponder $responder;

    private InMemoryAcceptedMetadata $acceptedMetadata;
    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->responder = new RecordingResponder();
        $this->acceptedMetadata = new InMemoryAcceptedMetadata();
        $this->events = new RecordingEventDispatcher();
    }

    /**
     * S-17: a browser without a session signs in first.
     */
    #[Test]
    public function aBrowserWithoutASessionSignsInFirst(): void
    {
        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), null, Fixtures::context());

        // Then
        static::assertNull($form);
    }

    /**
     * S-17, Core §3.4.1: IsPassive without a session that answers is NoPassive, never a page.
     */
    #[Test]
    public function aPassiveRequestWithoutASessionIsNoPassive(): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(isPassive: true), null, Fixtures::context());

        // Then
        static::assertSame(SignOnStatus::NoPassive, $this->responder->failure?->status);
    }

    /**
     * Section 6.4 steps 5 to 7: an active session answers with the persistent identifier of its user at that service
     * provider, its attributes, its ID as the SessionIndex and its latest proof, issued now.
     */
    #[Test]
    public function anActiveSessionAnswers(): void
    {
        // Given
        $session = $this->session();
        $request = SignOnRequests::request();

        // When
        $form = $this->singleSignOn()->answer($this->tenant, $request, $session, Fixtures::context());

        // Then
        static::assertEquals(
            new SignOnResponse(
                'https://id.acme.example' . FixedEndpoints::METADATA,
                $request,
                PersistentNameId::derive(ServiceProviderDocuments::SIGNED, $session->user->subject, FixedSalt::SALT),
                [new ReleasedAttribute('urn:oid:0.9.2342.19200300.100.1.3', AttributeNameFormat::Uri, 'mail', [new AttributeValue('alice@example.com')])],
                $session->id->toRfc4122(),
                $session->authenticatedAt(),
                Fixtures::now(),
            ),
            $this->responder->response,
        );
        static::assertEquals(new PostedForm(SignOnRequests::ASSERTION_CONSUMER, ['SAMLResponse' => 'success']), $form);
    }

    /**
     * S-17, Core §3.4.1: ForceAuthn is not answered from a proof older than the request.
     */
    #[Test]
    public function aForcedRequestIsNotAnsweredFromAnOlderProof(): void
    {
        // Given
        $session = $this->session(Fixtures::now()->modify('-1 second'));

        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(forceAuthn: true), $session, Fixtures::context());

        // Then
        static::assertNull($form);
    }

    /**
     * S-17: ForceAuthn is answered from a proof made at or after the request was received.
     */
    #[Test]
    public function aForcedRequestIsAnsweredFromAProofMadeSinceIt(): void
    {
        // Given
        $session = $this->session(Fixtures::now());

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(forceAuthn: true), $session, Fixtures::context());

        // Then
        static::assertSame($session->id->toRfc4122(), $this->responder->response?->sessionIndex);
    }

    /**
     * S-17: the core keeps a proof to the second, so the login a forced request waited for, typed in the second the
     * request was received in, reads back as that second and answers it.
     */
    #[Test]
    public function aForcedRequestIsAnsweredFromAProofOfTheSecondItWasReceivedIn(): void
    {
        // Given
        $session = $this->session(Fixtures::now());
        $request = SignOnRequests::request(forceAuthn: true, receivedAt: Fixtures::now()->modify('+500 milliseconds'));

        // When
        $this->singleSignOn($request)->answer($this->tenant, $request, $session, Fixtures::context());

        // Then
        static::assertSame($session->id->toRfc4122(), $this->responder->response?->sessionIndex);
    }

    /**
     * S-17: a session that has ended, or one of another tenant, answers nothing.
     *
     * @param Closure(Tenant): AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsThatDoNotAnswer')]
    public function aSessionThatDoesNotAnswerAsksForALogin(Closure $session): void
    {
        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $session($this->tenant), Fixtures::context());

        // Then
        static::assertNull($form);
    }

    /**
     * @return iterable<string, array{Closure(Tenant): AuthenticationSession}>
     */
    public static function provideSessionsThatDoNotAnswer(): iterable
    {
        yield 'ended' => [static function (Tenant $tenant): AuthenticationSession {
            $session = Fixtures::session(Fixtures::user($tenant));
            $session->end(SessionEnd::User, Fixtures::now());

            return $session;
        }];
        yield 'of another tenant' => [static fn (Tenant $tenant): AuthenticationSession => Fixtures::session(Fixtures::user(Fixtures::tenant('globex')))];
    }

    /**
     * Section 6.4 step 4, Core §3.4.1.1: a NameIDPolicy of another format is InvalidNameIDPolicy, whatever the session.
     */
    #[Test]
    public function aNameIdPolicyOfAnotherFormatIsRefused(): void
    {
        // When
        $this->singleSignOn()->answer(
            $this->tenant,
            SignOnRequests::request(nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'),
            $this->session(),
            Fixtures::context(),
        );

        // Then
        static::assertSame(SignOnStatus::InvalidNameIdPolicy, $this->responder->failure?->status);
    }

    /**
     * Section 6.4 step 4: a NameIDPolicy of the persistent format, or of the unspecified one, is answered.
     */
    #[Test]
    #[DataProvider('provideAnsweredFormats')]
    public function aNameIdPolicyThePersistentIdentifierSatisfiesIsAnswered(string $format): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(nameIdFormat: $format), $this->session(), Fixtures::context());

        // Then
        static::assertInstanceOf(SignOnResponse::class, $this->responder->response);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAnsweredFormats(): iterable
    {
        yield 'persistent' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'];
        yield 'unspecified' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'];
    }

    /**
     * Section 6.4 step 4, Core §3.3.2.2.1: a class of authentication context asked for is NoAuthnContext.
     */
    #[Test]
    public function aRequestedAuthenticationContextIsNoAuthnContext(): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(authnContextRequested: true), $this->session(), Fixtures::context());

        // Then
        static::assertEquals(
            new SignOnFailure(
                'https://id.acme.example' . FixedEndpoints::METADATA,
                SignOnRequests::request(authnContextRequested: true),
                SignOnStatus::NoAuthnContext,
                Fixtures::now(),
            ),
            $this->responder->failure,
        );
    }

    /**
     * Section 6.4 step 4: what is never written is answered before anybody signs in.
     */
    #[Test]
    public function aFailureIsAnsweredBeforeALogin(): void
    {
        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(authnContextRequested: true), null, Fixtures::context());

        // Then
        static::assertEquals(new PostedForm(SignOnRequests::ASSERTION_CONSUMER, ['SAMLResponse' => 'failure']), $form);
    }

    /**
     * S-18, section 7: a request is answered within ten minutes of its receipt and refused after.
     */
    #[Test]
    public function aRequestThatWaitedTenMinutesIsRefused(): void
    {
        // Given
        $this->clock->modify('+600 seconds');

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The request waited longer than the ten minutes it may wait for a login (spec/saml.md S-18).');

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $this->session(), Fixtures::context());
    }

    /**
     * S-18: a second before its ten minutes, the request is answered.
     */
    #[Test]
    public function aRequestIsAnsweredWithinItsTenMinutes(): void
    {
        // Given
        $this->clock->modify('+599 seconds');

        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $this->session(), Fixtures::context());

        // Then
        static::assertNotNull($form);
    }

    /**
     * S-7, S-19, section 6.4 step 2: a request of a service provider that asks for encryption, its accepted document
     * holding no key for it, is refused when it arrives, before anybody signs in.
     */
    #[Test]
    public function aServiceProviderThatAsksForEncryptionWithoutAKeyIsRefused(): void
    {
        // Given
        $this->accepted(ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The service provider asks for its assertions encrypted and no key for encryption is read back from its accepted metadata: none is sent in clear (spec/saml.md S-19).');

        // When
        $this->singleSignOn(SignOnRequests::request(serviceProvider: self::ENCRYPTING))->receiveRedirect($this->tenant, 'SAMLRequest=x');
    }

    /**
     * S-7, S-19, section 6.4 step 2: the same request is received when the accepted document holds a key for
     * encryption.
     */
    #[Test]
    public function aServiceProviderThatAsksForEncryptionWithAKeyIsReceived(): void
    {
        // Given
        $this->accepted(ServiceProviderDocuments::simpleSamlPhp());
        $request = SignOnRequests::request(serviceProvider: self::ENCRYPTING);

        // When / Then
        static::assertEquals($request, $this->singleSignOn($request)->receiveRedirect($this->tenant, 'SAMLRequest=x'));
    }

    /**
     * S-19, section 6.4 step 7: the answer to a service provider that asks for encryption names the first certificate
     * for encryption of its accepted document.
     */
    #[Test]
    public function theAnswerToAServiceProviderThatAsksForEncryptionNamesTheKeyOfItsMetadata(): void
    {
        // Given
        $this->accepted(ServiceProviderDocuments::simpleSamlPhp());

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(serviceProvider: self::ENCRYPTING), $this->session(), Fixtures::context());

        // Then
        static::assertEquals(
            new ModelServiceProviderMetadataReader($this->clock)->readTrusted(ServiceProviderDocuments::simpleSamlPhp())->encryptionCertificates[0],
            $this->responder->response?->encryptFor,
        );
    }

    /**
     * S-19, section 6.4 step 7: the accepted document is read back when the request is answered, so that a key a
     * refresh put in place while the request waited is the one the assertion is encrypted for.
     */
    #[Test]
    public function theKeyIsReadAgainWhenTheRequestIsAnswered(): void
    {
        // Given
        $this->accepted(ServiceProviderDocuments::simpleSamlPhp());
        $request = $this->singleSignOn(SignOnRequests::request(serviceProvider: self::ENCRYPTING))->receiveRedirect($this->tenant, 'SAMLRequest=x');
        $this->accepted(ServiceProviderDocuments::simpleSamlPhpWithCertificate(ServiceProviderDocuments::signer()->base64));

        // When
        $this->singleSignOn()->answer($this->tenant, $request, $this->session(), Fixtures::context());

        // Then
        static::assertEquals(ServiceProviderDocuments::signer(), $this->responder->response?->encryptFor);
    }

    /**
     * S-19, section 6.4 step 7: a service provider that asks for encryption is refused at the answer when no key is
     * read back from its accepted metadata by then, and nothing is written for it.
     */
    #[Test]
    #[DataProvider('provideDocumentsWithoutAKey')]
    public function anAnswerWithoutAKeyIsRefused(?string $document): void
    {
        // Given
        if ($document !== null) {
            $this->accepted($document);
        }

        // When
        try {
            $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(serviceProvider: self::ENCRYPTING), $this->session(), Fixtures::context());
        } catch (SignOnRefusedException) {
        }

        // Then
        static::assertNull($this->responder->response);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideDocumentsWithoutAKey(): iterable
    {
        yield 'no accepted document' => [null];
        yield 'a document without a key for encryption' => [ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey()];
        yield 'a document that expired since it was accepted' => [ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:00:00Z')];
    }

    /**
     * S-7, S-19: a service provider whose declaration does not ask for encryption is answered in clear, whatever keys
     * its metadata hold.
     */
    #[Test]
    public function aServiceProviderThatDoesNotAskIsAnsweredInClear(): void
    {
        // Given
        $this->accepted(ServiceProviderDocuments::signed(null), ServiceProviderDocuments::SIGNED);

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $this->session(), Fixtures::context());

        // Then
        static::assertNull($this->responder->response?->encryptFor);
    }

    /**
     * Section 6.4 step 2: a declaration removed while the request waited answers nothing.
     */
    #[Test]
    public function aServiceProviderNoLongerDeclaredIsRefused(): void
    {
        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The service provider of the request is no longer declared (spec/saml.md section 6.4 step 2).');

        // When
        $this->singleSignOn()->answer(
            $this->tenant,
            SignOnRequests::request(serviceProvider: 'https://gone.example.org/saml'),
            $this->session(),
            Fixtures::context(),
        );
    }

    /**
     * Section 6.4 step 1: the request the receiver accepted over HTTP-POST, its service provider declared.
     */
    #[Test]
    public function aRequestPostedIsReceived(): void
    {
        // When / Then
        static::assertEquals(SignOnRequests::request(), $this->singleSignOn()->receivePost($this->tenant, ['SAMLRequest' => 'x']));
    }

    /**
     * Section 6.4 step 1: the request the receiver accepted over HTTP-Redirect, its service provider declared.
     */
    #[Test]
    public function aRequestRedirectedIsReceived(): void
    {
        // When / Then
        static::assertEquals(SignOnRequests::request(), $this->singleSignOn()->receiveRedirect($this->tenant, 'SAMLRequest=x'));
    }

    /**
     * S-19, section 6.4 step 2: the key is looked for when the request is posted too.
     */
    #[Test]
    public function aRequestPostedForAServiceProviderThatAsksForEncryptionWithoutAKeyIsRefused(): void
    {
        // Given
        $this->accepted(ServiceProviderDocuments::simpleSamlPhpWithoutEncryptionKey());

        // Then
        $this->expectException(SignOnRefusedException::class);

        // When
        $this->singleSignOn(SignOnRequests::request(serviceProvider: self::ENCRYPTING))->receivePost($this->tenant, ['SAMLRequest' => 'x']);
    }

    private function singleSignOn(?SignOnRequest $received = null): SingleSignOn
    {
        return new SingleSignOn(
            new GivenRequests($received ?? SignOnRequests::request()),
            $this->responder,
            new ConfigurationServiceProviders(
                'acme',
                [
                    ServiceProviderDocuments::SIGNED => [
                        'metadata' => '/etc/saml/sp.xml',
                        'attributes' => [
                            'urn:oid:0.9.2342.19200300.100.1.3' => [
                                'claim' => 'email',
                                'friendly_name' => 'mail',
                            ],
                        ],
                    ],
                    self::ENCRYPTING => [
                        'metadata' => '/etc/saml/simplesamlphp.xml',
                        'encrypt_assertions' => true,
                    ],
                ],
                new FixedClaims(),
            ),
            new AttributeRelease(new FixedClaims(['email' => 'alice@example.com']), new RecordingLogger()),
            new FixedSalt(),
            new FixedEndpoints(),
            $this->clock,
            $this->acceptedMetadata,
            new ModelServiceProviderMetadataReader($this->clock),
            $this->events,
        );
    }

    /**
     * S-26: an assertion written from a session announces the service provider's part in it, the session by its ID,
     * the service provider by its entity ID and the person by their subject, with the context of the request.
     */
    #[Test]
    public function anAnswerFromASessionAnnouncesTheServiceProviderOfTheSession(): void
    {
        // Given
        $session = $this->session();

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $session, Fixtures::context());

        // Then
        static::assertEquals(
            [new ServiceProviderSignedIn(
                Fixtures::now(),
                $this->tenant,
                $session->id,
                ServiceProviderDocuments::SIGNED,
                $session->user->subject,
                Fixtures::context(),
            )],
            $this->events->events,
        );
    }

    /**
     * S-26: a failure is written from no session, and announces nothing.
     */
    #[Test]
    public function aFailureAnnouncesNothing(): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(isPassive: true), null, Fixtures::context());

        // Then
        static::assertSame([], $this->events->events);
    }

    /**
     * The document accepted for a service provider of the tenant, the one that asks for encryption by default.
     */
    private function accepted(string $document, string $entityId = self::ENCRYPTING): void
    {
        $this->acceptedMetadata->save(new AcceptedServiceProviderMetadata(Uuid::v7(), $this->tenant, $entityId, $document, null, Fixtures::now()));
    }

    /**
     * An active session of the tenant, its one proof a password at the instant given, the instant of the fixtures
     * by default.
     */
    private function session(?DateTimeImmutable $provenAt = null): AuthenticationSession
    {
        $provenAt ??= Fixtures::now();

        return Fixtures::session(
            Fixtures::user($this->tenant),
            $provenAt,
            AuthenticationProofs::of(AuthenticationMethod::password(), $provenAt),
        );
    }
}
