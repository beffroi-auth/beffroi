<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\DeclaredServiceProviderReader;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestReceiver;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\Signing;
use function parse_url;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.3, section 6.4 step 1: a request of a declared service provider received over either
 * binding, validated by the model at the URL of the single sign-on service of the tenant, and what it asks for kept;
 * anything else refused without a SAML answer.
 */
final class ModelAuthnRequestReceiverTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    private const string SINGLE_SIGN_ON = self::ISSUER . FixedEndpoints::SINGLE_SIGN_ON;

    private Tenant $tenant;

    private InMemoryAcceptedMetadata $accepted;

    private MockClock $clock;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', self::ISSUER);
        $this->accepted = new InMemoryAcceptedMetadata();
        $this->clock = new MockClock(Fixtures::now());
        $this->accepted->save(new AcceptedServiceProviderMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIGNED,
            ServiceProviderDocuments::signed(null),
            null,
            Fixtures::now(),
        ));
    }

    /**
     * Section 6.3 step 4, B-2: a request signed over its query string, its RelayState as it was sent.
     */
    #[Test]
    public function aRequestSignedOverHttpRedirectIsAccepted(): void
    {
        // Given
        $url = new RedirectSender()->authnRequest(self::request(), self::signing(), 'state-1');

        // When
        $request = $this->receiver()->redirect($this->tenant, (string) parse_url($url, PHP_URL_QUERY));

        // Then
        static::assertEquals(SignOnRequests::request(), $request);
    }

    /**
     * Section 6.3 step 4, M-2: a request signed in its XML over HTTP-POST, its RelayState byte for byte.
     */
    #[Test]
    public function aRequestSignedOverHttpPostIsAccepted(): void
    {
        // Given
        $form = new PostSender()->authnRequest(self::request(), self::signing(), "a state, with spaces & ~ and \u{e9}");

        // When
        $request = $this->receiver()->post($this->tenant, $form->fields);

        // Then
        static::assertSame("a state, with spaces & ~ and \u{e9}", $request->relayState);
    }

    /**
     * Section 6.4 step 1: what the request asks of the login and of the identifier is kept for the answer.
     */
    #[Test]
    public function whatTheRequestAsksForIsKept(): void
    {
        // Given
        $form = new PostSender()->authnRequest(self::request(
            nameIdPolicy: new NameIdPolicy('urn:oasis:names:tc:SAML:2.0:nameid-format:transient'),
            forceAuthn: true,
            isPassive: true,
            requestedAuthnContext: new RequestedAuthnContext(AuthnContextComparison::Exact, [
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ]),
        ), self::signing());

        // When
        $request = $this->receiver()->post($this->tenant, $form->fields);

        // Then
        static::assertEquals(
            new SignOnRequest(
                ServiceProviderDocuments::SIGNED,
                SignOnRequests::ID,
                SignOnRequests::ASSERTION_CONSUMER,
                null,
                true,
                true,
                'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                true,
                Fixtures::now(),
            ),
            $request,
        );
    }

    /**
     * S-9, section 6.3 step 4: a provider that signs gets no unsigned request accepted.
     */
    #[Test]
    public function anUnsignedRequestOfAProviderThatSignsIsRefused(): void
    {
        // Given
        $url = new RedirectSender()->authnRequest(self::request(), null);

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(M-2)');

        // When
        $this->receiver()->redirect($this->tenant, (string) parse_url($url, PHP_URL_QUERY));
    }

    /**
     * S-10, section 6.3 step 5: an assertion consumer service the accepted metadata do not list is refused.
     */
    #[Test]
    public function anEndpointTheMetadataDoNotListIsRefused(): void
    {
        // Given
        $form = new PostSender()->authnRequest(self::request(assertionConsumerService: 'https://attacker.example/acs'), self::signing());

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(M-9)');

        // When
        $this->receiver()->post($this->tenant, $form->fields);
    }

    /**
     * Section 6.3 step 1: an Issuer the tenant declares no service provider for is refused.
     */
    #[Test]
    public function anIssuerNobodyDeclaredIsRefused(): void
    {
        // Given
        $form = new PostSender()->authnRequest(self::request(issuer: 'https://unknown.example.org/saml'), self::signing());

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The Issuer of the request is no service provider this tenant declares (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->post($this->tenant, $form->fields);
    }

    /**
     * Section 6.3 step 1: a declared service provider whose metadata were never accepted is refused.
     */
    #[Test]
    public function aProviderWithoutAcceptedMetadataIsRefused(): void
    {
        // Given
        $this->accepted = new InMemoryAcceptedMetadata();
        $form = new PostSender()->authnRequest(self::request(), self::signing());

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The service provider of the request has no metadata accepted yet (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->post($this->tenant, $form->fields);
    }

    /**
     * Section 6.3 step 1: an accepted document the reading refuses now, past its validUntil, is refused.
     */
    #[Test]
    public function anAcceptedDocumentRefusedNowIsRefused(): void
    {
        // Given
        $this->accepted->save(new AcceptedServiceProviderMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIGNED,
            ServiceProviderDocuments::signed(Fixtures::now()->modify('-1 day')),
            null,
            Fixtures::now(),
        ));
        $form = new PostSender()->authnRequest(self::request(), self::signing());

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(M-7)');

        // When
        $this->receiver()->post($this->tenant, $form->fields);
    }

    /**
     * B-1: what the binding refuses is refused before anything else.
     */
    #[Test]
    public function aQueryStringTheBindingRefusesIsRefused(): void
    {
        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(B-1)');

        // When
        $this->receiver()->redirect($this->tenant, 'RelayState=state-1');
    }

    /**
     * B-1: what the binding refuses of a form is refused before anything else.
     */
    #[Test]
    public function aFormTheBindingRefusesIsRefused(): void
    {
        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(B-1)');

        // When
        $this->receiver()->post($this->tenant, ['RelayState' => 'state-1']);
    }

    private function receiver(): ModelAuthnRequestReceiver
    {
        return new ModelAuthnRequestReceiver(
            new DeclaredServiceProviderReader(
                new ConfigurationServiceProviders(
                    'acme',
                    [
                        ServiceProviderDocuments::SIGNED => [
                            'metadata' => '/etc/saml/sp.xml',
                        ],
                    ],
                    new FixedClaims(),
                ),
                $this->accepted,
                new ModelServiceProviderMetadataReader($this->clock),
            ),
            new FixedEndpoints(),
            $this->clock,
        );
    }

    private static function request(
        string $issuer = ServiceProviderDocuments::SIGNED,
        string $assertionConsumerService = SignOnRequests::ASSERTION_CONSUMER,
        ?NameIdPolicy $nameIdPolicy = null,
        bool $forceAuthn = false,
        bool $isPassive = false,
        ?RequestedAuthnContext $requestedAuthnContext = null,
    ): AuthnRequest {
        return new AuthnRequest(
            SignOnRequests::ID,
            Fixtures::now(),
            new Issuer($issuer),
            self::SINGLE_SIGN_ON,
            $assertionConsumerService,
            null,
            null,
            $nameIdPolicy,
            $forceAuthn,
            $isPassive,
            $requestedAuthnContext,
        );
    }

    private static function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('sp'));
    }
}
