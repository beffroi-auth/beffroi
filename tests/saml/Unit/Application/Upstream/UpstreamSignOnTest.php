<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Upstream;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Domain\Upstream\AddressHint;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedProfileClaims;
use Beffroi\Saml\Tests\Fixture\FixedServiceProviderEndpoints;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\RecordingAuthnRequestSender;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.11, S-48, S-50, S-68: a sign-on at an upstream identity provider started for a provider the
 * tenant declares, the request written from that provider, the service provider of the tenant, whether the bundle
 * forces a login, the instant of the clock and the address the bundle hands for a provider that reads one, under a
 * reference drawn for it.
 */
final class UpstreamSignOnTest extends TestCase
{
    private const string UNDECLARED = 'https://idp.nobody.example/saml';

    private Tenant $tenant;

    private RecordingAuthnRequestSender $sender;

    private UpstreamSignOn $signOn;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->sender = new RecordingAuthnRequestSender();
        $this->signOn = new UpstreamSignOn(
            new ConfigurationUpstreamIdentityProviders(
                'acme',
                [
                    IdentityProviderDocuments::SIGNED => [
                        'metadata' => '/srv/saml/idp.xml',
                        'domains' => ['acme.example'],
                        'email_attribute' => 'mail',
                        'address_parameter' => 'login_hint',
                    ],
                    RecordingAuthnRequestSender::REFUSED => [
                        'metadata' => '/srv/saml/refused.xml',
                        'domains' => ['refused.example'],
                        'email_attribute' => 'mail',
                    ],
                ],
                new FixedProfileClaims(),
            ),
            new FixedServiceProviderEndpoints(),
            $this->sender,
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * S-48, section 6.11 step 1: a provider the tenant does not declare is refused.
     */
    #[Test]
    public function aProviderTheTenantDoesNotDeclareIsRefused(): void
    {
        // Then
        $this->expectException(UpstreamSignOnRefusedException::class);
        $this->expectExceptionMessageIs('The identity provider is none this tenant declares (spec/saml.md S-48).');

        // When
        $this->signOn->start($this->tenant, self::UNDECLARED, false);
    }

    /**
     * S-48, section 6.11 step 1: nothing is sent to a provider the tenant does not declare.
     */
    #[Test]
    public function nothingIsSentToAProviderTheTenantDoesNotDeclare(): void
    {
        // When
        try {
            $this->signOn->start($this->tenant, self::UNDECLARED, false);
        } catch (UpstreamSignOnRefusedException) {
        }

        // Then
        static::assertSame([], $this->sender->sent);
    }

    /**
     * Section 6.11 step 3: the request is written from the provider, the endpoints of the service provider of the
     * tenant, whether the bundle forces a login (S-49) and the instant of the clock.
     */
    #[Test]
    #[DataProvider('provideForceAuthn')]
    public function theRequestIsWrittenFromTheProviderTheServiceProviderAndTheClock(bool $forceAuthn): void
    {
        // When
        $this->signOn->start($this->tenant, IdentityProviderDocuments::SIGNED, $forceAuthn);

        // Then
        $request = $this->sender->sent[0] ?? static::fail('Nothing was sent.');
        static::assertEquals(
            [IdentityProviderDocuments::SIGNED, new FixedServiceProviderEndpoints()->locate($this->tenant), $forceAuthn, Fixtures::now()],
            [$request->identityProvider, $request->serviceProvider, $request->forceAuthn, $request->issuedAt],
        );
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
     * S-68, section 6.11 step 3: the request to a provider that reads the address carries the address the bundle
     * handed, in the parameter its declaration names, its domain written as its A-label.
     */
    #[Test]
    public function theRequestCarriesTheAddressToAProviderThatReadsOne(): void
    {
        // When
        $this->signOn->start($this->tenant, IdentityProviderDocuments::SIGNED, false, 'Alice@ACME.example');

        // Then
        $request = $this->sender->sent[0] ?? static::fail('Nothing was sent.');
        static::assertEquals(new AddressHint('login_hint', new EmailAddress('Alice@acme.example')), $request->addressHint);
    }

    /**
     * S-68: a provider whose declaration names no parameter of the address is sent none, nor is a request for which
     * the bundle handed none.
     */
    #[Test]
    #[DataProvider('provideSignOnsWithoutAHint')]
    public function noAddressIsSent(string $identityProvider, ?string $address): void
    {
        // When
        $this->signOn->start($this->tenant, $identityProvider, false, $address);

        // Then
        $request = $this->sender->sent[0] ?? static::fail('Nothing was sent.');
        static::assertNull($request->addressHint);
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideSignOnsWithoutAHint(): iterable
    {
        yield 'a provider that reads none' => [RecordingAuthnRequestSender::REFUSED, 'bob@refused.example'];
        yield 'no address handed' => [IdentityProviderDocuments::SIGNED, null];
    }

    /**
     * Section 6.11 step 5: what the sender sent is what the sign-on started.
     */
    #[Test]
    public function whatTheSenderSentIsReturned(): void
    {
        // When
        $sent = $this->signOn->start($this->tenant, IdentityProviderDocuments::SIGNED, false);

        // Then
        static::assertSame(
            [RecordingAuthnRequestSender::ID, $this->sender->sent[0] ?? null],
            [$sent->id, $sent->request],
        );
    }

    /**
     * S-50, section 6.11 step 2: the RelayState is a reference of 32 bytes of random_bytes() in base64url, 43
     * characters, and nothing else.
     */
    #[Test]
    public function theRelayStateIsAReferenceOfThirtyTwoBytes(): void
    {
        // When
        $sent = $this->signOn->start($this->tenant, IdentityProviderDocuments::SIGNED, false);

        // Then
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $sent->request->relayState);
    }

    /**
     * S-61: a sign-on of the tenant may send a browser to the single sign-on service of each provider it declares, and
     * to none of a provider whose sign-on would be refused.
     */
    #[Test]
    public function aSignOnMaySendABrowserToTheServiceOfEachProviderItWouldStart(): void
    {
        // When / Then
        static::assertSame([RecordingAuthnRequestSender::LOCATION], $this->signOn->destinations($this->tenant));
    }

    /**
     * S-61: a tenant that declares no provider sends a browser nowhere.
     */
    #[Test]
    public function aTenantThatDeclaresNoProviderSendsABrowserNowhere(): void
    {
        // When / Then
        static::assertSame([], $this->signOn->destinations(Fixtures::tenant('initech', 'https://id.initech.example')));
    }

    /**
     * S-50: each sign-on is remembered under a reference of its own.
     */
    #[Test]
    public function eachSignOnHasAReferenceOfItsOwn(): void
    {
        // Given
        $first = $this->signOn->start($this->tenant, IdentityProviderDocuments::SIGNED, false);

        // When
        $second = $this->signOn->start($this->tenant, IdentityProviderDocuments::SIGNED, false);

        // Then
        static::assertNotSame($first->request->relayState, $second->request->relayState);
    }
}
