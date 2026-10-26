<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use function array_key_exists;
use function array_values;
use function base64_decode;
use function gzinflate;
use function parse_str;
use function parse_url;
use function preg_quote;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-49 to S-51 and S-61, decision 0029: the login a page of the provider waits for without an
 * interaction (LoginTarget), here the approval of a device (RFC 8628 §3.3), asks for the address first, and sends an
 * address of a federated domain to the sign-on of its provider, which remembers that page to come back to. What follows
 * at the provider, and the way back through the assertion consumer service, is issue #784's.
 */
final class FederatedPageLoginTest extends ConsoleTestCase
{
    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    /**
     * What the appliance shows and the person types, well formed: the page carries it back once signed in.
     */
    private const string USER_CODE = 'BCDFGHJK';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_service_provider',
        ];
    }

    /**
     * S-61: the login the page of a device waits for asks for the address, and offers no password.
     */
    #[Test]
    public function theLoginTheDevicePageWaitsForAsksForTheAddress(): void
    {
        // Given
        $this->browser->request('GET', '/device', [
            'user_code' => self::USER_CODE,
        ]);

        // When
        $crawler = $this->browser->followRedirect();

        // Then
        static::assertSame(
            [1, 0],
            [$crawler->filter('form[data-step="address"]')->count(), $crawler->filter('input[name="_password"]')->count()],
        );
    }

    /**
     * S-61, S-51: an address of a federated domain typed on the login the page of a device waits for is sent to the
     * sign-on without an interaction, and on to the single sign-on service of its provider.
     */
    #[Test]
    public function aFederatedAddressOnTheDevicePageIsSentToItsProvider(): void
    {
        // Given
        self::generate();
        self::accept();
        $this->signOnFromTheDevicePage();

        // When
        $this->browser->followRedirect();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertStringStartsWith(self::SINGLE_SIGN_ON . '?SAMLRequest=', (string) $response->headers->get('Location'));
    }

    /**
     * S-50: the request remembered names the page that waits, with the code it carried, and no interaction, so that the
     * answer of the provider comes back to it.
     */
    #[Test]
    public function theRequestRemembersThePageThatWaits(): void
    {
        // Given
        self::generate();
        self::accept();
        $this->signOnFromTheDevicePage();
        $this->browser->followRedirect();

        // When
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);

        // Then
        static::assertIsArray($remembered);
        $entry = array_values($remembered)[0] ?? null;
        static::assertIsArray($entry);
        static::assertSame(
            [
                [
                    'route' => 'beffroi_interaction_device',
                    'parameters' => [
                        'user_code' => self::USER_CODE,
                    ],
                ],
                false,
            ],
            [$entry['page'] ?? null, array_key_exists('interaction', $entry)],
        );
    }

    /**
     * S-49: the first login a page asks for of a browser that holds no session forces no login at the provider, which
     * may answer from the session it holds.
     */
    #[Test]
    public function aFirstLoginForcesNoLoginAtTheProvider(): void
    {
        // Given
        self::generate();
        self::accept();
        $this->signOnFromTheDevicePage();

        // When
        $this->browser->followRedirect();

        // Then
        static::assertStringNotContainsString('ForceAuthn', self::inflatedRequest((string) $this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * S-49: a page that asks a person signed in already for a proof given a short while ago (RecentLogin) forces a
     * login at the provider, whose own session must not answer for a proof the page asked to be fresh.
     */
    #[Test]
    public function aFreshProofOfASignedInPersonForcesTheLoginAtTheProvider(): void
    {
        // Given
        self::generate();
        self::accept();
        $this->signIn(self::user('alice'), self::currentSecond()->modify('-1 hour'));
        $this->browser->request('GET', '/account/passkeys');
        $form = $this->browser->followRedirect()->filter('form[data-step="address"]')->form();
        $form['_address'] = 'alice@example.org';
        $this->browser->submit($form);

        // When
        $this->browser->followRedirect();

        // Then
        static::assertStringContainsString('ForceAuthn="true"', self::inflatedRequest((string) $this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * The page of the device sends the browser to the login, whose address is posted as a person posts it.
     */
    private function signOnFromTheDevicePage(): void
    {
        $this->browser->request('GET', '/device', [
            'user_code' => self::USER_CODE,
        ]);
        $form = $this->browser->followRedirect()->filter('form[data-step="address"]')->form();
        $form['_address'] = 'alice@example.org';
        $this->browser->submit($form);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        static::assertMatchesRegularExpression(
            '#^/saml/sp/sign-on\?identity_provider=' . preg_quote(IdentityProviderDocuments::SIMPLESAMLPHP, '#') . '&reference=[A-Za-z0-9_-]{43}$#',
            (string) $response->headers->get('Location'),
        );
    }

    /**
     * The AuthnRequest a redirection carries, inflated (SAML Bindings §3.4.4.1).
     */
    private static function inflatedRequest(string $location): string
    {
        $query = [];
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $encoded = $query['SAMLRequest'] ?? null;
        static::assertIsString($encoded);

        return (string) gzinflate((string) base64_decode($encoded, true));
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
    private static function accept(): void
    {
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                IdentityProviderDocuments::simpleSamlPhp(),
                null,
                self::currentSecond(),
            ));
    }
}
