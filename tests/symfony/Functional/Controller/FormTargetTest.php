<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Closure;
use DateTimeImmutable;
use function intdiv;
use PHPUnit\Framework\Attributes\Test;
use Psr\Container\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Uid\Uuid;

/**
 * CSP Level 3 §6.1, §6.3.2 on a deployment that writes a policy for its pages: a page of the interaction
 * plane says what it adds to that policy and the directive it names is completed once the policy is
 * written (PolicyCompletion). A page that may send the browser to a client names the origin of that
 * client among the targets of a submission (FormTarget), a browser checking the directive over the whole
 * redirect chain of one and the last hop of that chain being the answer carried to the client, so a page
 * that names only this provider is a page whose login never reaches the client that asked for it; the
 * consent page names the hosts of the images it shows as well (ImageSource).
 *
 * The kernel of this suite writes no policy of its own: what every page of the plane carries is the floor
 * of the plane, which restricts no submission (architecture §5.2). The listener below stands in for the
 * one an application writes (apps/op config/packages/nelmio_security.yaml), so that what is read here is
 * what a browser reads there.
 */
final class FormTargetTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * What a deployment writes on the pages of this plane, the two directives of this test among the ones
     * it names: every form of these pages comes back to the provider and nothing else may be posted to,
     * every image is served by the provider and no other host.
     */
    private const string DEPLOYMENT_POLICY = "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'";

    /**
     * The client of the walks below, and the origin it is answered at.
     */
    private const string CLIENT_ID = 'oidc-demo';

    private const string REDIRECT_URI = 'https://demo.test/login/check';

    private const string CLIENT_ORIGIN = 'https://demo.test';

    /**
     * The client consent is required of, the one declared with a logo (config_test.yml), and the two
     * origins its consent page names: where it is answered, and where that logo is served from.
     */
    private const string CONSENT_CLIENT_ID = 'consent-app';

    private const string CONSENT_REDIRECT_URI = 'https://consent.test/callback';

    private const string CONSENT_CLIENT_ORIGIN = 'https://consent.test';

    private const string CONSENT_LOGO_ORIGIN = 'https://cdn.consent.test';

    /**
     * The origin of the single logout service of the SAML service provider of the suite (beffroi/saml S-36).
     */
    private const string SERVICE_PROVIDER_ORIGIN = 'https://sp.example.org';

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $dispatcher = $container->get('event_dispatcher');
            static::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
            // where the policy of an application is written: after the controller that answered, before
            // the directive of a page is completed with what it may answer (FormTarget), and on the pages
            // the bundle computes no policy for, as App\Http\DeploymentPolicyPrevails leaves them
            $dispatcher->addListener(
                KernelEvents::RESPONSE,
                static function (ResponseEvent $event): void {
                    $response = $event->getResponse();
                    if (! $event->isMainRequest() || $response->isRedirection()) {
                        return;
                    }
                    if ($response->headers->get('Content-Security-Policy') !== InteractionPages::HEADERS['Content-Security-Policy']) {
                        return;
                    }
                    $response->headers->set('Content-Security-Policy', self::DEPLOYMENT_POLICY);
                },
                0,
            );
        };
    }

    /**
     * The page the browser of an authorization request lands on: the login it asks for ends with the code
     * carried to the client, so the client is named.
     */
    #[Test]
    public function theLoginPageOfAnAuthorizationRequestNamesTheOriginOfTheClient(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorizeTheClient();

        // When
        $this->loginPage($interaction);

        // Then
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * The second step of the same login (architecture §5.4): the code page belongs to the interaction as
     * the login page does, and the code it asks for is what ends the login.
     */
    #[Test]
    public function theCodePageOfAnAuthorizationRequestNamesTheOriginOfTheClient(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorizeTheClient();
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);

        // When
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * RP-Initiated Logout §2: a confirmed logout sends the browser where the client asked to be sent
     * back, so the page that asks for the confirmation names it.
     */
    #[Test]
    public function theLogoutConfirmationNamesWhereTheClientAskedToBeSentBack(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/logout', [
            'client_id' => self::CLIENT_ID,
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * Issue #584: the consent page extends the layout of its deployment, so it carries the policy of that
     * deployment and not one of its own, with the client it may answer in the "form-action" and the host
     * serving the logo it shows in the "img-src".
     */
    #[Test]
    public function theConsentPageNamesTheClientItMayAnswerAndTheHostOfTheLogoItShows(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $interaction = $this->authorize([
            'client_id' => self::CONSENT_CLIENT_ID,
            'redirect_uri' => self::CONSENT_REDIRECT_URI,
        ]);

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            "default-src 'none'; script-src 'self'; img-src 'self' "
            . self::CONSENT_LOGO_ORIGIN
            . "; form-action 'self' "
            . self::CONSENT_CLIENT_ORIGIN
            . "; frame-ancestors 'none'",
            $this->policyOfTheAnswer(),
        );
    }

    /**
     * beffroi/saml S-36: a confirmed logout goes through the single logout service of each SAML service
     * provider of the session before the client that asked, redirections of the same submission, so the
     * page that asks for the confirmation names them after the client.
     */
    #[Test]
    public function theLogoutConfirmationNamesTheSingleLogoutServicesOfTheSession(): void
    {
        // Given
        $this->signedInAtTheServiceProvider();

        // When
        $this->browser->request('GET', '/logout', [
            'client_id' => self::CLIENT_ID,
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);

        // Then
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN . ' ' . self::SERVICE_PROVIDER_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * beffroi/saml S-36: the button of the sessions page that ends the session of the browser is answered
     * with the same chain, so that page names the single logout services of that session.
     */
    #[Test]
    public function theSessionsPageNamesTheSingleLogoutServicesOfTheSessionOfTheBrowser(): void
    {
        // Given
        $this->signedInAtTheServiceProvider();

        // When
        $this->browser->request('GET', '/account/sessions');

        // Then
        static::assertSame(self::policyNaming(self::SERVICE_PROVIDER_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * A page of the account answers no client and sends the browser nowhere: what a deployment wrote is
     * what it carries.
     */
    #[Test]
    public function aPageThatAnswersNoClientNamesNoOrigin(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/account');

        // Then
        static::assertSame(self::DEPLOYMENT_POLICY, $this->policyOfTheAnswer());
    }

    /**
     * Alice signed in, her session signed in at the SAML service provider of the configuration of the
     * suite too, whose accepted metadata list a single logout service (beffroi/saml S-26, S-30).
     */
    private function signedInAtTheServiceProvider(): AuthenticationSession
    {
        $session = $this->signIn(self::user('alice'));
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(
                Uuid::v7(),
                self::tenant(),
                ServiceProviderDocuments::SIGNED,
                ServiceProviderDocuments::exampleOrgWithSingleLogout([[
                    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    ServiceProviderDocuments::SIGNED . '/slo',
                    null,
                ]]),
                null,
                self::currentSecond(),
            ));
        self::service('test.beffroi.saml_session_participants', SessionParticipationRepositoryInterface::class)
            ->record(new SessionParticipation(Uuid::v7(), self::tenant(), $session, ServiceProviderDocuments::SIGNED, self::currentSecond()));

        return $session;
    }

    private function authorizeTheClient(): string
    {
        return $this->authorize([
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
        ]);
    }

    /**
     * The user of the walk with a second factor, so that the login takes the code page on its way.
     */
    private function userWithTotp(string $username, string $password): User
    {
        $user = self::userWithPassword($username, $password);
        $secret = Totps::secret();
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new TotpCredential(
                    Uuid::v7(),
                    $user,
                    self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $secret->bytes),
                    Totps::credential($user, new FakePasswordHasher())->backupCodes,
                    intdiv($anHourAgo->getTimestamp(), TotpCredential::PERIOD),
                    $anHourAgo,
                ),
            );

        return $user;
    }

    private static function policyNaming(string $origin): string
    {
        return "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self' " . $origin . "; frame-ancestors 'none'";
    }

    private function policyOfTheAnswer(): string
    {
        $policy = $this->browser->getResponse()->headers->get('Content-Security-Policy');
        static::assertIsString($policy);

        return $policy;
    }
}
