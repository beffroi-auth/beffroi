<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use function preg_replace;
use function array_map;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Tests\Functional\Controller\PasskeyTestCase;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Closure;
use DateTimeImmutable;
use function intdiv;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-60 to S-63, decision 0029, the acceptance of issue #785: in a deployment whose tenant is
 * a service provider (tests/symfony/config/config_test_service_provider.yml), the SimpleSAMLphp identity provider of
 * the judge declared for example.org and for bücher.example, written as its A-label, the login page of an interaction
 * asks for the address first, sends an address of a federated domain to the sign-on of that provider, and sends any
 * other address on to the usual page; a person of a federated domain is refused every local credential.
 */
final class DomainDiscoveryTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * What a deployment writes on the pages of the interaction plane, its "form-action" among them
     * (apps/op config/packages/nelmio_security.yaml), as FormTargetTest writes it.
     */
    private const string DEPLOYMENT_POLICY = "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'";

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_service_provider',
        ];
    }

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $dispatcher = $container->get('event_dispatcher');
            static::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
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
     * S-61: the login page of an interaction of a tenant that federates a domain asks for the address, and offers no
     * password and no passkey.
     */
    #[Test]
    public function theLoginPageAsksForTheAddressAlone(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame(
            [1, 0, 0, 'username'],
            [
                $crawler->filter('form[data-step="address"] input[name="_address"]')->count(),
                $crawler->filter('input[name="_password"]')->count(),
                $crawler->filter('form[data-passkey]')->count(),
                $crawler->filter('input[name="_address"]')->attr('autocomplete'),
            ],
        );
    }

    /**
     * The acceptance of issue #785, S-61: an address of a federated domain is sent to the sign-on of its provider for
     * the interaction, and no password is asked of it.
     */
    #[Test]
    public function anAddressOfAFederatedDomainIsSentToItsProviderWithoutAPasswordPrompt(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->submitAddress($interaction, 'alice@example.org');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_SEE_OTHER, self::signOn($interaction)],
            [$response->getStatusCode(), self::locationOf($response)],
        );
    }

    /**
     * The acceptance of issue #785, S-60, S-61: an address in capitals, in a U-label or in both is sent to the provider
     * of its domain as the address in its A-label is.
     */
    #[Test]
    #[DataProvider('provideSpellings')]
    public function theUnicodeAndUpperCaseFormsOfAFederatedDomainAreRoutedLikeItsALabel(string $address): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->submitAddress($interaction, $address);

        // Then
        static::assertSame(self::signOn($interaction), self::locationOf($this->browser->getResponse()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpellings(): iterable
    {
        yield 'its A-label' => ['alice@xn--bcher-kva.example'];
        yield 'a U-label' => ['alice@bücher.example'];
        yield 'a U-label in capitals' => ['alice@BÜCHER.EXAMPLE'];
        yield 'an A-label in capitals' => ['alice@XN--BCHER-KVA.example'];
        yield 'the other domain in capitals' => ['alice@EXAMPLE.Org'];
    }

    /**
     * The acceptance of issue #785, S-62: a login_hint that is an address of a federated domain skips the page.
     */
    #[Test]
    public function aLoginHintOfAFederatedDomainSkipsThePage(): void
    {
        // Given
        $interaction = $this->authorize([
            'login_hint' => 'alice@example.org',
        ]);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, self::signOn($interaction)],
            [$response->getStatusCode(), self::locationOf($response)],
        );
    }

    /**
     * The acceptance of issue #785, S-61: an address of another domain, and a username, go on to the usual page, the
     * field of the username holding what was typed.
     */
    #[Test]
    #[DataProvider('provideOtherIdentifiers')]
    public function anotherDomainGetsTheUsualPage(string $identifier): void
    {
        // Given
        $interaction = $this->authorize();
        $this->submitAddress($interaction, $identifier);

        // When
        $crawler = $this->afterTheForm();

        // Then
        static::assertSame(
            [$identifier, 1],
            [$crawler->filter('input[name="_username"]')->attr('value'), $crawler->filter('input[name="_password"]')->count()],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherIdentifiers(): iterable
    {
        yield 'an address of another domain' => ['bob@umbrella.example'];
        yield 'an address of a subdomain of a federated domain' => ['bob@eu.example.org'];
        yield 'a username' => ['bob'];
    }

    /**
     * The acceptance of issue #785, S-61: the answer to an address is the same whether a person holds it or not, of a
     * federated domain as of another, nothing being read of a person.
     */
    #[Test]
    #[DataProvider('provideAddresses')]
    public function anUnknownAddressAndAKnownOneGetTheSameAnswer(string $address): void
    {
        // Given
        $interaction = $this->authorize();
        $token = (string) $this->loginPage($interaction)->filter('form[data-step="address"] input[name="_token"]')->attr('value');
        $this->postAddress($interaction, $address, $token);
        $unknown = self::answer($this->browser->getResponse());
        self::personOf($address);

        // When
        $this->postAddress($interaction, $address, $token);

        // Then
        static::assertSame($unknown, self::answer($this->browser->getResponse()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddresses(): iterable
    {
        yield 'of a federated domain' => ['carol@example.org'];
        yield 'of another domain' => ['carol@umbrella.example'];
    }

    /**
     * The acceptance of issue #785, S-61: the page of the address is the same whether the login_hint of the request
     * names a person or not, the field holding the hint as the client wrote it when it is an address, and nothing a
     * reading of it would find. The form tokens are drawn again at each render (BREACH), and set aside.
     */
    #[Test]
    #[DataProvider('provideHints')]
    public function theAddressPageIsTheSameWhetherTheHintNamesAPersonOrNot(string $hint): void
    {
        // Given
        $interaction = $this->authorize([
            'login_hint' => $hint,
        ]);
        $unknown = self::withoutTokens($this->loginPage($interaction)->html());
        self::user('carol@umbrella.example', $hint);

        // When
        $known = self::withoutTokens($this->loginPage($interaction)->html());

        // Then
        static::assertSame($unknown, $known);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHints(): iterable
    {
        yield 'a subject' => ['carol-subject'];
        yield 'an address of another domain' => ['carol@umbrella.example'];
    }

    /**
     * S-61, S-44: an address whose domain the rule does not read comes back to the step of the address, which says so,
     * and is never taken for an address of no federated domain.
     */
    #[Test]
    public function anAddressWhoseDomainTheRuleRefusesComesBackToTheStep(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'alice@example.org.');

        // When
        $crawler = $this->afterTheForm();

        // Then
        static::assertSame(
            ['address_unreadable', 1, 0],
            [
                $crawler->filter('p[data-error]')->attr('data-error'),
                $crawler->filter('form[data-step="address"]')->count(),
                $crawler->filter('input[name="_password"]')->count(),
            ],
        );
    }

    /**
     * S-61: the usual page goes back to the step of the address, for another one.
     */
    #[Test]
    public function theUsualPageGoesBackToTheStepOfTheAddress(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'bob@umbrella.example');
        $usual = $this->afterTheForm();

        // When
        $this->browser->submit($usual->selectButton('Use another address')->form());

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('form[data-step="address"]'));
    }

    /**
     * S-61, S-36, CSP Level 3 §6.3.2: the page of the address names in its "form-action" the origin of the single sign-on
     * service its submission ends at over HTTP-Redirect, beside the client the interaction answers.
     */
    #[Test]
    public function thePageOfTheAddressNamesTheSingleSignOnServiceOfTheProvider(): void
    {
        // Given
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->authorize();

        // When
        $this->loginPage($interaction);

        // Then
        static::assertSame(
            "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self' http://127.0.0.1 https://saml-idp.localhost; frame-ancestors 'none'",
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * The acceptance of issue #785, S-63, decision 0029: a password presented for a person of a federated domain is
     * refused, past the page that offered none, and announced so.
     */
    #[Test]
    public function aPasswordPresentedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        self::federated(self::userWithPassword('alice', self::PASSWORD));
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'alice');

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame(
            [false, [AuthenticationFailureReason::FederatedDomain]],
            [$this->isBoundToASession(), self::failures()],
        );
    }

    /**
     * The acceptance of issue #785, S-63, decision 0029: a passkey presented for a person of a federated domain is
     * refused after its signature, and announced so.
     */
    #[Test]
    public function aPasskeyPresentedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $device = self::device();
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        self::federated($alice);
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'bob');
        self::forgetEvents();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertSame(
            [false, [AuthenticationFailureReason::FederatedDomain]],
            [$this->isBoundToASession(), self::failures()],
        );
    }

    /**
     * The acceptance of issue #785, S-63, decision 0029: the code that completes a password, held before the address of
     * the person moved into a federated domain, is refused before it is read, and announced so.
     */
    #[Test]
    public function aCodePresentedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $secret = Totps::secret();
        $alice = $this->userWithTotp('alice', $secret);
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'alice');
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        self::federated($alice);

        // When
        $this->submitCode($interaction, $this->codeAt($secret, new DateTimeImmutable()));

        // Then
        static::assertSame(
            [false, [AuthenticationFailureReason::FederatedDomain]],
            [$this->isBoundToASession(), self::failures()],
        );
    }

    /**
     * The page with the value of each form token left out, a token being drawn again at each render.
     */
    private static function withoutTokens(string $html): string
    {
        return (string) preg_replace('/name="(_token|_csrf_token)" value="[^"]*"/', 'name="$1"', $html);
    }

    /**
     * The sign-on of S-51 at the identity provider of the judge, for that interaction, its reference set aside.
     */
    private static function signOn(string $interaction): string
    {
        return '/saml/sp/sign-on?interaction=' . $interaction . '&identity_provider=' . IdentityProviderDocuments::SIMPLESAMLPHP;
    }

    /**
     * Fills and posts the form of the address, as a person does.
     */
    private function submitAddress(string $interaction, string $address): void
    {
        $form = $this->loginPage($interaction)->filter('form[data-step="address"]')->form();
        $form['_address'] = $address;
        $this->browser->submit($form);
    }

    /**
     * Posts the address without reading the page, with the token the page gave.
     */
    private function postAddress(string $interaction, string $address, string $token): void
    {
        $this->browser->request('POST', '/login/address?interaction=' . $interaction, [
            '_token' => $token,
            '_address' => $address,
        ]);
    }

    /**
     * Fills and posts the form of the password of the usual page, as a person does.
     */
    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    /**
     * Fills and posts the form of the code page, as a person does.
     */
    private function submitCode(string $interaction, string $code): void
    {
        $crawler = $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        $form = $crawler->selectButton('Continue')->form();
        $form['_code'] = $code;
        $this->browser->submit($form);
    }

    /**
     * What a browser reads of an answer: its status, where it goes, and its body.
     *
     * @return array{int, string|null, string|false}
     */
    private static function answer(Response $response): array
    {
        $content = $response->getContent();

        return [$response->getStatusCode(), self::locationOf($response), $content === false ? false : self::withoutReferences($content)];
    }

    /**
     * Where an answer sends the browser, the one-time reference of a sign-on set aside (S-51).
     */
    private static function locationOf(Response $response): ?string
    {
        $location = $response->headers->get('Location');

        return $location === null ? null : self::withoutReferences($location);
    }

    /**
     * What names a sign-on with its one-time reference left out, a reference being drawn again at each answer (S-51).
     */
    private static function withoutReferences(string $text): string
    {
        return (string) preg_replace('/&(amp;)?reference=[A-Za-z0-9_-]{43}/', '', $text);
    }

    /**
     * A person whose username and mailbox are that address.
     */
    private static function personOf(string $address): void
    {
        $person = self::user($address, $address . '-subject');
        $person->changeEmail(new EmailAddress($address), true, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($person);
    }

    /**
     * The person given a mailbox of example.org, the domain the provider of the judge answers for.
     */
    private static function federated(User $user): void
    {
        $users = self::service('test.beffroi.users', UserRepositoryInterface::class);
        $person = $users->find($user->id) ?? static::fail('The person is gone.');
        $person->changeEmail(new EmailAddress($user->username . '@example.org'), true, self::now());
        $users->save($person);
    }

    /**
     * The reasons of the refused logins announced, in their order.
     *
     * @return list<AuthenticationFailureReason>
     */
    private static function failures(): array
    {
        return array_map(static fn (AuthenticationFailed $failed): AuthenticationFailureReason => $failed->reason, self::events(AuthenticationFailed::class));
    }

    /**
     * A person with a password and a TOTP enrolled an hour ago.
     */
    private function userWithTotp(string $username, TotpSecret $secret): User
    {
        $user = self::userWithPassword($username, self::PASSWORD);
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $secret->bytes);
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(new TotpCredential(
                Uuid::v7(),
                $user,
                $sealed,
                Totps::credential($user, new FakePasswordHasher())->backupCodes,
                intdiv($anHourAgo->getTimestamp(), TotpCredential::PERIOD),
                $anHourAgo,
            ));

        return $user;
    }

    private function codeAt(TotpSecret $secret, DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }

    /**
     * The document of the identity provider of the judge accepted for the tenant.
     */
    private static function accept(string $document): void
    {
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                $document,
                null,
                self::currentSecond(),
            ));
    }
}
