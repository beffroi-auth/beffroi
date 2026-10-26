<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\UpstreamResponses;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Xml\Dsig\PrivateKey;
use DateTimeImmutable;
use function array_map;
use function http_build_query;
use function parse_url;
use function str_starts_with;
use function strtok;
use function ucfirst;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-52 to S-59, section 6.14, the acceptance of issue #784: in a deployment whose tenant is
 * a service provider (tests/symfony/config/config_test_service_provider.yml), the SimpleSAMLphp identity provider of
 * the judge declared and its document accepted, an interaction sent to it is answered by a response signed by its key,
 * posted to the assertion consumer service, which signs the person in and resumes the interaction; what the response
 * does not answer is refused, and nobody is signed in.
 */
final class AssertionConsumerServiceTest extends ConsoleTestCase
{
    use SignOnFromTheLoginPage;

    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string ASSERTION_CONSUMER_SERVICE = 'https://op.test/saml/sp/acs';

    private const string AUDIENCE = 'https://op.test/saml/sp/metadata';

    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    private const string ADDRESS = 'alice@example.org';

    /**
     * The single sign-on service of the second provider of the kernel, which requires its assertions encrypted.
     */
    private const string ENCRYPTING_SINGLE_SIGN_ON = 'https://idp.example.org/saml/sso';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * The acceptance of issue #784, S-53, S-59: a signed response for the request of the interaction completes the
     * interaction with a code for the client.
     */
    #[Test]
    public function aSignedResponseCompletesTheInteractionWithACode(): void
    {
        // Given
        self::provisioned();
        $interaction = $this->beginAuthorization();
        $request = $this->signOn($interaction);

        // When
        $this->post($this->response($request));
        $answer = $this->resumed();

        // Then
        static::assertArrayHasKey('code', self::redirectedQuery($answer));
    }

    /**
     * The acceptance of issue #784, S-56, issues #781 and #782: the first sign-in creates the person the provider names,
     * its address verified, and makes it a member of the group the declaration maps its value to.
     */
    #[Test]
    public function theFirstSignInCreatesThePersonWithItsGroup(): void
    {
        // Given
        self::provisioned();
        $members = new Group(Uuid::v7(), self::tenant(), 'Members', GroupSource::Local, self::currentSecond());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($members);
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, ['eduPersonAffiliation' => ['member', 'student']]));

        // Then
        $alice = self::person();
        static::assertSame([self::ADDRESS, true, ['Members']], [
            $alice->username,
            $alice->emailVerified,
            array_map(
                static fn ($membership): string => $membership->group->name,
                self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($alice),
            ),
        ]);
    }

    /**
     * The acceptance of issue #784, S-55: the client gets the same subject at every sign-in of that person, the person
     * found again by its linked identity.
     */
    #[Test]
    public function theClientGetsTheSameSubAtEverySignIn(): void
    {
        // Given
        self::provisioned();
        $first = self::claimsOf($this->idTokenOf('alice'));
        $this->browser->getCookieJar()->clear();

        // When
        $second = self::claimsOf($this->idTokenOf('alice'));

        // Then
        static::assertSame($first['sub'], $second['sub']);
    }

    /**
     * S-57, OIDC Core §2: the AuthnInstant of the assertion is the auth_time the client reads, and the methods are a
     * federated assertion and the password its class names.
     */
    #[Test]
    public function theAuthnInstantIsTheAuthTimeOfTheSession(): void
    {
        // Given
        self::provisioned();
        $authnInstant = new DateTimeImmutable('@' . (Clock::get()->now()->getTimestamp() - 30));
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, authnInstant: $authnInstant));
        $claims = $this->idToken($this->resumed());

        // Then
        static::assertSame([$authnInstant->getTimestamp(), ['fed', 'pwd']], [$claims['auth_time'], $claims['amr']]);
    }

    /**
     * The acceptance of issue #784, S-53, M-8, Core §2.5.1.4: a response for another audience signs nobody in.
     */
    #[Test]
    public function aResponseForAnotherAudienceIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, audience: 'https://another.example/saml/sp/metadata'));

        // Then
        $this->assertRefused('An AudienceRestriction does not hold our entity ID among its audiences (M-8).');
    }

    /**
     * The acceptance of issue #784, S-53, M-10: a response to a request nobody sent signs nobody in.
     */
    #[Test]
    public function aResponseToARequestNobodySentIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response([...$request, 'id' => '_ffffffffffffffffffffffffffffffffffffffff']));

        // Then
        $this->assertRefused('The InResponseTo of the response is not the one the consumer expects (M-10).');
    }

    /**
     * The acceptance of issue #784, S-53: a form posted a second time finds nothing the browser remembers, its request
     * forgotten at the first post, and signs nobody in again.
     */
    #[Test]
    public function aResponsePostedTwiceIsRefused(): void
    {
        // Given
        self::provisioned();
        $form = $this->response($this->signOn($this->beginAuthorization()));
        $this->post($form);
        self::forgetEvents();

        // When
        $this->post($form);

        // Then
        $this->assertRefused('The response answers no request this browser remembers (spec/saml.md S-53).');
    }

    /**
     * The acceptance of issue #784, S-53, M-11: the assertion of a response accepted, presented again under a request
     * this browser does remember, is refused by the replay store.
     */
    #[Test]
    public function anAssertionPresentedAgainIsRefusedByTheReplayStore(): void
    {
        // Given
        self::provisioned();
        $this->post($this->response($this->signOn($this->beginAuthorization()), assertionId: '_assertion-of-alice'));
        $this->browser->getCookieJar()->clear();
        self::forgetEvents();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, assertionId: '_assertion-of-alice'));

        // Then
        $this->assertRefused('The assertion was already accepted from its issuer (M-11).');
    }

    /**
     * The acceptance of issue #784, S-53, decision 0029: an unsolicited response, which answers no request and carries
     * no RelayState, signs nobody in.
     */
    #[Test]
    public function anUnsolicitedResponseIsRefused(): void
    {
        // Given
        self::provisioned();
        $this->signOn($this->beginAuthorization());

        // When
        $this->post(UpstreamResponses::form(
            UpstreamResponses::simpleSamlPhpKey(),
            IdentityProviderDocuments::SIMPLESAMLPHP,
            self::ASSERTION_CONSUMER_SERVICE,
            self::AUDIENCE,
            null,
            Clock::get()->now(),
            ['mail' => [self::ADDRESS]],
        ));

        // Then
        $this->assertRefused('The response answers no request this browser remembers (spec/saml.md S-53).');
    }

    /**
     * The acceptance of issue #784, S-53, M-3: a response signed by a key the metadata of the provider do not publish
     * signs nobody in, whatever key the message names.
     */
    #[Test]
    public function aSignatureUnderAKeyOutsideTheMetadataIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, key: MetadataFixtures::signingKey('idp'), certificatePem: MetadataFixtures::certificatePem('idp')));

        // Then
        $this->assertRefused('No trusted key verifies the signature over SignedInfo (D-7, D-8).');
    }

    /**
     * S-39, S-52: the assertion consumer service the metadata of the service provider announce is the URL the router
     * generates for its route.
     */
    #[Test]
    public function theMetadataAnnounceTheUrlOfTheRoute(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        $serviceProvider = new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
        )->serviceProvider ?? static::fail('The tenant serves no service provider.');
        static::assertSame(
            self::tenant()->issuer->origin()
                . self::service('router', UrlGeneratorInterface::class)->generate(ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE),
            $serviceProvider->assertionConsumerServices->default()->location,
        );
    }

    /**
     * S-52, S-28: the response the provider posts from its own site, which comes without the session cookie, is posted
     * again from the origin of the provider, and that post signs the person in.
     */
    #[Test]
    public function aResponsePostedFromAnotherSiteIsPostedAgainAndSignsThePersonIn(): void
    {
        // Given
        self::provisioned();
        $form = $this->response($this->signOn($this->beginAuthorization()));
        $this->postedFromAnotherSite('/saml/sp/acs', http_build_query($form));

        // When
        $this->postedAgain();
        $answer = $this->resumed();

        // Then
        static::assertArrayHasKey('code', self::redirectedQuery($answer));
    }

    /**
     * S-58, S-49, OIDC Core §3.1.2.1: an AuthnInstant older than the max_age of the client opens no session, and the
     * request is sent once more, with ForceAuthn.
     */
    #[Test]
    public function anAssertionOlderThanTheMaxAgeSendsTheRequestOnceMoreWithForceAuthn(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization(['max_age' => '60']));

        // When
        $this->post($this->response($request, authnInstant: Clock::get()->now()->modify('-2 hours')));

        // Then
        static::assertSame([true, []], [$this->sentRequest()->forceAuthn, self::events(UserAuthenticated::class)]);
    }

    /**
     * S-58, OIDC Core §3.1.2.6: an assertion that answers the request sent with ForceAuthn still older than the max_age
     * is answered with login_required at the redirection URI of the client, and nothing is sent a third time.
     */
    #[Test]
    public function anAssertionStillOlderThanTheMaxAgeIsAnsweredLoginRequired(): void
    {
        // Given
        self::provisioned();
        $this->post($this->response($this->signOn($this->beginAuthorization(['max_age' => '60'])), authnInstant: Clock::get()->now()->modify('-2 hours')));
        $again = $this->sentRequestOfTheAnswer();

        // When
        $this->post($this->response($again, authnInstant: Clock::get()->now()->modify('-2 hours')));

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * S-58, S-49: a client that asked for prompt=login sends ForceAuthn from the first request, and an AuthnInstant
     * before the interaction began is answered with login_required, never sent round again.
     */
    #[Test]
    public function anAssertionOlderThanAPromptLoginIsAnsweredLoginRequired(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization(['prompt' => 'login']));

        // When
        $this->post($this->response($request, authnInstant: Clock::get()->now()->modify('-5 seconds')));

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * S-59: the login a page of the provider waits for comes back to that page, its route and its parameters as the
     * provider remembered them.
     */
    #[Test]
    public function theLoginAPageWaitsForComesBackToThatPage(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOnFromTheAccount();

        // When
        $this->post($this->response($request));

        // Then
        static::assertSame('/account', $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * S-49, S-58, OIDC Core §3.1.2.1: a client that names bob by an id_token_hint while alice is signed in has the
     * request force a login at the provider, whose own session would answer for alice.
     */
    #[Test]
    public function anIdTokenHintNamingAnotherPersonForcesTheLogin(): void
    {
        // Given
        self::provisioned();
        $bob = $this->idTokenOf('bob');
        $this->browser->getCookieJar()->clear();
        $this->idTokenOf('alice');
        $interaction = $this->beginAuthorization(['id_token_hint' => $bob]);

        // When
        $this->signOnAs($interaction, self::ADDRESS);

        // Then
        static::assertTrue($this->sentRequest()->forceAuthn);
    }

    /**
     * S-58, OIDC Core §3.1.2.6: the provider asserting alice again for a client that names bob, ForceAuthn
     * notwithstanding, is answered with login_required, and never sent round again.
     */
    #[Test]
    public function aProviderThatAssertsAnotherPersonThanTheHintIsAnsweredLoginRequired(): void
    {
        // Given
        self::provisioned();
        $bob = $this->idTokenOf('bob');
        $this->browser->getCookieJar()->clear();
        $this->idTokenOf('alice');
        $request = $this->signOn($this->beginAuthorization(['id_token_hint' => $bob]));

        // When
        $this->post($this->response($request));

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * S-59: a page that asks a person signed in for a login sends a request that forces one, and an AuthnInstant
     * before that request was issued, a provider that did not authenticate the person again, is refused and sent
     * nowhere again.
     */
    #[Test]
    public function aPageIsRefusedAnAuthenticationOlderThanItsRequest(): void
    {
        // Given
        self::provisioned();
        $this->idTokenOf('alice');
        $this->httpSession(static function (SessionInterface $httpSession): void {
            $httpSession->set(LoginTarget::SESSION_KEY, [
                'route' => 'beffroi_interaction_account',
                'parameters' => [],
                'step_up' => null,
            ]);
        });
        $this->signOnAs(null, self::ADDRESS);
        $request = $this->sentRequestOfTheAnswer();
        self::forgetEvents();

        // When
        $this->post($this->response($request, authnInstant: Clock::get()->now()->modify('-1 hour')));

        // Then
        $this->assertRefused('The identity provider did not authenticate the person again, ForceAuthn notwithstanding (spec/saml.md S-59).');
    }

    /**
     * S-57, S-53: a tenant whose every login must prove two factors refuses a login of the provider that proves one,
     * with the page of a refusal, before the person is written, and announces it with no identifier.
     */
    #[Test]
    public function aLoginUnderTheFloorOfTheTenantIsRefusedAndAnnounced(): void
    {
        // Given
        self::provisioned();
        $tester = self::console('beffroi:tenant:login-floor', ['floor' => 'two_factors'], ['yes']);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request));

        // Then
        $this->assertRefused('The login of the identity provider proves less than this tenant requires of every login (spec/saml.md S-57).');
        static::assertSame(
            [[AuthenticationFailureReason::BelowTheFloor, 'fed', null, null], []],
            [
                self::failures(),
                self::service('test.beffroi.users', UserRepositoryInterface::class)->findAllByEmail(self::tenant(), new EmailAddress(self::ADDRESS)),
            ],
        );
    }

    /**
     * S-53: a response refused, here one signed by a key outside the metadata, leaves its trace in the audit trail: a
     * federated assertion refused, nothing typed, nobody named.
     */
    #[Test]
    public function aRefusedResponseIsAnnounced(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());
        self::forgetEvents();

        // When
        $this->post($this->response($request, key: MetadataFixtures::signingKey('idp'), certificatePem: MetadataFixtures::certificatePem('idp')));

        // Then
        static::assertSame([AuthenticationFailureReason::UpstreamResponseRefused, 'fed', null, null], self::failures());
    }

    /**
     * S-53, M-16: the refusal of an address the core refuses carries no exception under it, whose message would hold the
     * address, since what the firewall logs is the whole chain.
     */
    #[Test]
    public function theRefusalOfAnAddressCarriesNoValueInItsChain(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());
        $refused = new class {
            public ?AuthenticationException $exception = null;
        };
        // the dispatcher of the firewall, where the security component dispatches what a login of it does
        self::service('security.event_dispatcher.beffroi_interaction', EventDispatcherInterface::class)
            ->addListener(
                LoginFailureEvent::class,
                static function (LoginFailureEvent $event) use ($refused): void {
                    $refused->exception = $event->getException();
                },
            );

        // When
        $this->post($this->response($request, ['mail' => ['al ice@example.org']]));

        // Then
        static::assertSame(
            ['The attribute of the e-mail is no address whose domain the rule reads (spec/saml.md S-56, S-60).', null],
            [$refused->exception?->getMessage(), $refused->exception?->getPrevious()],
        );
    }

    /**
     * S-55, decision 0029: a persistent NameID an administrator filled with the address of the person is refused, a
     * mailbox given again naming the newcomer otherwise.
     */
    #[Test]
    public function aPersistentNameIdThatIsTheAddressIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, nameId: new NameId('Alice@EXAMPLE.org', NameIdFormat::Persistent)));

        // Then
        $this->assertRefused('The subject is the address of the person, which is given again to another (spec/saml.md S-55).');
    }

    /**
     * The acceptance of issue #820, S-56: a valid assertion for a person an administrator disabled writes nothing of
     * what it says, the address, the username, the profile and the groups of the person being what they were.
     */
    #[Test]
    public function aValidAssertionForADisabledPersonWritesNothing(): void
    {
        // Given
        self::provisioned();
        $this->disabledAliceSigningOnAgain();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, ['mail' => ['alicia@example.org'], 'givenName' => ['Alicia']]));

        // Then
        $alice = self::person();
        static::assertSame([self::ADDRESS, self::ADDRESS, 'Alice', ['Members']], [
            $alice->email?->value,
            $alice->username,
            $alice->profile->givenName,
            array_map(
                static fn ($membership): string => $membership->group->name,
                self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($alice),
            ),
        ]);
    }

    /**
     * The acceptance of issue #820, S-56, S-53: a valid assertion for a disabled person is refused with the page of
     * every refusal of the person, which says nothing of the state of the account, and announced as a login refused
     * for a disabled account, nothing typed.
     */
    #[Test]
    public function aValidAssertionForADisabledPersonIsRefusedAndAnnounced(): void
    {
        // Given
        self::provisioned();
        $this->disabledAliceSigningOnAgain();
        $request = $this->signOn($this->beginAuthorization());
        self::forgetEvents();

        // When
        $this->post($this->response($request));

        // Then
        $this->assertRefused('The person the identity provider named is not one this provider signs in (spec/saml.md S-56).');
        static::assertSame([AuthenticationFailureReason::DisabledUser, 'fed', null, null], self::failures());
    }

    /**
     * S-57, SAML Core §2.7.2, issue #813: the session the login opens ends at the SessionNotOnOrAfter the provider
     * allows, before the lifetime of the tenant.
     */
    #[Test]
    public function theSessionEndsAtTheSessionNotOnOrAfter(): void
    {
        // Given
        self::provisioned();
        $bound = new DateTimeImmutable('@' . (Clock::get()->now()->getTimestamp() + 3600));
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, sessionNotOnOrAfter: $bound));

        // Then
        static::assertEquals($bound, $this->boundSession()->expiresAt);
    }

    /**
     * S-59, decision (b) of the review of #806: another person signing in for a page that waits ends the session the
     * browser held, opens theirs, and the page is served to them.
     */
    #[Test]
    public function anotherPersonSigningInForAPageThatWaitsIsServedThatPage(): void
    {
        // Given
        self::provisioned();
        $this->idTokenOf('alice');
        $request = $this->signOnForThePage([]);

        // When
        $this->post($this->response($request, person: 'bob'));

        // Then
        static::assertSame(['/account', 'bob@example.org'], [$this->browser->getResponse()->headers->get('Location'), $this->boundSession()->user->username]);
    }

    /**
     * S-59: a page that asked for one more proof, a class the login of the provider does not prove, is refused, its
     * request having carried ForceAuthn already.
     */
    #[Test]
    public function aPageWhoseStepUpTheLoginDoesNotMeetIsRefused(): void
    {
        // Given
        self::provisioned();
        $this->idTokenOf('alice');
        $request = $this->signOnForThePage(['classes' => ['phr'], 'kinds' => ['passkey']]);
        self::forgetEvents();

        // When
        $this->post($this->response($request));

        // Then
        $this->assertRefused('The identity provider proved none of the classes the page asks for (spec/saml.md S-59).');
    }

    /**
     * S-53, M-8, Profiles §4.1.4.3: a response for another assertion consumer service than the one the router generates
     * is refused.
     */
    #[Test]
    public function aResponseToAnotherAssertionConsumerServiceIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, assertionConsumerService: 'https://op.test/elsewhere/acs'));

        // Then
        $this->assertRefused('The Destination of the response is not the URL at which it arrived (M-8).');
    }

    /**
     * S-58, OIDC Core §3.1.2.6: a client that asks for an account to be chosen, answered twice by the session the provider
     * holds, is answered account_selection_required.
     */
    #[Test]
    public function anAccountSelectionTheProviderDoesNotOfferIsAnsweredAccountSelectionRequired(): void
    {
        // Given
        self::provisioned();
        $this->post($this->response(
            $this->signOn($this->beginAuthorization(['prompt' => 'select_account'])),
            authnInstant: Clock::get()->now()->modify('-5 seconds'),
        ));
        $again = $this->sentRequestOfTheAnswer();

        // When
        $this->post($this->response($again, authnInstant: Clock::get()->now()->modify('-5 seconds')));

        // Then
        static::assertSame('account_selection_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * The acceptance of issue #784 as amended, S-54, S-67: a provider declared with require_encrypted_assertions has a
     * clear assertion it signed refused, whatever signatures held.
     */
    #[Test]
    public function aClearAssertionOfAProviderAskedToEncryptIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization(), IdentityProviderDocuments::SIGNED);

        // When
        $this->post(UpstreamResponses::form(
            MetadataFixtures::signingKey('idp'),
            IdentityProviderDocuments::SIGNED,
            self::ASSERTION_CONSUMER_SERVICE,
            self::AUDIENCE,
            $request['id'],
            Clock::get()->now(),
            ['mail' => ['carol@encrypting.example']],
            $request['relay_state'],
        ));

        // Then
        $this->assertRefused('The identity provider is required to encrypt its assertions and sent one in clear (spec/saml.md S-54, S-67).');
    }

    /**
     * S-53, M-3, M-8: an assertion the first provider signed, posted for a request sent to the second, is verified under
     * the metadata of the second, and refused.
     */
    #[Test]
    public function anAssertionOfOneProviderForARequestSentToAnotherIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization(), IdentityProviderDocuments::SIGNED);

        // When
        $this->post($this->response($request));

        // Then
        $this->assertRefused('No trusted key verifies the signature over SignedInfo (D-7, D-8).');
    }

    /**
     * S-58, OIDC Core §3.1.2.6: a response whose status is not Success, the person having failed at the provider, ends
     * the interaction with access_denied at the redirection URI of the client, its state given back, and nothing of the
     * provider in it.
     */
    #[Test]
    public function aFailedAuthenticationAnswersTheClientAccessDenied(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post(UpstreamResponses::failure(
            UpstreamResponses::simpleSamlPhpKey(),
            IdentityProviderDocuments::SIMPLESAMLPHP,
            self::ASSERTION_CONSUMER_SERVICE,
            $request['id'],
            Clock::get()->now(),
            SecondLevelStatusCode::AuthnFailed,
            $request['relay_state'],
        ));

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertSame(
            ['http://127.0.0.1/callback', 'access_denied', 'state-of-the-client', 'The identity provider authenticated nobody.'],
            [
                strtok(self::string($this->browser->getResponse()->headers->get('Location')), '?'),
                $query['error'] ?? null,
                $query['state'] ?? null,
                $query['error_description'] ?? null,
            ],
        );
    }

    /**
     * S-58, S-59: a response whose status is not Success for the login a page waits for is the page of a refusal.
     */
    #[Test]
    public function aFailedAuthenticationForAPageIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOnFromTheAccount();

        // When
        $this->post(UpstreamResponses::failure(
            UpstreamResponses::simpleSamlPhpKey(),
            IdentityProviderDocuments::SIMPLESAMLPHP,
            self::ASSERTION_CONSUMER_SERVICE,
            $request['id'],
            Clock::get()->now(),
            SecondLevelStatusCode::AuthnFailed,
            $request['relay_state'],
        ));

        // Then
        $this->assertRefused('The identity provider authenticated nobody (spec/saml.md S-58).');
    }

    /**
     * The tenant holds a SAML key, a key that signs its ID tokens, the document of the provider of the judge and the one
     * of the second provider of the kernel.
     */
    private static function provisioned(): void
    {
        self::generate();
        self::signingKey();
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                IdentityProviderDocuments::simpleSamlPhp(),
                null,
                self::currentSecond(),
            ));
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIGNED,
                self::encryptingDocument(),
                null,
                self::currentSecond(),
            ));
    }

    private static function generate(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * @param array<string, string> $parameters
     */
    private function beginAuthorization(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));

        return self::redirectedInteraction($response);
    }

    /**
     * The request the sign-on of the interaction sent the provider, as the provider reads it, the sign-on started from
     * the login page by an address of a domain of that provider.
     *
     * @return array{id: string, relay_state: string}
     */
    private function signOn(string $interaction, string $identityProvider = IdentityProviderDocuments::SIMPLESAMLPHP): array
    {
        $this->signOnAs($interaction, $identityProvider === IdentityProviderDocuments::SIGNED ? 'alice@encrypting.example' : self::ADDRESS);

        return $this->sentRequestOfTheAnswer($identityProvider);
    }

    /**
     * The document of the second provider of the kernel, which requires its assertions encrypted.
     */
    private static function encryptingDocument(): string
    {
        return self::string(file_get_contents(IdentityProviderDocuments::signedPath()));
    }

    /**
     * The login the home of the account waits for sent to the provider, its address typed as a person types it.
     *
     * @return array{id: string, relay_state: string}
     */
    private function signOnFromTheAccount(): array
    {
        $this->browser->request('GET', '/account');
        $this->signOnAs(null, self::ADDRESS);

        return $this->sentRequestOfTheAnswer();
    }

    /**
     * The ID and the RelayState of the request the last answer carries to the provider.
     *
     * @return array{id: string, relay_state: string}
     */
    private function sentRequestOfTheAnswer(string $identityProvider = IdentityProviderDocuments::SIMPLESAMLPHP): array
    {
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));
        $request = $this->sentRequest($identityProvider);

        return [
            'id' => $request->id,
            'relay_state' => $received->relayState ?? static::fail('The request carries no RelayState.'),
        ];
    }

    /**
     * The request the last answer carries to the provider, validated on its side under the metadata the service
     * provider serves.
     */
    private function sentRequest(string $identityProvider = IdentityProviderDocuments::SIMPLESAMLPHP): AuthnRequest
    {
        $singleSignOn = $identityProvider === IdentityProviderDocuments::SIGNED ? self::ENCRYPTING_SINGLE_SIGN_ON : self::SINGLE_SIGN_ON;
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $location = self::string($response->headers->get('Location'));
        static::assertStringStartsWith($singleSignOn . '?', $location);
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));
        $this->browser->request('GET', '/saml/sp/metadata');
        $serviceProvider = new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
        )->serviceProvider ?? static::fail('The tenant serves no service provider.');
        $document = $identityProvider === IdentityProviderDocuments::SIGNED ? self::encryptingDocument() : IdentityProviderDocuments::simpleSamlPhp();
        $read = new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load($document),
        )->identityProvider ?? static::fail('The document holds no identity provider.');

        return $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), Clock::get()),
            $serviceProvider,
            $read,
            $singleSignOn,
        )->request;
    }

    /**
     * The form the provider posts for the request, signed by its key.
     *
     * @param array{id: string, relay_state: string} $request
     * @param array<string, list<string>> $attributes
     *
     * @return array<string, string>
     */
    private function response(
        array $request,
        array $attributes = [],
        string $audience = self::AUDIENCE,
        ?DateTimeImmutable $authnInstant = null,
        ?string $assertionId = null,
        ?PrivateKey $key = null,
        string $person = 'alice',
        ?string $certificatePem = null,
        ?NameId $nameId = null,
        ?DateTimeImmutable $sessionNotOnOrAfter = null,
        string $assertionConsumerService = self::ASSERTION_CONSUMER_SERVICE,
    ): array {
        return UpstreamResponses::form(
            $key ?? UpstreamResponses::simpleSamlPhpKey(),
            IdentityProviderDocuments::SIMPLESAMLPHP,
            $assertionConsumerService,
            $audience,
            $request['id'],
            Clock::get()->now(),
            ['mail' => [$person . '@example.org'], 'givenName' => [ucfirst($person)], ...$attributes],
            $request['relay_state'],
            $authnInstant,
            $nameId ?? new NameId('persistent-' . $person, NameIdFormat::Persistent),
            assertionId: $assertionId,
            sessionNotOnOrAfter: $sessionNotOnOrAfter,
            certificatePem: $certificatePem,
        );
    }

    /**
     * @param array<string, string> $form
     */
    private function post(array $form): void
    {
        $this->browser->request('POST', '/saml/sp/acs', $form);
    }

    /**
     * The answer of the client once the browser is sent back to the interaction, past a consent the client asks for.
     */
    private function resumed(): Response
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $this->browser->followRedirect();
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        if (str_starts_with($location, '/consent?')) {
            $this->browser->submit($this->browser->followRedirect()->selectButton('Allow')->form());
        }

        return $this->browser->getResponse();
    }

    /**
     * The login the home of the account waits for, the step-up given, sent to the provider by a browser signed in.
     *
     * @param array{classes?: list<string>, kinds?: list<string>} $stepUp
     *
     * @return array{id: string, relay_state: string}
     */
    private function signOnForThePage(array $stepUp): array
    {
        $this->httpSession(static function (SessionInterface $httpSession) use ($stepUp): void {
            $httpSession->set(LoginTarget::SESSION_KEY, [
                'route' => 'beffroi_interaction_account',
                'parameters' => [],
                'step_up' => $stepUp === [] ? null : $stepUp,
            ]);
        });
        $this->signOnAs(null, self::ADDRESS);

        return $this->sentRequestOfTheAnswer();
    }

    /**
     * The session the browser is bound to.
     */
    private function boundSession(): AuthenticationSession
    {
        $id = $this->readHttpSession()->get(BrowserSession::AUTHENTICATION_SESSION_KEY);
        static::assertIsString($id);

        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString($id)) ?? static::fail('The browser is bound to no session.')
        );
    }

    /**
     * What the audit trail was told of the one login refused since the events were last forgotten: the reason, the
     * method, the identifier and the person.
     *
     * @return array{AuthenticationFailureReason, string|null, string|null, string|null}
     */
    private static function failures(): array
    {
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);

        return [$failures[0]->reason, $failures[0]->method?->value, $failures[0]->identifier, $failures[0]->user?->username];
    }

    /**
     * A sign-in of that person through the provider, from an interaction to the ID token its code is exchanged for.
     */
    private function idTokenOf(string $person): string
    {
        $this->post($this->response($this->signOn($this->beginAuthorization()), person: $person));
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => self::redirectedQuery($this->resumed())['code'] ?? static::fail('The client got no code.'),
            'redirect_uri' => 'http://127.0.0.1/callback',
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => 'native-app',
        ]);

        return self::string(self::json($this->browser->getResponse())['id_token'] ?? null);
    }

    /**
     * The claims of the ID token the code of the answer is exchanged for.
     *
     * @return array<string, mixed>
     */
    private function idToken(Response $answer): array
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => self::redirectedQuery($answer)['code'] ?? static::fail('The client got no code.'),
            'redirect_uri' => 'http://127.0.0.1/callback',
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => 'native-app',
        ]);

        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token'] ?? null));
    }

    /**
     * Refused with the page of a refusal, for the rule given, and nobody signed in.
     */
    private function assertRefused(string $rule): void
    {
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'saml_assertion_refused', 'saml_assertion_refused: ' . $rule, []],
            [
                $response->getStatusCode(),
                $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'),
                $this->browser->getCrawler()->filter('[data-description]')->text(),
                self::events(UserAuthenticated::class),
            ],
            self::string($response->getContent()),
        );
    }

    /**
     * Alice signed in once through the provider, a member of the group her value maps to, then disabled by an
     * administrator, in a browser that holds no session of hers.
     */
    private function disabledAliceSigningOnAgain(): void
    {
        $members = new Group(Uuid::v7(), self::tenant(), 'Members', GroupSource::Local, self::currentSecond());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($members);
        $this->post($this->response($this->signOn($this->beginAuthorization()), ['eduPersonAffiliation' => ['member']]));
        $this->browser->getCookieJar()->clear();
        $alice = self::person();
        $alice->disable(Clock::get()->now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
    }

    private static function person(): User
    {
        $people = self::service('test.beffroi.users', UserRepositoryInterface::class)->findAllByEmail(self::tenant(), new EmailAddress(self::ADDRESS));
        static::assertCount(1, $people);

        return $people[0];
    }
}
