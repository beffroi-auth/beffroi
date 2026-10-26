<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleLogout;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\SingleLogout\ProviderLogout;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainEnded;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Domain\SingleLogout\LogoutHop;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\LogoutRequester;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\FixedSalt;
use Beffroi\Saml\Tests\Fixture\InMemoryLogoutChains;
use Beffroi\Saml\Tests\Fixture\InMemorySessionParticipations;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutNotifier;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutResponder;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.6, S-29 to S-34: every service provider of the sessions a browser ended told in turn, the
 * chain kept by the provider and played once, and where it ends.
 */
final class ProviderLogoutTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example' . FixedEndpoints::METADATA;

    private const string SINGLE_LOGOUT = 'https://id.acme.example' . FixedEndpoints::SINGLE_LOGOUT;

    private const string FIRST = 'https://first.example.org/saml';

    private const string SECOND = 'https://second.example.org/saml';

    private const string REQUESTER = 'https://asked.example.org/saml';

    private const string CONTINUE_TO = 'https://demo.example/?state=x';

    private Tenant $tenant;

    private MockClock $clock;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemorySessionParticipations $participations;

    private InMemoryLogoutChains $chains;

    private RecordingSignOutResponder $responder;

    private RecordingSignOutNotifier $notifier;

    private AuthenticationSession $session;

    /**
     * The secret of the browser of the test, the one the last chain resumed was bound to (S-32).
     */
    private LogoutChainSecret $held;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->participations = new InMemorySessionParticipations();
        $this->chains = new InMemoryLogoutChains();
        $this->responder = new RecordingSignOutResponder();
        $this->notifier = new RecordingSignOutNotifier();
        $this->session = $this->sessionSignedInAt([self::FIRST, self::REQUESTER, self::SECOND]);
        $this->held = LogoutChainSecret::draw();
    }

    /**
     * S-30, section 6.6 step 1: the service providers of each session, session by session, each in the order of its
     * first sign-on, the one that asked left out.
     */
    #[Test]
    public function theServiceProvidersOfEachSessionAreLeftToTellButTheOneThatAsked(): void
    {
        // Given
        $other = $this->sessionSignedInAt([self::SECOND]);

        // When
        $this->logout()->begin($this->tenant, [$this->session, $other], self::requester(), null);

        // Then
        static::assertEquals(
            [
                new LogoutHop($this->session->id, self::FIRST),
                new LogoutHop($this->session->id, self::SECOND),
                new LogoutHop($other->id, self::SECOND),
            ],
            $this->chains->all()[0]->progress->hops,
        );
    }

    /**
     * Section 6.6 step 1: nothing to tell and nobody to answer ends at once where the starter said, nothing written.
     */
    #[Test]
    public function nothingToTellEndsAtOnce(): void
    {
        // Given
        $alone = $this->sessionSignedInAt([]);

        // When
        $begun = $this->logout()->begin($this->tenant, [$alone], null, self::CONTINUE_TO);

        // Then
        static::assertEquals([new LogoutChainEnded(self::CONTINUE_TO), []], [$begun, $this->chains->all()]);
    }

    /**
     * S-32, section 6.6 step 1: the chain is written under the SHA-256 of a reference of 32 bytes in base64url,
     * waiting for no answer, open ten minutes, for the sessions ended.
     */
    #[Test]
    public function theChainIsWrittenUnderTheDigestOfItsReference(): void
    {
        // When
        $begun = $this->logout()->begin($this->tenant, [$this->session], null, self::CONTINUE_TO);

        // Then
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        $chain = $this->chains->all()[0];
        static::assertEquals(
            [43, LogoutChain::digestOf($begun->reference), null, Fixtures::now()->modify('+600 seconds'), [$this->session], [$this->session->id]],
            [strlen($begun->reference), $chain->reference, $chain->awaitingRequest, $chain->expiresAt, $begun->sessions, $chain->progress->sessions],
        );
    }

    /**
     * S-32, section 6.6 step 1: the chain is bound to the browser that ended the sessions by a secret of 32 bytes drawn
     * for it, in base64url, which the chain started hands on, and of which the chain keeps the SHA-256 alone.
     */
    #[Test]
    public function theChainIsBoundToASecretDrawnForTheBrowser(): void
    {
        // When
        $begun = $this->logout()->begin($this->tenant, [$this->session], null, self::CONTINUE_TO);

        // Then
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        static::assertSame(
            [43, $begun->secret->digest(), false],
            [strlen($begun->secret->value), $this->chains->all()[0]->secret, $begun->secret->value === $begun->reference],
        );
    }

    /**
     * S-32, section 6.6 step 3: the chain written again at a step stays bound to the browser that began it.
     */
    #[Test]
    public function theChainStaysBoundToTheBrowserThatBeganIt(): void
    {
        // When
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        static::assertSame($this->held->digest(), $this->chains->all()[0]->secret);
    }

    /**
     * S-30, S-31, section 6.6 step 3: the first service provider is sent a notice naming it, the persistent NameID of
     * the user of the session at it, the ID of the session and the instant of the clock, by the identity provider of
     * the tenant; what carries it is what the browser is given.
     */
    #[Test]
    public function theFirstServiceProviderIsTold(): void
    {
        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        static::assertEquals(
            [
                [new SignOutNotice(
                    self::IDENTITY_PROVIDER,
                    self::FIRST,
                    PersistentNameId::derive(self::FIRST, $this->session->user->subject, FixedSalt::SALT)->value,
                    $this->session->id->toRfc4122(),
                    Fixtures::now(),
                )],
                new RedirectedMessage(self::FIRST . '/slo?SAMLRequest=told'),
            ],
            [$this->notifier->notices, $step],
        );
    }

    /**
     * S-32, section 6.6 step 3: the chain is written again under its reference, waiting for the answer of the request
     * sent, from the service provider it went to, open ten minutes from now.
     */
    #[Test]
    public function theChainWaitsForTheAnswerOfTheRequestSent(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $this->clock->modify('+30 seconds');

        // When
        $this->resumed($begun);

        // Then
        $chain = $this->chains->all()[0];
        static::assertSame(
            [RecordingSignOutNotifier::idOf(1), self::FIRST, [self::SECOND], Fixtures::now()->modify('+630 seconds')->getTimestamp()],
            [
                $chain->awaitingRequest,
                $chain->progress->awaitingFrom,
                array_map(static fn (LogoutHop $hop): string => $hop->serviceProvider, $chain->progress->hops),
                $chain->expiresAt->getTimestamp(),
            ],
        );
    }

    /**
     * S-36, section 6.6 step 3: a request posted over HTTP-POST reaches the single logout service of the tenant, where
     * its answer comes back, the single logout service of each service provider left to tell, and where the chain ends.
     *
     * @param list<string> $ends
     */
    #[Test]
    #[DataProvider('provideEnds')]
    public function aRequestPostedReachesWhereTheChainGoesFromThere(?LogoutRequester $requester, ?string $continueTo, array $ends): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier(posting: [self::FIRST]);
        $session = $this->sessionSignedInAt([self::FIRST, self::SECOND]);

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$session], $requester, $continueTo));

        // Then
        static::assertEquals(
            new PostedForm(self::FIRST . '/slo', ['SAMLRequest' => 'told'], [self::SINGLE_LOGOUT, self::SECOND . '/slo', ...$ends]),
            $step,
        );
    }

    /**
     * @return iterable<string, array{LogoutRequester|null, string|null, list<string>}>
     */
    public static function provideEnds(): iterable
    {
        yield 'the service provider that asked' => [self::requester(), null, [self::REQUESTER . '/slo']];
        yield 'where the starter named' => [null, self::CONTINUE_TO, [self::CONTINUE_TO]];
        yield 'the page that says the browser is signed out' => [null, null, []];
    }

    /**
     * S-36: a service provider left to tell that the notifier cannot tell is not reached.
     */
    #[Test]
    public function aRequestPostedDoesNotReachAServiceProviderThatCannotBeTold(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier([self::SECOND], [self::FIRST]);
        $session = $this->sessionSignedInAt([self::FIRST, self::SECOND]);

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$session], null, null));

        // Then
        static::assertEquals(new PostedForm(self::FIRST . '/slo', ['SAMLRequest' => 'told'], [self::SINGLE_LOGOUT]), $step);
    }

    /**
     * S-32, section 6.6 step 2: a reference resumed once is not resumed again.
     */
    #[Test]
    public function aReferenceIsResumedOnce(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $this->resumed($begun);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->resumed($begun);
    }

    /**
     * S-32, section 6.6 step 2: a reference nobody wrote, and the reference of a chain past its ten minutes, resume
     * nothing.
     */
    #[Test]
    #[DataProvider('provideReferencesThatResumeNothing')]
    public function aReferenceThatHoldsNoOpenChainIsRefused(string $case): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        $reference = $case === 'nobody wrote' ? 'a-reference-nobody-wrote' : $begun->reference;
        $this->clock->modify($case === 'past its ten minutes' ? '+600 seconds' : '+599 seconds');

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->logout()->resume($this->tenant, $reference, $begun->secret);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideReferencesThatResumeNothing(): iterable
    {
        yield 'a reference nobody wrote' => ['nobody wrote'];
        yield 'a chain past its ten minutes' => ['past its ten minutes'];
    }

    /**
     * S-32: a chain that waits for the answer of a service provider is not resumed by its reference, which would skip
     * that answer.
     */
    #[Test]
    public function aChainWaitingForAnAnswerIsNotResumedByItsReference(): void
    {
        // Given
        $secret = LogoutChainSecret::draw();
        $this->chains->save(
            new LogoutChain(
                LogoutChain::digestOf('reference'),
                $secret->digest(),
                $this->tenant,
                '_request-1',
                self::progress(),
                Fixtures::now()->modify('+600 seconds'),
            ),
        );

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->logout()->resume($this->tenant, 'reference', $secret);
    }

    /**
     * S-32, section 6.6 step 2: the reference of a chain presented by a client that holds no secret, or the secret of
     * another chain, resumes nothing: the browser that began the chain holds the reference of the URL that resumes it,
     * and so may an access log.
     */
    #[Test]
    #[DataProvider('provideSecretsOfAnotherClient')]
    public function aReferenceIsRefusedToAClientThatDidNotBeginTheChain(?LogoutChainSecret $secret): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        static::assertInstanceOf(LogoutChainStarted::class, $begun);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->logout()->resume($this->tenant, $begun->reference, $secret);
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
     * S-32, section 6.6 step 2: a reference refused to another client leaves the chain to the browser it is bound to,
     * which resumes it.
     */
    #[Test]
    public function aReferenceRefusedToAnotherClientIsLeftToTheBrowserThatBeganTheChain(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        try {
            $this->logout()->resume($this->tenant, $begun->reference, LogoutChainSecret::draw());
        } catch (LogoutRefusedException) {
        }

        // When
        $step = $this->resumed($begun);

        // Then
        static::assertEquals(new RedirectedMessage(self::FIRST . '/slo?SAMLRequest=told'), $step);
    }

    /**
     * S-30, section 6.6 step 3: a service provider the notifier cannot tell is passed over, and the next one told.
     */
    #[Test]
    public function aServiceProviderThatCannotBeToldIsPassedOver(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier([self::FIRST]);

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        static::assertEquals(
            [new RedirectedMessage(self::SECOND . '/slo?SAMLRequest=told'), true],
            [$step, $this->chains->all()[0]->progress->partial],
        );
    }

    /**
     * S-30, section 6.6 step 3: a service provider whose request cannot be written, a single logout service the sender
     * refuses among the reasons, is passed over, and the next one told.
     */
    #[Test]
    public function aServiceProviderWhoseRequestCannotBeWrittenIsPassedOver(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier(refusing: [self::FIRST]);

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        static::assertEquals(
            [new RedirectedMessage(self::SECOND . '/slo?SAMLRequest=told'), true],
            [$step, $this->chains->all()[0]->progress->partial],
        );
    }

    /**
     * S-30, S-34, Core §3.7.3.2: a service provider whose request could not be written counts as one that did not
     * answer Success, the one that asked answered PartialLogout once the others answered Success.
     */
    #[Test]
    public function aServiceProviderWhoseRequestCannotBeWrittenMakesTheAnswerPartial(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier(refusing: [self::FIRST]);
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // When
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));

        // Then
        static::assertSame(SignOutStatus::PartialLogout, $this->responder->response?->status);
    }

    /**
     * S-32, section 6.6 step 2: a step that fails once it took the chain, the KMS not answering, writes the chain back
     * as it took it.
     */
    #[Test]
    public function aStepThatFailsWritesTheChainBackAsItWasTaken(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $taken = $this->chains->all();
        $this->notifier->failure = self::outage();

        // When
        try {
            $this->resumed($begun);
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertEquals($taken, $this->chains->all());
    }

    /**
     * S-32, section 6.5 step 4, section 6.6 step 2: a chain that ends at the route that resumes it, where step 1 of
     * section 6.5 does not run, has its answer open the key; a key that cannot be opened then fails the step after the
     * chain was taken, and the chain is written back as it was taken.
     */
    #[Test]
    public function aKeyThatCannotBeOpenedForTheAnswerWritesTheChainBack(): void
    {
        // Given
        $alone = $this->sessionSignedInAt([self::REQUESTER]);
        $begun = $this->logout()->begin($this->tenant, [$alone], self::requester(), null);
        $taken = $this->chains->all();
        $this->responder = new RecordingSignOutResponder(self::outage());

        // When
        try {
            $this->resumed($begun);
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertEquals($taken, $this->chains->all());
    }

    /**
     * S-32, section 6.6 step 2: the failure of a step resumed by its reference goes up, for the bundle to answer.
     */
    #[Test]
    public function theFailureOfAStepResumedByItsReferenceGoesUp(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $this->notifier->failure = self::outage();

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The KMS did not answer.');

        // When
        $this->resumed($begun);
    }

    /**
     * S-32, section 6.6 step 2: once the KMS answers, the same reference plays the step that failed.
     */
    #[Test]
    public function aStepThatFailedIsPlayedAgainByTheSameReference(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $this->notifier->failure = self::outage();
        try {
            $this->resumed($begun);
        } catch (KmsUnavailableException) {
        }
        $this->notifier->failure = null;

        // When
        $step = $this->resumed($begun);

        // Then
        static::assertEquals(new RedirectedMessage(self::FIRST . '/slo?SAMLRequest=told'), $step);
    }

    /**
     * S-32, section 6.6 step 4: a next step that fails after an answer, which cannot be read again, hands the chain on
     * under a new reference, bound to the same browser, the answer counted, waiting for nothing, its ten minutes
     * unchanged.
     */
    #[Test]
    public function aNextStepThatFailsAfterAnAnswerHandsTheChainOnUnderANewReference(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));
        $chain = $this->chains->all()[0];
        $this->notifier->failure = self::outage();
        $this->clock->modify('+30 seconds');

        // When
        $handed = $this->logout()->answered($this->tenant, new SignOutAnswer($chain, false, $this->held));

        // Then
        static::assertInstanceOf(LogoutChainStarted::class, $handed);
        static::assertEquals(
            [
                [],
                $this->held,
                [new LogoutChain(
                    LogoutChain::digestOf($handed->reference),
                    $chain->secret,
                    $this->tenant,
                    null,
                    $chain->progress->answered(false),
                    $chain->expiresAt,
                )],
            ],
            [$handed->sessions, $handed->secret, $this->chains->all()],
        );
    }

    /**
     * S-32, S-35: the chain an answer handed on is resumed by its new reference once the KMS answers, the next service
     * provider told.
     */
    #[Test]
    public function theChainAnAnswerHandedOnIsResumedByItsNewReference(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));
        $this->notifier->failure = self::outage();
        $handed = $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));
        $this->notifier->failure = null;

        // When
        $step = $this->resumed($handed);

        // Then
        static::assertEquals(new RedirectedMessage(self::SECOND . '/slo?SAMLRequest=told'), $step);
    }

    /**
     * S-30, section 6.6 step 3: a session no longer stored is passed over: no NameID can be computed for it.
     */
    #[Test]
    public function aSessionNoLongerStoredIsPassedOver(): void
    {
        // Given
        $gone = Fixtures::session(Fixtures::user($this->tenant));
        $this->participations->record(new SessionParticipation(Uuid::v7(), $this->tenant, $gone, self::SECOND, Fixtures::now()));

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$gone], self::requester(), null));

        // Then
        static::assertEquals(
            [[], SignOutStatus::PartialLogout, new LogoutChainEnded(null, new RedirectedMessage(self::REQUESTER . '/slo?SAMLResponse=answered'))],
            [$this->notifier->notices, $this->responder->response?->status, $step],
        );
    }

    /**
     * S-33, section 6.6 step 4: the answer of the service provider awaited moves the chain on to the next one.
     */
    #[Test]
    public function anAnswerMovesTheChainOnToTheNextServiceProvider(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // When
        $step = $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));

        // Then
        static::assertEquals(new RedirectedMessage(self::SECOND . '/slo?SAMLRequest=told'), $step);
    }

    /**
     * S-32: a chain another request took first is not played again from an answer.
     */
    #[Test]
    public function anAnswerToAChainAnotherRequestTookIsRefused(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));
        $chain = $this->chains->all()[0];
        $this->logout()->answered($this->tenant, new SignOutAnswer($chain, true, $this->held));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The chain of logout was played by another request (spec/saml.md S-32).');

        // When
        $this->logout()->answered($this->tenant, new SignOutAnswer($chain, true, $this->held));
    }

    /**
     * S-32, S-33: an answer carried by another browser than the one the chain is bound to moves nothing.
     */
    #[Test]
    public function anAnswerCarriedByAnotherBrowserIsRefused(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The LogoutResponse answers no request an open chain of logout waits for (spec/saml.md S-33).');

        // When
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, LogoutChainSecret::draw()));
    }

    /**
     * S-32, S-33: an answer refused to another browser leaves the chain as it was, waiting for the answer.
     */
    #[Test]
    public function anAnswerRefusedToAnotherBrowserLeavesTheChainAsItWas(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));
        $waiting = $this->chains->all();

        // When
        try {
            $this->logout()->answered($this->tenant, new SignOutAnswer($waiting[0], true, LogoutChainSecret::draw()));
        } catch (LogoutRefusedException) {
        }

        // Then
        static::assertEquals($waiting, $this->chains->all());
    }

    /**
     * S-34, section 6.6 step 5: the last answer of a chain a service provider started ends it with the answer to that
     * service provider, which the browser carries, nothing of the chain left.
     */
    #[Test]
    public function theLastAnswerEndsTheChainWithTheAnswerToTheServiceProviderThatAsked(): void
    {
        // Given
        $session = $this->sessionSignedInAt([self::FIRST, self::REQUESTER]);
        $this->resumed($this->logout()->begin($this->tenant, [$session], self::requester(), null));

        // When
        $step = $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));

        // Then
        static::assertEquals(
            [new LogoutChainEnded(null, new RedirectedMessage(self::REQUESTER . '/slo?SAMLResponse=answered')), []],
            [$step, $this->chains->all()],
        );
    }

    /**
     * S-34, section 6.6 step 5: the last answer ends a chain that answers nobody where its starter said.
     */
    #[Test]
    public function theLastAnswerEndsTheChainWhereItsStarterSaid(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], null, self::CONTINUE_TO));
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));

        // When
        $step = $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));

        // Then
        static::assertEquals([new LogoutChainEnded(self::CONTINUE_TO), []], [$step, $this->chains->all()]);
    }

    /**
     * S-34, Core §3.7.3.2: the service provider that asked is answered at the end, Success when every other one
     * answered Success, PartialLogout when one did not, or was passed over.
     */
    #[Test]
    #[DataProvider('provideOutcomes')]
    public function theServiceProviderThatAskedIsAnsweredAtTheEnd(bool $firstSucceeds, bool $secondReachable, SignOutStatus $expected): void
    {
        // Given
        if (! $secondReachable) {
            $this->notifier = new RecordingSignOutNotifier([self::SECOND]);
        }
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // When
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], $firstSucceeds, $this->held));
        if ($secondReachable) {
            $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true, $this->held));
        }

        // Then
        static::assertEquals(
            [self::requester(), $expected, self::IDENTITY_PROVIDER, Fixtures::now()],
            [
                $this->responder->response?->requester,
                $this->responder->response?->status,
                $this->responder->response?->identityProvider,
                $this->responder->response?->issuedAt,
            ],
        );
    }

    /**
     * @return iterable<string, array{bool, bool, SignOutStatus}>
     */
    public static function provideOutcomes(): iterable
    {
        yield 'every one answered Success' => [true, true, SignOutStatus::Success];
        yield 'one answered otherwise' => [false, true, SignOutStatus::PartialLogout];
        yield 'one passed over' => [true, false, SignOutStatus::PartialLogout];
    }

    /**
     * S-36: the single logout services a chain of the session would go to, the ones the notifier can tell.
     */
    #[Test]
    public function theDestinationsAreTheServicesOfTheServiceProvidersThatCanBeTold(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier([self::REQUESTER]);

        // When / Then
        static::assertSame([self::FIRST . '/slo', self::SECOND . '/slo'], $this->logout()->destinations($this->session));
    }

    /**
     * A session of the tenant, stored, that signed in at the service providers given, in that order.
     *
     * @param list<string> $serviceProviders
     */
    private function sessionSignedInAt(array $serviceProviders): AuthenticationSession
    {
        $session = Fixtures::session(Fixtures::user($this->tenant));
        $this->sessions->save($session);
        foreach ($serviceProviders as $serviceProvider) {
            $this->participations->record(new SessionParticipation(Uuid::v7(), $this->tenant, $session, $serviceProvider, Fixtures::now()));
        }

        return $session;
    }

    /**
     * The chain $begun resumed by its reference, by the browser it is bound to, whose secret the test keeps.
     */
    private function resumed(PostedForm|RedirectedMessage|LogoutChainStarted|LogoutChainEnded $begun): PostedForm|RedirectedMessage|LogoutChainEnded
    {
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        $this->held = $begun->secret;

        return $this->logout()->resume($this->tenant, $begun->reference, $begun->secret);
    }

    private function logout(): ProviderLogout
    {
        return new ProviderLogout(
            $this->participations,
            $this->chains,
            $this->sessions,
            $this->notifier,
            $this->responder,
            new FixedSalt(),
            new FixedEndpoints(),
            $this->clock,
        );
    }

    private static function requester(): LogoutRequester
    {
        return new LogoutRequester(self::REQUESTER, SignOutRequests::ID, 'state-1', SignOutRequests::REDIRECT, self::REQUESTER . '/slo');
    }

    /**
     * The KMS that does not answer, as the notifier meets it opening the key that signs (S-32).
     */
    private static function outage(): KmsUnavailableException
    {
        return new KmsUnavailableException('The KMS did not answer.');
    }

    private static function progress(): LogoutProgress
    {
        return new LogoutProgress([], [], self::FIRST, false, null, null);
    }
}
