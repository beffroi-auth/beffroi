<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use DateTimeImmutable;
use App\Http\BrowserSession;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\PasswordRehashed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.4
 */
final class LoginTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Architecture §5.4
     */
    #[Test]
    public function aSuccessfulLoginGoesBackToTheLoginPageOfTheInteraction(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * RFC 8265 §3.3.4, RFC 7643 §4.1.1
     */
    #[Test]
    public function aLoginUnderAnotherCaseOfTheUsernameSignsThePersonIn(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'ALICE', self::PASSWORD);

        // Then
        static::assertTrue($this->boundSession()->user->id->equals($user->id));
    }

    /**
     * RFC 8265 §4.2.3, RFC 7644 §5
     */
    #[Test]
    public function aPasswordTypedInAnotherFormThanItWasSetInSignsThePersonIn(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', "correct\u{00A0}horse battery\u{3000}staple");

        // Then
        static::assertTrue($this->boundSession()->user->id->equals($user->id));
    }

    /**
     * OIDC Core §2, RFC 8176 §2, Architecture §3.2, §3.5
     */
    #[Test]
    public function aSuccessfulLoginOpensASessionOfTheCore(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $before = new DateTimeImmutable();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $session = $this->boundSession();
        static::assertTrue($session->user->id->equals($user->id));
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertGreaterThanOrEqual(
            $before->setTime((int) $before->format('H'), (int) $before->format('i'), (int) $before->format('s')),
            $session->authenticatedAt(),
        );
        static::assertLessThanOrEqual(new DateTimeImmutable('+5 seconds'), $session->authenticatedAt());
        static::assertSame('127.0.0.1', $session->createdFrom->ipAddress);
        static::assertSame('Symfony BrowserKit', $session->createdFrom->userAgent);
        static::assertTrue($session->isActive(new DateTimeImmutable()));
        static::assertSame('1', $session->authenticationContextClass()->value);
    }

    #[Test]
    public function theTokenOfTheFirewallCarriesTheAuthTimeOfTheSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame(
            [
                'pwd' => $this->boundSession()->authenticatedAt()->getTimestamp(),
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    #[Test]
    public function aSuccessfulLoginDatesTheUseOfTheCredential(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $credential = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($this->boundSession()->user, PasswordCredential::class)[0] ?? static::fail('The credential is gone.');
        static::assertNotNull($credential->lastUsedAt);
    }

    /**
     * Architecture §3.5
     */
    #[Test]
    public function aSuccessfulLoginIsAnnouncedOnce(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $events = self::events(UserAuthenticated::class);
        static::assertCount(1, $events);
        static::assertTrue($events[0]->session->id->equals($this->boundSession()->id));
        static::assertSame([], self::events(PasswordRehashed::class));
    }

    #[Test]
    public function theInteractionGoesOnWithTheSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function anotherBrowserCannotSeeTheLoginPageOfAnInteraction(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->browser->getCookieJar()->clear();

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function anotherBrowserCannotPostTheLoginFormOfAnInteraction(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $token = $this->csrfTokenOfTheLoginPage($interaction);
        $this->browser->getCookieJar()->clear();

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, $token);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    #[Test]
    public function aLoginPostedByAnotherBrowserOpensNoSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $token = $this->csrfTokenOfTheLoginPage($interaction);
        $this->browser->getCookieJar()->clear();

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, $token);

        // Then
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    #[Test]
    #[DataProvider('providePagesOfAnInteraction')]
    public function aBrowserSignedInOnItsOwnInteractionCannotResumeAnotherOne(string $path): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->browser->getCookieJar()->clear();
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', $path, [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePagesOfAnInteraction(): iterable
    {
        yield 'the login page' => ['/login'];
        yield 'the consent page' => ['/consent'];
    }

    #[Test]
    public function anInteractionAnotherBrowserTriedToResumeIsStillPending(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->browser->getCookieJar()->clear();
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertFalse(self::service('test.beffroi.interactions', InteractionRepositoryInterface::class)->find($interaction)?->isCompleted());
    }

    /**
     * Decision 0006, Architecture §3.4
     */
    #[Test]
    public function aWrongPasswordGoesBackToTheLoginPage(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    #[Test]
    public function aWrongPasswordOpensNoSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.4
     */
    #[Test]
    public function aWrongPasswordIsRecordedWithItsReason(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('alice', $failures[0]->identifier);
        static::assertTrue($failures[0]->user?->id->equals($user->id));
        static::assertSame('127.0.0.1', $failures[0]->context->ipAddress);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function afterAWrongPasswordTheFormShowsOneMessageAndKeepsTheUsername(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', 'not the password');

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('authentication_failed', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('alice', $crawler->filter('input[name="_username"]')->attr('value'));
    }

    #[Test]
    public function theMessageOfAFailedLoginIsShownOnce(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', 'not the password');
        $this->loginPage($interaction);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertCount(0, $crawler->filter('p[data-error]'));
    }

    /**
     * Decision 0006
     *
     * @param callable(): ?User $user
     */
    #[Test]
    #[DataProvider('provideUsersRefusedLikeAWrongPassword')]
    public function anUnknownADisabledOrAPasswordlessUserIsRefusedLikeAWrongPassword(
        string $username,
        callable $user,
        AuthenticationFailureReason $reason,
    ): void {
        // Given
        $user();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, $username, self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf($username));
        static::assertSame('authentication_failed', $this->loginPage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Decision 0006
     *
     * @param callable(): ?User $user
     */
    #[Test]
    #[DataProvider('provideUsersRefusedLikeAWrongPassword')]
    public function theAuditTrailTellsTheReasonOfARefusedLogin(string $username, callable $user, AuthenticationFailureReason $reason): void
    {
        // Given
        $refused = $user();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, $username, self::PASSWORD);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame($reason, $failures[0]->reason);
        static::assertSame($username, $failures[0]->identifier);
        if ($refused === null) {
            static::assertNull($failures[0]->user);
        } else {
            static::assertTrue($failures[0]->user?->id->equals($refused->id));
        }
    }

    /**
     * @return iterable<string, array{string, callable(): ?User, AuthenticationFailureReason}>
     */
    public static function provideUsersRefusedLikeAWrongPassword(): iterable
    {
        yield 'unknown' => [
            'nobody',
            static fn (): ?User => null,
            AuthenticationFailureReason::UnknownUser,
        ];
        yield 'disabled' => [
            'bob',
            static function (): User {
                $disabled = self::userWithPassword('bob', self::PASSWORD);
                $disabled->disable(self::now());
                self::service('test.beffroi.users', UserRepositoryInterface::class)->save($disabled);

                return $disabled;
            },
            AuthenticationFailureReason::DisabledUser,
        ];
        yield 'without a password' => [
            'carol',
            static fn (): User => self::user('carol', 'carol-subject'),
            AuthenticationFailureReason::NoSuchCredential,
        ];
    }

    /**
     * Decision 0006, Architecture §3.4
     */
    #[Test]
    public function theSixthAttemptInAMinuteOpensNoSessionWhateverThePassword(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.4
     */
    #[Test]
    public function aRefusedAttemptIsRecordedWithItsReason(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }
        self::forgetEvents();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, $failures[0]->reason);
        static::assertSame('alice', $failures[0]->identifier);
        static::assertTrue($failures[0]->user?->id->equals($user->id));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aRefusedAttemptIsShownLikeAnyOtherFailure(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('authentication_failed', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function theAttemptsOnOneUserDoNotCountForAnother(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $bob = self::userWithPassword('bob', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }

        // When
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        // Then
        static::assertTrue($this->boundSession()->user->id->equals($bob->id));
    }

    /**
     * Architecture §3.4
     */
    #[Test]
    public function aSuccessfulLoginEmptiesTheCountOfTheUser(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }
        self::forgetEvents();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertCount(1, self::sessionsOf('alice'));
    }

    #[Test]
    public function aFormWithoutItsTokenIsRefused(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->loginPage($interaction);

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, 'not-the-token');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertSame('authentication_failed', $this->loginPage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function aFormWithoutItsTokenRecordsNothing(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->loginPage($interaction);

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, 'not-the-token');

        // Then
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    #[Test]
    public function aLoginPostedWithoutOriginOrRefererOpensASession(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;

        // When
        $this->postedWithoutOriginOrReferer($form);

        // Then
        static::assertTrue($this->boundSession()->user->id->equals($alice->id));
    }

    /**
     * Architecture §3.4
     */
    #[Test]
    public function aHashWeakerThanThePolicyIsRehashedOnLogin(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD, new Bcrypt());
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $credential = $this->credentialOf($user);
        static::assertSame(Argon2id::NAME, $credential->hash->algorithm->name());
        static::assertNotNull($credential->lastUsedAt);
    }

    /**
     * Architecture §3.4
     */
    #[Test]
    public function aRehashOnLoginIsAnnounced(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD, new Bcrypt());
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $rehashes = self::events(PasswordRehashed::class);
        static::assertCount(1, $rehashes);
        static::assertTrue($rehashes[0]->credential->id->equals($this->credentialOf($user)->id));
        static::assertSame('127.0.0.1', $rehashes[0]->context->ipAddress);
    }

    /**
     * RFC 8018 §5.2, Decision 0002
     */
    #[Test]
    #[DataProvider('providePbkdf2Algorithms')]
    public function aPbkdf2HashAnImportBroughtOpensTheSessionAndIsRehashed(PasswordAlgorithmInterface $algorithm): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD, $algorithm);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        static::assertSame(Argon2id::NAME, $this->credentialOf($user)->hash->algorithm->name());
    }

    /**
     * @return iterable<string, array{PasswordAlgorithmInterface}>
     */
    public static function providePbkdf2Algorithms(): iterable
    {
        yield 'pbkdf2-sha256' => [new Pbkdf2Sha256()];

        yield 'pbkdf2-sha512' => [new Pbkdf2Sha512()];
    }

    /**
     * RFC 8018 §5.2, Decision 0006
     */
    #[Test]
    public function aWrongPasswordAgainstAPbkdf2HashGoesBackToTheLoginPage(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD, new Pbkdf2Sha256());
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    #[Test]
    public function theRehashedPasswordOpensTheSessionNextTime(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD, new Bcrypt());
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $this->browser->getCookieJar()->clear();
        self::forgetEvents();

        // When
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // Then
        static::assertCount(2, self::sessionsOf('alice'));
        static::assertSame([], self::events(PasswordRehashed::class));
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function theLoginPageSaysWhenAFreshLoginIsAsked(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('reauthentication_requested', $crawler->filter('p[data-requirement]')->attr('data-requirement'));
    }

    /**
     * OIDC Core §3.1.2.1, Architecture §3.2
     */
    #[Test]
    public function aFreshLoginAskedByTheClientRecordsAProofOnTheExistingSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $first = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        self::forgetEvents();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $session = $this->boundSession();
        static::assertTrue($session->id->equals($first->id));
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertGreaterThanOrEqual($first->authenticatedAt(), $session->authenticatedAt());
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
    }

    #[Test]
    public function aFreshLoginMovesTheAuthTimeOfTheToken(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame(
            [
                'pwd' => $this->boundSession()->authenticatedAt()->getTimestamp(),
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    #[Test]
    public function theInteractionGoesOnAfterAFreshLogin(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §3.2
     */
    #[Test]
    public function anotherUserSigningInOnABoundBrowserOpensTheirOwnSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::userWithPassword('bob', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $alice = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        self::forgetEvents();

        // When
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        // Then
        $bob = $this->boundSession();
        static::assertTrue($bob->user->id->equals(self::sessionsOf('bob')[0]->user->id));
        static::assertFalse($bob->id->equals($alice->id));
        static::assertCount(1, self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.2
     */
    #[Test]
    public function anotherUserSigningInOnABoundBrowserEndsTheSessionOfTheFirst(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::userWithPassword('bob', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $alice = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        // Then
        $ended = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($alice->id) ?? static::fail('The session of alice is gone.');
        static::assertTrue($ended->hasEnded());
        static::assertSame(SessionEnd::User, $ended->endedBy);
        $endings = self::events(AuthenticationSessionEnded::class);
        static::assertCount(1, $endings);
        static::assertTrue($endings[0]->session->id->equals($alice->id));
    }

    /**
     * OIDC Core §3.1.2.1, §3.1.2.6
     */
    #[Test]
    public function aLoginAsAnotherPersonThanTheIdTokenHintNamesIsAnsweredLoginRequired(): void
    {
        // Given
        self::signingKey();
        self::userWithPassword('alice', self::PASSWORD);
        $this->signIn(self::userWithPassword('bob', self::PASSWORD));
        $this->signInClient('native-app', 'http://127.0.0.1/callback', null);
        $hint = self::string(self::json($this->browser->getResponse())['id_token'] ?? null);
        $this->browser->getCookieJar()->clear();
        $interaction = $this->authorize([
            'id_token_hint' => $hint,
        ]);
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    #[DataProvider('provideProtocolRequests')]
    public function theProtocolPlaneStartsNoSession(string $method, string $path): void
    {
        // When
        $this->browser->request($method, $path);

        // Then
        static::assertFalse($this->browser->getResponse()->headers->has('Set-Cookie'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideProtocolRequests(): iterable
    {
        yield 'discovery' => ['GET', '/.well-known/openid-configuration'];
        yield 'authorization server metadata' => ['GET', '/.well-known/oauth-authorization-server'];
        yield 'jwks' => ['GET', '/jwks'];
        yield 'token' => ['POST', '/token'];
        yield 'userinfo' => ['GET', '/userinfo'];
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return string the identifier of the interaction
     */
    private function authorize(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters(parameters: $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));

        return $interaction;
    }

    private function loginPage(string $interaction): Crawler
    {
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    private function csrfTokenOfTheLoginPage(string $interaction): string
    {
        $token = $this->loginPage($interaction)->filter('input[name="_csrf_token"]')->attr('value');
        static::assertIsString($token);

        return $token;
    }

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    private function postLogin(string $interaction, string $username, string $password, string $token): void
    {
        $this->browser->request('POST', '/login?interaction=' . $interaction, [
            '_username' => $username,
            '_password' => $password,
            '_csrf_token' => $token,
        ]);
    }

    private function credentialOf(User $user): PasswordCredential
    {
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');

        return (
            self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
                ->findByUser($managed, PasswordCredential::class)[0] ?? static::fail('The credential is gone.')
        );
    }

    private function boundSession(): AuthenticationSession
    {
        $id = $this->readHttpSession()->get(BrowserSession::AUTHENTICATION_SESSION_KEY);
        static::assertIsString($id, 'The browser is bound to no session.');
        self::reload();

        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString($id)) ?? static::fail('The bound session is gone.')
        );
    }

    private function securityToken(): TokenInterface
    {
        $serialized = $this->readHttpSession()->get('_security_beffroi_interaction');
        static::assertIsString($serialized, 'The firewall stored no token.');
        $token = unserialize($serialized);
        static::assertInstanceOf(TokenInterface::class, $token);

        return $token;
    }

    /**
     * @return list<AuthenticationSession> the active ones
     */
    private static function sessionsOf(string $username): array
    {
        self::reload();
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), $username);
        if (! $user instanceof User) {
            return [];
        }

        return self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->findActiveByUser($user, new DateTimeImmutable());
    }
}
