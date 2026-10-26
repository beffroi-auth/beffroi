<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function array_map;
use function base64_encode;
use DateTimeImmutable;
use Beffroi\Bundle\Http\PendingLoginStore;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\BackupCodeUsed;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\TotpUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use function intdiv;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The acceptance of issue #91 on the login (architecture §3.2, §5.4): a user who enrolled a TOTP is
 * asked for a code after a good password and not after a bad one, no session exists before the code, a
 * good code establishes the session with both factors and the ID token says so, a backup code works
 * once, the attempts are limited, and an authorization request received between the two steps gets no
 * code. With the acceptance of issue #133 on what the page says of a refusal: the message names the
 * shape that was typed, the same for a code that never existed as for one that is spent, and never the
 * reason. The firewall is the one of tests/symfony/config/config_test.yml.
 */
final class LoginCodeTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * What the page says of a refused backup code, whatever became of the one that was typed (#133).
     */
    private const string BACKUP_CODE_REFUSED = 'This backup code is not valid, or it has already been used. Each backup code works only once.';

    private TotpSecret $secret;

    protected function setUp(): void
    {
        parent::setUp();
        $this->secret = Totps::secret();
    }

    #[Test]
    public function aUserWithoutATotpSignsInWithThePasswordAlone(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['pwd'], $this->boundSession()->methodReferences());
    }

    /**
     * Architecture §5.4: the password of a user who holds a second factor is held, the browser sent to
     * the code page.
     */
    #[Test]
    public function aUserWithATotpIsAskedForACodeAfterAGoodPassword(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);
        static::assertSame('/login/code?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Decision 0006 and architecture §3.2: between the password and the code there is no session of the
     * core, no token of the firewall, and no login announced; what the browser holds is the pending
     * login, and nothing else.
     */
    #[Test]
    public function nothingIsOpenedBeforeTheCode(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $httpSession = $this->readHttpSession();
        static::assertFalse($this->isBoundToASession());
        static::assertFalse($httpSession->has('_security_beffroi_interaction'), 'The firewall kept a token of the first step.');
        $pending = $httpSession->get(PendingLoginStore::KEY);
        static::assertInstanceOf(PendingLogin::class, $pending);
        static::assertTrue($pending->userId->equals($alice->id));
        static::assertSame(['pwd'], array_map(static fn ($method): string => (string) $method, $pending->methods));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    #[Test]
    public function aWrongPasswordAsksForNoCode(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(PendingLoginStore::KEY));
    }

    #[Test]
    public function theCodePageShowsItsFormToTheBrowserThatTypedThePassword(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $crawler = $this->codePage($interaction);

        // Then
        $response = $this->browser->getResponse();
        self::assertInteractionHeaders($response);
        $form = $crawler->filter('form[data-login="code"]');
        static::assertSame('/login/code?interaction=' . $interaction, $form->attr('action'));
        static::assertCount(1, $form->filter('input[name="_code"]'));
        static::assertCount(1, $form->filter('input[name="_csrf_token"]'));
        static::assertCount(0, $crawler->filter('input[name="_password"]'));
        static::assertCount(0, $crawler->filter('p[data-error]'));
    }

    #[Test]
    public function theCodePageWithoutAPendingLoginGoesBackToTheLoginPage(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §4.3: the code page belongs to the interaction like the login page.
     */
    #[Test]
    public function anotherBrowserCannotSeeTheCodePageOfAnInteraction(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->forgetTheBrowser();

        // When
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Architecture §3.2 and §5.4: the session is established once the code passes, with both factors,
     * "mfa" derived (RFC 8176 §2), the browser bound to it and sent to the login page, which resumes.
     */
    #[Test]
    public function aGoodCodeEstablishesTheSessionWithBothFactors(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        $session = $this->boundSession();
        static::assertTrue($session->user->id->equals($alice->id));
        static::assertSame(['pwd', 'otp', 'mfa'], $session->methodReferences());
        static::assertSame('2', $session->authenticationContextClass()->value);
        static::assertCount(1, self::sessionsOf('alice'));
        static::assertFalse($this->readHttpSession()->has(PendingLoginStore::KEY), 'The pending login was not forgotten.');
    }

    /**
     * The token of the firewall says both, the proofs copied from the session (symfony/symfony#66064).
     */
    #[Test]
    public function theTokenOfTheFirewallCarriesBothProofs(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $authTime = $this->boundSession()->authenticatedAt()->getTimestamp();
        static::assertSame(
            [
                'pwd' => $authTime,
                'otp' => $authTime,
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    /**
     * Architecture §3.4, §3.5: the core is told of the password, of the code and of the session, once
     * each; the password and the TOTP are dated.
     */
    #[Test]
    public function aGoodCodeIsAnnouncedAndDatesBothCredentials(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertCount(1, self::events(TotpUsed::class));
        static::assertCount(0, self::events(BackupCodeUsed::class));
        static::assertCount(1, self::events(PasswordUsed::class));
        static::assertCount(1, self::events(UserAuthenticated::class));
        static::assertNotNull(self::credentialOf($alice, PasswordCredential::class)->lastUsedAt);
        static::assertNotNull(self::credentialOf($alice, TotpCredential::class)->lastUsedAt);
    }

    /**
     * The acceptance of the issue on the token endpoint: the ID token carries both methods and "acr" "2".
     */
    #[Test]
    public function theIdTokenCarriesBothFactorsAndTheTwoFactorClass(): void
    {
        // Given
        self::signingKey();
        $this->userWithTotp('alice', self::PASSWORD);
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('2', $claims['acr']);
        static::assertSame(['pwd', 'otp', 'mfa'], $claims['amr']);
    }

    #[Test]
    public function aBackupCodeEstablishesTheSession(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);

        // Then
        static::assertSame(['pwd', 'otp', 'mfa'], $this->boundSession()->methodReferences());
        static::assertCount(1, self::events(BackupCodeUsed::class));
        static::assertCount(0, self::events(TotpUsed::class));
    }

    /**
     * A backup code is spent by its first use.
     */
    #[Test]
    public function aBackupCodeWorksOnce(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame(AuthenticationFailureReason::InvalidCredential, self::events(AuthenticationFailed::class)[0]->reason ?? null);
    }

    /**
     * Decision 0006: a refused code sends the browser back to the code page with one message, the
     * pending login kept for another try.
     */
    #[Test]
    public function aWrongCodeGoesBackToTheCodePage(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, '000000');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login/code?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame('code_refused', $this->codePage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Architecture §3.4: the refusal is announced by the core with its reason; the firewall adds nothing.
     */
    #[Test]
    public function aWrongCodeIsAnnouncedOnceWithItsReason(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, '000000');

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('otp', (string) $failures[0]->method);
        static::assertTrue($failures[0]->user?->id->equals($alice->id));
    }

    /**
     * Issue #133: six digits refused are the code of an app, and what the page says is the way out that
     * shape has, the code the app shows now.
     */
    #[Test]
    public function aRefusedAppCodeSaysToTryTheCodeTheAppShowsNow(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, '000000');

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('code_refused', $refusal->attr('data-error'));
        static::assertSame('The code was refused. Try again with the code the app shows now.', $refusal->text());
    }

    /**
     * Issue #133, the defect the run by hand of 2026-09-20 found: a user who spent a backup code was
     * told to try the code their app shows now, which is not what they typed and not what would work
     * next. The page names the shape instead, and the single use of a backup code, which is a fact of
     * the feature printed with the codes at enrolment and not a fact about this account.
     */
    #[Test]
    public function aRefusedBackupCodeSaysEachBackupCodeServesOnce(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('backup_code_refused', $refusal->attr('data-error'));
        static::assertSame(self::BACKUP_CODE_REFUSED, $refusal->text());
    }

    /**
     * Issue #133 and decision 0006: the message names what was typed and never what the account holds;
     * a backup code that was never one of the user's is refused exactly as a spent one is.
     */
    #[Test]
    public function aBackupCodeThatNeverExistedIsRefusedLikeASpentOne(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, 'ZZZZZ-ZZZZZ');

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('backup_code_refused', $refusal->attr('data-error'));
        static::assertSame(self::BACKUP_CODE_REFUSED, $refusal->text());
    }

    /**
     * Decision 0006, architecture §5.4: five attempts a minute, the sixth refused whatever the code.
     */
    #[Test]
    public function theSixthWrongCodeInAMinuteIsRefusedEvenWhenRight(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitCode($interaction, '000000');
        }
        self::forgetEvents();

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, self::events(AuthenticationFailed::class)[0]->reason ?? null);
    }

    /**
     * Issue #133: past the limit, trying again is precisely what does not help, so the page says to wait
     * rather than to type the code the app shows now. The limit is a fact of the request and not of the
     * account: the page may name it without saying anything of the credential.
     */
    #[Test]
    public function theCodeRefusedByTheLimitSaysToWait(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitCode($interaction, '000000');
        }

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('too_many_attempts', $refusal->attr('data-error'));
        static::assertSame('Too many codes have been tried. Wait a moment, then try again.', $refusal->text());
    }

    /**
     * The acceptance of the issue: an authorization request received between the password and the code
     * finds no session and asks for a login; the login page shows the password form, not a code.
     */
    #[Test]
    public function anAuthorizationRequestBetweenThePasswordAndTheCodeGetsNoCode(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertCount(1, $this->loginPage($interaction)->filter('input[name="_password"]'));
    }

    /**
     * A code posted without the password before it, by a browser holding nothing, is not a login.
     */
    #[Test]
    public function aCodePostedWithoutAPendingLoginOpensNothing(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->browser->request('POST', '/login/code?interaction=' . $interaction, [
            '_code' => $this->codeAt(new DateTimeImmutable()),
            '_csrf_token' => 'whatever',
        ]);

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(AuthenticationFailed::class), 'Nothing was tried on an account.');
    }

    /**
     * Architecture §5.4: a pending login expires; past it, the password is typed again. The refusal is the
     * one the core pronounces on its own path, announced here too (issue #130): a tenant reading its audit
     * trail sees the login that was too late, whichever path served it.
     */
    #[Test]
    public function anExpiredPendingLoginIsRefusedAndAsksForThePasswordAgain(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->holdExpiredLogin($alice);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()), fromThePage: false);

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        $refused = self::events(AuthenticationFailed::class);
        static::assertCount(1, $refused);
        static::assertSame(AuthenticationFailureReason::ExpiredLogin, $refused[0]->reason);
        static::assertSame('alice', $refused[0]->identifier);
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * OIDC Core §3.1.2.1 (prompt=login), architecture §3.2: a fresh login asked of a user who holds a
     * TOTP goes through the code again, and records both proofs on the session the browser has. The
     * first code spent its step (RFC 6238 §5.2); the second is the one of the next step, which the drift
     * of one step accepts now rather than in thirty seconds. Both logins are played on the clock of the test, the first
     * at a second it pins and the second a second later, so that the proofs they date never depend on the wall clock
     * of the machine, which a runner may step back between two readings.
     */
    #[Test]
    public function aFreshLoginOfATotpUserGoesThroughTheCodeAgain(): void
    {
        // Given
        self::mockTime(self::currentSecond());
        $this->userWithTotp('alice', self::PASSWORD);
        $first = $this->authorize();
        $this->submitLogin($first, 'alice', self::PASSWORD);
        $this->submitCode($first, $this->codeAt(Clock::get()->now()));
        $session = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        self::forgetEvents();

        // When
        $this->submitCode($interaction, $this->codeAt(Clock::get()->now()->modify(sprintf('+%d seconds', TotpCredential::PERIOD))));

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $refreshed = $this->boundSession();
        static::assertTrue($refreshed->id->equals($session->id));
        static::assertGreaterThan($session->authenticatedAt(), $refreshed->authenticatedAt());
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
    }

    /**
     * A passkey is a first factor by itself (architecture §3.2): a user who holds a TOTP signs in with
     * a passkey without any code.
     */
    #[Test]
    public function aPasskeyLoginOfATotpUserAsksForNoCode(): void
    {
        // Given
        $device = self::device();
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['hwk', 'user'], $this->boundSession()->methodReferences());
    }

    /**
     * The acceptance of issue #92 (decision 0010, architecture §4.3): the login page of a step-up to the
     * two-factor class, for a password session of a user who holds a TOTP, names the code after the
     * password, which a password alone would not satisfy, and no passkey the user does not hold.
     */
    #[Test]
    public function theStepUpToTwoFactorsNamesTheCodeOfTheUserWhoHoldsATotp(): void
    {
        // Given
        $this->signIn($this->userWithTotp('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize([
            'acr_values' => '2',
        ]);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('2', $crawler->filter('p[data-requirement]')->attr('data-acr'));
        static::assertCount(1, $crawler->filter('p[data-step-up="totp"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="password"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="passkey"]'));
    }

    /**
     * A user with a password and a TOTP enrolled an hour ago on the secret of RFC 6238; the backup codes
     * are hashed by the hasher of the kernel only when a test spends one, the others being content with a
     * hash that verifies nothing.
     */
    private function userWithTotp(string $username, string $password, bool $hashedBackupCodes = false): User
    {
        $user = self::userWithPassword($username, $password);
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $this->secret->bytes);
        $hasher = $hashedBackupCodes ? self::service('test.beffroi.password_hasher', PasswordHasherInterface::class) : new FakePasswordHasher();
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new TotpCredential(
                    Uuid::v7(),
                    $user,
                    $sealed,
                    Totps::credential($user, $hasher)->backupCodes,
                    intdiv($anHourAgo->getTimestamp(), TotpCredential::PERIOD),
                    $anHourAgo,
                ),
            );

        return $user;
    }

    private function codeAt(DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($this->secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    private function codePage(string $interaction): Crawler
    {
        $crawler = $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * The one message the code page shows of a refusal, read from the page the browser was sent back to.
     */
    private function refusalShown(string $interaction): Crawler
    {
        $refusals = $this->codePage($interaction)->filter('p[data-error]');
        static::assertCount(1, $refusals);

        return $refusals;
    }

    /**
     * Fills and posts the form of the code page, as a user does; or posts without the page, with a
     * token the page would have given, when there is no page to read.
     */
    private function submitCode(string $interaction, string $code, bool $fromThePage = true): void
    {
        if (! $fromThePage) {
            $token = $this->loginPage($interaction)->filter('input[name="_csrf_token"]')->attr('value');
            $this->browser->request('POST', '/login/code?interaction=' . $interaction, [
                '_code' => $code,
                '_csrf_token' => $token,
            ]);

            return;
        }
        $form = $this->codePage($interaction)->selectButton('Continue')->form();
        $form['_code'] = $code;
        $this->browser->submit($form);
    }

    /**
     * A pending login of the user, expired, written in the HTTP session the browser holds.
     */
    private function holdExpiredLogin(User $user): void
    {
        $this->httpSession(static function (SessionInterface $httpSession) use ($user): void {
            $provenAt = new DateTimeImmutable('-1 hour');
            new PendingLoginStore()->hold(
                $httpSession,
                new PendingLogin($user->id, [AuthenticationMethod::password()], $provenAt, $provenAt->modify('+5 minutes')),
            );
        });
    }

    /**
     * @template T of Credential
     *
     * @param class-string<T> $kind
     *
     * @return T
     */
    private static function credentialOf(User $user, string $kind): object
    {
        self::reload();
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');

        return (
            self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
                ->findByUser($managed, $kind)[0] ?? static::fail('The credential is gone.')
        );
    }
}
