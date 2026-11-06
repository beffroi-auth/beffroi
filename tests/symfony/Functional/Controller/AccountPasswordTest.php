<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use DateInterval;
use App\Http\RecentLogin;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use function json_decode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §5.2
 */
final class AccountPasswordTest extends BrowserTestCase
{
    use TokensOfASession;

    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    private const string BREACHED = 'monkey business as usual';

    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $this->browser->request('GET', '/account/password');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function thePageSaysWhenThePasswordWasLastWritten(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password] time'));
        static::assertCount(1, $page->filter('form[data-password="change"]'));
    }

    #[Test]
    public function thePasswordPosedIsTheOneHeldAfterwards(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::POSED));
        static::assertCount(1, self::events(PasswordChanged::class));
    }

    #[Test]
    public function replacingThePasswordSignsEveryOtherBrowserOut(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $current = $this->signIn($alice);
        $elsewhere = self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertTrue(self::reread($elsewhere)->hasEnded());
        static::assertFalse(self::reread($current)->hasEnded());
    }

    /**
     * Decision 0031
     */
    #[Test]
    public function replacingThePasswordRevokesTheTokensOfASessionPastItsExpiry(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        $expired = self::session($alice, self::currentSecond()->modify('-13 hours'));
        $tokens = self::tokensIssuedIn($expired);

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        self::assertTheTokensAreRevoked($tokens);
    }

    #[Test]
    public function aPasswordInUseThatWasNotTypedIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->change('not the password', self::POSED);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="wrong_password"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    #[Test]
    public function aPasswordPosedThatIsTheOneHeldIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $this->change(self::IN_USE, self::IN_USE);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="same_as_before"]'));
    }

    #[Test]
    #[DataProvider('providePasswordsThatAreNoPassword')]
    public function aPasswordPosedThatIsNoPasswordIsRefusedAndSaidOnThePage(string $posed, string $error): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $this->change(self::IN_USE, $posed);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="' . $error . '"]'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providePasswordsThatAreNoPassword(): iterable
    {
        yield 'shorter than the fifteen characters the floor asks' => ['short', 'too_short'];
        yield 'a word written twice' => ['passwordpassword', 'too_weak'];
    }

    #[Test]
    public function aPasswordPosedTwiceAndTypedDifferentlyIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->change(self::IN_USE, self::POSED, self::POSED . '!');

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="not_confirmed"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    /**
     * NIST SP 800-63B §3.1.1.2
     */
    #[Test]
    public function aPasswordAListCountsIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        self::breaches()->names([self::BREACHED]);

        // When
        $this->change(self::IN_USE, self::BREACHED);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="breached"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aPasswordNoListCouldBeAskedAboutIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        self::breaches()->cannotBeReached();

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="not_checked"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    #[Test]
    public function aDeploymentThatNamesNoListPosesThePasswordAllTheSame(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        self::breaches()->namesNothing();

        // When
        $this->change(self::IN_USE, self::BREACHED);

        // Then
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::BREACHED));
        static::assertSame([], self::breaches()->asked);
    }

    #[Test]
    public function aSessionThatProvedNothingRecentlyIsSentToTheLogin(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE), self::currentSecond()->modify('-1 hour'));

        // When
        $this->browser->request('GET', '/account/password');

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertStringEndsWith('/login', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    #[Test]
    public function aPasswordPostedOnASessionThatProvedNothingRecentlyIsNotWritten(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        $token = $this->token();
        self::mockTime(self::currentSecond()->add(new DateInterval(RecentLogin::WITHIN))->modify('+1 second'));

        // When
        $this->browser->request('POST', '/account/password', [
            '_token' => $token,
            'current_password' => self::IN_USE,
            'new_password' => self::POSED,
            'new_password_again' => self::POSED,
        ]);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    #[Test]
    public function aPasswordFoundInABreachIsSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        $credential = self::passwordOf($alice);
        $credential->foundInABreach(self::currentSecond());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password-breached]'));
    }

    #[Test]
    public function aPersonWhoHoldsNoPasswordIsOfferedNoForm(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password="none"]'));
        static::assertCount(0, $page->filter('form[data-password="change"]'));
    }

    #[Test]
    public function changingThePasswordWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->browser->request('POST', '/account/password', [
            'current_password' => self::IN_USE,
            'new_password' => self::POSED,
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    #[Test]
    public function thePageHandsTheMeterItsWordsAndItsFloor(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $page = $this->passwordPage();

        // Then
        $field = $page->filter('input[data-password-strength]');
        static::assertCount(1, $field);
        static::assertSame('password-strength', $field->attr('data-password-strength'));
        static::assertSame((string) PlainPassword::MINIMUM_STRENGTH, $field->attr('data-strength-floor'));
        static::assertCount(5, (array) json_decode(self::string($field->attr('data-strength-labels')), true));
        static::assertCount(1, $page->filter('p#password-strength[data-strength-meter]'));
    }

    /**
     * NIST SP 800-63B §3.1.1.2, Architecture §9
     */
    #[Test]
    #[DataProvider('provideFloorsAndTheLengthTheyAsk')]
    public function theFormDeclaresTheLengthTheFloorOfTheTenantAsks(AuthenticationPredicateInterface $floor, string $minimum): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        self::harden($floor);
        self::reload();
        $this->signIn($alice);

        // When
        $page = $this->passwordPage();

        // Then
        static::assertSame($minimum, $page->filter('input#password-new')->attr('minlength'));
    }

    /**
     * @return iterable<string, array{AuthenticationPredicateInterface, string}>
     */
    public static function provideFloorsAndTheLengthTheyAsk(): iterable
    {
        yield 'a password that signs somebody in alone' => [new SingleFactor(), '15'];
        yield 'a password a second factor is read beside' => [new TwoFactors(), '12'];
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function theScriptOfTheMeterIsServedByTheProvider(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));
        static::assertSame('/password-strength.js', $this->passwordPage()->filter('script')->attr('src'));

        // When
        $this->browser->request('GET', '/password-strength.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
        static::assertStringNotContainsString('fetch(', self::string($this->browser->getInternalResponse()->getContent()));
    }

    private function passwordPage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/password');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        return $page;
    }

    private function change(string $inUse, string $posed, ?string $again = null): void
    {
        $this->browser->request('POST', '/account/password', [
            '_token' => $this->token(),
            'current_password' => $inUse,
            'new_password' => $posed,
            'new_password_again' => $again ?? $posed,
        ]);
    }

    private static function breaches(): BreachedPasswordsOfARecord
    {
        return self::service('test.beffroi.breached_passwords', BreachedPasswordsOfARecord::class);
    }

    private function token(): string
    {
        return self::string($this->passwordPage()->filter('form[data-password="change"] input[name="_token"]')->attr('value'));
    }

    private static function hasher(): PasswordHasherInterface
    {
        return self::service('test.beffroi.password_hasher', PasswordHasherInterface::class);
    }

    private static function passwordOf(User $user): PasswordCredential
    {
        self::reload();
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $password = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($reread, PasswordCredential::class)[0] ?? null;
        static::assertInstanceOf(PasswordCredential::class, $password);

        return $password;
    }

    private static function reread(AuthenticationSession $session): AuthenticationSession
    {
        $reread = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $reread);

        return $reread;
    }
}
