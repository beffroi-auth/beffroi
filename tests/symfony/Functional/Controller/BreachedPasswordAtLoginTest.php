<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use DateInterval;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use Symfony\Component\HttpFoundation\Response;

final class BreachedPasswordAtLoginTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Test]
    public function aPasswordAListCountsIsMarkedAsFoundAfterTheLoginThatUsedIt(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertTrue(self::passwordOf($alice)->isBreached());
    }

    /**
     * RFC 8265 §8.2
     */
    #[Test]
    public function aPasswordTypedInAnotherFormIsLookedUpInTheFormThatIsHashed(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', "correct\u{00A0}horse battery staple");

        // Then
        static::assertTrue(self::passwordOf($alice)->isBreached());
    }

    #[Test]
    public function aPasswordNoListHoldsIsMarkedAsLookedUpAndNotAsFound(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names(['a password of somebody else']);

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertFalse(self::passwordOf($alice)->isBreached());
        static::assertNotNull(self::passwordOf($alice)->breachCheckedAt);
    }

    #[Test]
    public function aPasswordThatDidNotVerifyIsAskedAboutNobody(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', 'not the password of anybody');

        // Then
        static::assertSame([], self::breaches()->asked);
    }

    #[Test]
    #[TestWith(['+1 second', false], 'a second short of the delay')]
    #[TestWith(['-1 day', true], 'a day past the delay')]
    public function aLoginAsksOnlyWhenTheCredentialIsDue(string $modification, bool $asked): void
    {
        // Given
        self::mockTime(self::currentSecond());
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $credential = self::passwordOf($alice);
        $credential->notFoundInABreach(
            self::currentSecond()->sub(new DateInterval(PasswordCredential::LOOKUP_AGAIN_AFTER))->modify($modification),
        );
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertSame($asked, self::breaches()->asked !== []);
    }

    #[Test]
    public function aDeploymentThatNamesNoListSignsThePersonInAndAsksNobody(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->namesNothing();

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertSame([], self::breaches()->asked);
        static::assertNull(self::passwordOf($alice)->breachCheckedAt);
    }

    #[Test]
    public function theListOfTheSuiteNamesNothingUntilATestNamesOne(): void
    {
        // When / Then
        static::assertFalse(self::breaches()->looksUp());
    }

    private function signInOnTheForm(string $username, string $password): void
    {
        $this->browser->request('GET', '/account');
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        $this->browser->submit(
            $this->browser
                ->followRedirect()
                ->selectButton('Sign in')
                ->form([
                    '_username' => $username,
                    '_password' => $password,
                ]),
        );
    }

    private static function breaches(): BreachedPasswordsOfARecord
    {
        return self::service('test.beffroi.breached_passwords', BreachedPasswordsOfARecord::class);
    }

    private static function passwordOf(User $user): PasswordCredential
    {
        self::reload();
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $password = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($reread, PasswordCredential::class)[0] ?? null;
        static::assertInstanceOf(PasswordCredential::class, $password);

        return $password;
    }
}
