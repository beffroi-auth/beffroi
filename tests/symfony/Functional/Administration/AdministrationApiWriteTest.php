<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use App\Tests\Symfony\Functional\Controller\TokensOfASession;
use function array_map;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: what the administration API of a tenant changes for an administrator, on the use cases of the commands
 * of the console, and the act of the person each change is, which names the administrator who made it.
 */
final class AdministrationApiWriteTest extends AdministrationTestCase
{
    use TokensOfASession;

    #[Test]
    public function anAdministratorEndsAnOpenSessionOfAPerson(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_OK, SessionEnd::Administrator], [$response->getStatusCode(), self::sessionAgain($session)->endedBy]);
    }

    /**
     * Back-Channel Logout 1.0 §2.5
     */
    #[Test]
    public function theRelyingPartiesOfASessionAnAdministratorEndedAreTold(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame(['oidc-demo'], array_map(
            static fn (JournalEntry $entry): ?string => $entry->client,
            self::entityManager()->getRepository(JournalEntry::class)->findBy(['act' => LogoutTokenIssued::NAME]),
        ));
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theLogoutTokenOfASessionAnAdministratorEndedIsAnActThatNamesThem(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(LogoutTokenIssued::NAME));
    }

    #[Test]
    public function theEndOfASessionIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(AuthenticationSessionEnded::NAME));
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theTokensOfASessionAnAdministratorEndedAreAnActOfThePersonThatNamesThem(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        self::tokensIssuedIn($session);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(SessionTokensRevoked::NAME));
    }

    /**
     * Decision 0031
     */
    #[Test]
    public function anAdministratorEndsASessionPastItsExpiryThatHasNotEnded(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob, self::currentSecond()->modify('-13 hours'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_OK, SessionEnd::Administrator], [$response->getStatusCode(), self::sessionAgain($session)->endedBy]);
    }

    #[Test]
    public function aSessionThatEndedIsNotEndedAgain(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob);
        $token = $this->administratorToken(self::user('alice'));
        $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // When
        $response = $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, 'not_found', 1],
            [$response->getStatusCode(), self::json($response)['error'] ?? null, count(self::authored(AuthenticationSessionEnded::NAME))],
        );
    }

    #[Test]
    public function aSessionOfAnotherPersonIsNotEnded(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn(self::user('carol', 'carol-subject'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::sessionPath($bob, $session), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, null], [$response->getStatusCode(), self::sessionAgain($session)->endedAt]);
    }

    #[Test]
    public function anAdministratorRevokesAPasskeyOfAPerson(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $device = self::device();
        $passkey = $this->enrol($bob, $device);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_OK, true], [$response->getStatusCode(), self::passkeyOf($bob, $device)->isRevoked()]);
    }

    #[Test]
    public function theRevocationOfACredentialIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $passkey = $this->enrol($bob, self::device());
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(CredentialRevoked::NAME));
    }

    /**
     * A credential revoked already keeps the moment it was revoked, and its revocation is written once.
     */
    #[Test]
    public function aCredentialRevokedAlreadyIsLeftAsItIs(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $passkey = $this->enrol($bob, self::device());
        $token = $this->administratorToken(self::user('alice'));
        $first = self::json($this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE'));
        self::aSecondLater();

        // When
        $again = $this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE');

        // Then
        static::assertSame(
            [Response::HTTP_OK, $first['revoked_at'] ?? null, 1],
            [$again->getStatusCode(), self::json($again)['revoked_at'] ?? null, count(self::authored(CredentialRevoked::NAME))],
        );
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function answeringACredentialRevokedAlreadyIsAReadOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $passkey = $this->enrol($bob, self::device());
        $token = $this->administratorToken(self::user('alice'));
        $this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE');

        // When
        $this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(PersonReadByAnAdministrator::NAME));
    }

    #[Test]
    public function aPasswordIsNotRevoked(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $password = new PasswordCredential(Uuid::v7(), $bob, new PasswordHash(new Argon2id(), '$argon2id$bob'), self::now());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($password);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::credentialPath($bob, $password->id), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, []], [$response->getStatusCode(), self::authored(CredentialRevoked::NAME)]);
    }

    #[Test]
    public function aCredentialOfAnotherPersonIsNotRevoked(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $carol = self::user('carol', 'carol-subject');
        $device = self::device();
        $passkey = $this->enrol($carol, $device);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::credentialPath($bob, $passkey->id), $token, method: 'DELETE');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, false], [$response->getStatusCode(), self::passkeyOf($carol, $device)->isRevoked()]);
    }

    private static function sessionPath(User $person, AuthenticationSession $session): string
    {
        return sprintf('/users/%s/sessions/%s', $person->id->toRfc4122(), $session->id->toRfc4122());
    }

    private static function credentialPath(User $person, Uuid $credential): string
    {
        return sprintf('/users/%s/credentials/%s', $person->id->toRfc4122(), $credential->toRfc4122());
    }
}
