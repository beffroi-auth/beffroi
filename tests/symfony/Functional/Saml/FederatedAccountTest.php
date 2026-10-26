<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use function intdiv;
use Symfony\Component\Uid\Uuid;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Domain\Event\BackupCodesRenewed;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Tests\Functional\Controller\PasskeyTestCase;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml, spec/saml.md S-63, decision 0029: in a deployment whose tenant federates example.org to the SimpleSAMLphp
 * identity provider of the judge (tests/symfony/config/config_test_service_provider.yml), the pages of the account
 * offer a person of that domain no password, passkey or authenticator app, and refuse each posted by hand, here with
 * the token a page rendered before the address of the person moved into that domain.
 */
final class FederatedAccountTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_service_provider',
        ];
    }

    /**
     * S-63: the page of the passkeys offers a person of a federated domain no passkey, and says why.
     */
    #[Test]
    public function thePasskeysPageOffersAPersonOfAFederatedDomainNoPasskey(): void
    {
        // Given
        $this->signIn(self::federated(self::user('alice')));

        // When
        $crawler = $this->passkeysPage();

        // Then
        static::assertSame([0, 1], self::offered($crawler, 'form[data-passkey="enrol"]'));
    }

    /**
     * S-63: a passkey posted by hand for a person of a federated domain is refused before the ceremony goes on, and
     * nothing is enrolled.
     */
    #[Test]
    public function aPasskeyPostedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = self::token($this->passkeysPage(), 'form[data-passkey="enrol"]');
        $attestation = self::device()->create($this->creationOptions());
        self::federated($alice);

        // When
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'YubiKey 5',
            '_passkey' => $attestation,
        ]);

        // Then
        static::assertSame(
            ['federated_domain', []],
            [self::refusal($this->afterTheForm()), self::credentialsOf($alice, PasskeyCredential::class)],
        );
    }

    /**
     * S-63: the page of the second factor offers a person of a federated domain no authenticator app, and says why.
     */
    #[Test]
    public function theTwoFactorPageOffersAPersonOfAFederatedDomainNoApp(): void
    {
        // Given
        $this->signIn(self::federated(self::user('alice')));

        // When
        $crawler = $this->page('/account/two-factor');

        // Then
        static::assertSame([0, 1], self::offered($crawler, 'form[data-two-factor="begin"], form[data-two-factor="backup-codes"]'));
    }

    /**
     * S-63: the page of the second factor offers a person of a federated domain who set up an app before their domain was
     * federated no new backup codes, and says why.
     */
    #[Test]
    public function theTwoFactorPageOffersAPersonOfAFederatedDomainNoBackupCodes(): void
    {
        // Given
        $this->signIn(self::federated($this->userWithTotp('alice')));

        // When
        $crawler = $this->page('/account/two-factor');

        // Then
        static::assertSame([0, 1], self::offered($crawler, 'form[data-two-factor="backup-codes"]'));
    }

    /**
     * S-63: backup codes renewed by hand for a person of a federated domain are refused, and none is drawn.
     */
    #[Test]
    public function backupCodesRenewedForAPersonOfAFederatedDomainAreRefused(): void
    {
        // Given
        $alice = $this->userWithTotp('alice');
        $this->signIn($alice);
        $token = self::token($this->page('/account/two-factor'), 'form[data-two-factor="backup-codes"]');
        self::federated($alice);
        self::forgetEvents();

        // When
        $this->browser->request('POST', '/account/two-factor/backup-codes', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(
            ['federated_domain', []],
            [self::refusal($this->afterTheForm()), self::events(BackupCodesRenewed::class)],
        );
    }

    /**
     * S-63: an authenticator app set up by hand for a person of a federated domain is refused before a secret is drawn.
     */
    #[Test]
    public function anAppSetUpForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = self::token($this->page('/account/two-factor'), 'form[data-two-factor="begin"]');
        self::federated($alice);

        // When
        $this->browser->request('POST', '/account/two-factor/begin', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(
            ['federated_domain', false],
            [self::refusal($this->afterTheForm()), $this->readHttpSession()->has(TotpProvisioningStore::KEY)],
        );
    }

    /**
     * S-63: the page of the password offers a person of a federated domain no form, though they held a password before
     * their domain was federated, and says why.
     */
    #[Test]
    public function thePasswordPageOffersAPersonOfAFederatedDomainNoForm(): void
    {
        // Given
        $this->signIn(self::federated(self::userWithPassword('alice', self::PASSWORD)));

        // When
        $crawler = $this->page('/account/password');

        // Then
        static::assertSame([0, 1], self::offered($crawler, 'form[data-password="change"]'));
    }

    /**
     * S-63: a password posed by hand for a person of a federated domain is refused, and the one they held is kept.
     */
    #[Test]
    public function aPasswordPosedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        $token = self::token($this->page('/account/password'), 'form[data-password="change"]');
        $held = self::credentialsOf($alice, PasswordCredential::class);
        self::federated($alice);

        // When
        $this->browser->request('POST', '/account/password', [
            '_token' => $token,
            'current_password' => self::PASSWORD,
            'new_password' => 'another horse battery staple',
            'new_password_again' => 'another horse battery staple',
        ]);

        // Then
        static::assertEquals(
            ['federated_domain', $held],
            [self::refusal($this->afterTheForm()), self::credentialsOf($alice, PasswordCredential::class)],
        );
    }

    /**
     * A person with an authenticator app set up an hour ago.
     */
    private function userWithTotp(string $username): User
    {
        $user = self::user($username);
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), Totps::secret()->bytes);
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

    private function page(string $path): Crawler
    {
        $crawler = $this->browser->request('GET', $path);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * How many of the form the page offers, and how many times it says the organisation signs the person in.
     *
     * @return array{int, int}
     */
    private static function offered(Crawler $crawler, string $form): array
    {
        return [$crawler->filter($form)->count(), $crawler->filter('p[data-federated]')->count()];
    }

    private static function token(Crawler $crawler, string $form): string
    {
        return (string) $crawler->filter($form . ' input[name="_token"]')->attr('value');
    }

    private static function refusal(Crawler $crawler): ?string
    {
        $refusal = $crawler->filter('p[data-error]');

        return $refusal->count() === 0 ? null : $refusal->attr('data-error');
    }

    /**
     * The person given a mailbox of example.org, the domain the provider of the judge answers for.
     */
    private static function federated(User $user): User
    {
        $users = self::service('test.beffroi.users', UserRepositoryInterface::class);
        $person = $users->find($user->id) ?? static::fail('The person is gone.');
        $person->changeEmail(new EmailAddress($user->username . '@example.org'), true, self::now());
        $users->save($person);

        return $person;
    }

    /**
     * The credentials of that kind the person holds, read from the rows.
     *
     * @param class-string<PasskeyCredential|PasswordCredential> $kind
     *
     * @return list<array{string, string}>
     */
    private static function credentialsOf(User $user, string $kind): array
    {
        self::reload();
        $credentials = [];
        foreach (self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($user, $kind) as $credential) {
            $credentials[] = [$credential->id->toRfc4122(), $credential instanceof PasswordCredential ? $credential->hash->encoded : $credential->name];
        }

        return $credentials;
    }
}
