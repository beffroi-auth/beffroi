<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use DateTimeImmutable;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Tests\Fixture\Grants;
use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Domain\Token\StoredClientAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokenInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Events;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * Architecture §4.6, §5.3
 */
final class DoctrineAccessTokenRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function anIssuedTokenComesBackWithWhatAResourceNeeds(): void
    {
        // Given
        $session = self::session(self::user());
        $client = self::client();
        $claims = new ClaimsRequest([
            'name' => new ClaimRequest(true),
        ]);
        $code = Tokens::code('the-code', $client, $session, self::now(), ['openid', 'email'], claims: $claims);
        $value = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            self::now()->modify('+1 minute'),
            self::now()->modify('+11 minutes'),
        );
        self::reload();

        // When
        $found = self::tokens()->find($value) ?? static::fail('The token was not stored.');

        // Then
        static::assertInstanceOf(StoredUserAccessToken::class, $found);
        static::assertSame(DrawnSecret::digestOf($value), $found->tokenHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertTrue($code->grantId->equals($found->grantId));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->registration->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertEquals([new Scope('openid'), new Scope('email')], $found->scopes->all);
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authentication->authenticatedAt);
        static::assertSame(['pwd'], $found->authentication->methods);
        static::assertSame('1', $found->authentication->contextClass);
        static::assertEquals(self::now()->modify('+1 minute'), $found->issuedAt);
        static::assertEquals(self::now()->modify('+11 minutes'), $found->expiresAt);
    }

    /**
     * RFC 7800 §3.1
     *
     * @param non-empty-string $thumbprint
     */
    #[Test]
    #[DataProvider('provideBindings')]
    public function aBoundTokenComesBackBoundToTheSameThing(ConfirmationInterface $confirmation, string $thumbprint): void
    {
        // Given
        $session = self::session(self::user());
        $code = Tokens::code('the-code', self::client(), $session, self::now());
        $value = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code, $confirmation),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        self::reload();

        // When
        $found = self::tokens()->find($value) ?? static::fail('The token was not stored.');

        // Then
        static::assertNotNull($found->confirmation);
        static::assertSame($confirmation->member(), $found->confirmation->member());
        static::assertSame($thumbprint, $found->confirmation->value());
        static::assertTrue($found->confirmation->matches($confirmation));
    }

    /**
     * @return iterable<string, array{ConfirmationInterface, non-empty-string}>
     */
    public static function provideBindings(): iterable
    {
        $thumbprint = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

        yield 'the certificate of the handshake' => [new CertificateConfirmation($thumbprint), $thumbprint];

        yield 'the key of a proof' => [new KeyConfirmation($thumbprint), $thumbprint];
    }

    #[Test]
    public function aTokenIsFoundByItsValueNeverByItsHash(): void
    {
        // Given
        $value = self::issued(self::authorization(self::session(self::user())), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When / Then
        static::assertNotNull(self::tokens()->find($value));
        static::assertNull(self::tokens()->find(DrawnSecret::digestOf($value)));
        static::assertNull(self::tokens()->find('unknown'));
    }

    #[Test]
    public function aRevokedTokenIsGone(): void
    {
        // Given
        $session = self::session(self::user());
        $revoked = self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        $kept = self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        self::reload();
        $record = self::tokens()->find($revoked) ?? static::fail('The token was not stored.');

        // When
        self::revoker()->revoke($record);
        self::reload();

        // Then
        static::assertNull(self::tokens()->find($revoked));
        static::assertNotNull(self::tokens()->find($kept));
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    public function theTokensOfAGrantAreRevokedTogether(): void
    {
        // Given
        $session = self::session(self::user());
        $code = Tokens::code('the-code', self::client(), $session, self::now());
        $second = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            self::now()->modify('+2 minutes'),
            self::now()->modify('+12 minutes'),
        );
        $first = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            self::now()->modify('+1 minute'),
            self::now()->modify('+11 minutes'),
        );
        $other = self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When
        $revoked = self::grantRevoker()->revokeByGrant($code->grantId);
        self::reload();

        // Then
        static::assertSame([DrawnSecret::digestOf($first), DrawnSecret::digestOf($second)], self::hashes($revoked));
        static::assertNull(self::tokens()->find($first));
        static::assertNull(self::tokens()->find($second));
        static::assertNotNull(self::tokens()->find($other));
        static::assertSame([], self::grantRevoker()->revokeByGrant($code->grantId), 'nothing left');
    }

    /**
     * Architecture §4.6, §5.3, RFC 6749 §4.4
     */
    #[Test]
    public function aTokenNobodySignedInForComesBackFromTheTableOfItsKind(): void
    {
        // Given
        $service = self::client('service-app');
        $grant = Uuid::v7();
        $value = self::issued(self::clientAuthorization($service, $grant), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When
        $found = self::tokens()->find($value) ?? static::fail('The token was not stored.');

        // Then
        static::assertInstanceOf(StoredClientAccessToken::class, $found);
        static::assertSame(DrawnSecret::digestOf($value), $found->tokenHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertTrue($grant->equals($found->grantId));
        static::assertSame('service-app', $found->clientId);
        static::assertSame('service-app', $found->client->registration->clientId);
        static::assertSame([Clients::CALENDAR], $found->resources?->values());
        static::assertEquals([new Scope('invoices.read')], $found->scopes->all);
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function aTokenNobodySignedInForIsRevokedLikeAnyOther(): void
    {
        // Given
        $service = self::client('service-app');
        $value = self::issued(self::clientAuthorization($service), self::now(), self::now()->modify('+10 minutes'));
        self::reload();
        $found = self::tokens()->find($value) ?? static::fail('The token was not stored.');

        // When
        self::revoker()->revoke($found);
        self::reload();

        // Then
        static::assertNull(self::tokens()->find($value));
    }

    /**
     * Architecture §4.9, RFC 6749 §4.4
     */
    #[Test]
    public function aLogoutLeavesTheTokensNobodySignedInFor(): void
    {
        // Given
        $session = self::session(self::user());
        $ofTheSession = self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        $ofTheService = self::issued(self::clientAuthorization(self::client('service-app')), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When
        $revoked = self::sessionRevoker()->revokeBySession($session->id);
        self::reload();

        // Then
        static::assertSame([DrawnSecret::digestOf($ofTheSession)], self::hashes($revoked));
        static::assertNull(self::tokens()->find($ofTheSession));
        static::assertNotNull(self::tokens()->find($ofTheService));
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    public function aGrantIsRevokedAcrossTheTablesOfEveryKind(): void
    {
        // Given
        $session = self::session(self::user());
        $grant = Uuid::v7();
        $code = Tokens::code('shared-code', self::client(), $session, self::now(), grantId: $grant);
        $ofTheSession = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        $ofTheService = self::issued(
            self::clientAuthorization(self::client('service-app'), $grant),
            self::now()->modify('+1 second'),
            self::now()->modify('+10 minutes'),
        );
        self::reload();

        // When
        $revoked = self::grantRevoker()->revokeByGrant($grant);
        self::reload();

        // Then
        static::assertSame(
            [DrawnSecret::digestOf($ofTheSession), DrawnSecret::digestOf($ofTheService)],
            self::hashes($revoked),
            'oldest first, whichever table it was in',
        );
        static::assertNull(self::tokens()->find($ofTheSession));
        static::assertNull(self::tokens()->find($ofTheService));
    }

    /**
     * Architecture §4.3, RFC 6749 §4.4
     */
    #[Test]
    public function theTokensOfAConsentAreRevokedTogether(): void
    {
        // Given
        $alice = self::user();
        $session = self::session($alice);
        $here = self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        $ofAnotherClient = self::issued(
            self::authorization($session, self::client('native-app')),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        $ofAnotherUser = self::issued(
            self::authorization(self::session(self::user('bob', 'bob-subject'))),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        $ofTheClientItself = self::issued(
            self::clientAuthorization(self::client('service-app')),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        self::reload();

        // When
        $revoked = self::consentRevoker()->revokeByConsent(self::consent($alice, self::client()));

        // Then
        static::assertSame([DrawnSecret::digestOf($here)], self::hashes($revoked));
        static::assertNull(self::tokens()->find($here));
        static::assertNotNull(self::tokens()->find($ofAnotherClient));
        static::assertNotNull(self::tokens()->find($ofAnotherUser));
        static::assertNotNull(self::tokens()->find($ofTheClientItself));
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function theTokensOfASessionAreRevokedTogether(): void
    {
        // Given
        $alice = self::user();
        $session = self::session($alice);
        $otherSession = self::session($alice, self::now()->modify('+1 minute'));
        $here = self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        $elsewhere = self::issued(self::authorization($otherSession), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When
        $revoked = self::sessionRevoker()->revokeBySession($session->id);
        self::reload();

        // Then
        static::assertSame([DrawnSecret::digestOf($here)], self::hashes($revoked));
        static::assertNull(self::tokens()->find($here));
        static::assertNotNull(self::tokens()->find($elsewhere));
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function aTokenAnotherWorkerRemovesBetweenTheReadAndTheRemovalIsNotTold(): void
    {
        // Given
        $session = self::session(self::user());
        self::issued(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        self::reload();
        self::removedByAnotherWorkerOnceRead();

        // When
        $revoked = self::sessionRevoker()->revokeBySession($session->id);

        // Then
        static::assertSame([], $revoked);
    }

    #[Test]
    public function aTokenOfAnUnregisteredClientIsNeitherFoundNorTold(): void
    {
        // Given
        $session = self::session(self::user());
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        $grant = Uuid::v7();
        $orphan = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'ghost-code',
                $ghost,
                $session,
                self::now(),
                grantId: $grant,
            )),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        $kept = self::issued(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                self::client(),
                $session,
                self::now()->modify('+1 minute'),
                grantId: $grant,
            )),
            self::now()->modify('+1 minute'),
            self::now()->modify('+11 minutes'),
        );
        self::reload();

        // When
        $found = self::tokens()->find($orphan);
        $revoked = self::grantRevoker()->revokeByGrant($grant);

        // Then
        static::assertNull($found);
        static::assertSame([DrawnSecret::digestOf($kept)], self::hashes($revoked));
        static::assertEquals(
            0,
            self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM beffroi_access_token'),
            'the row of the ghost went with the others',
        );
    }

    private static function authorization(AuthenticationSession $session, ?Client $client = null): UserAuthorization
    {
        return UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('a-code', $client ?? self::client(), $session, self::now()),
        );
    }

    private static function consent(User $user, Client $client): Consent
    {
        return new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now());
    }

    private static function consentRevoker(): CanRevokeAccessTokensByConsentInterface
    {
        return self::service('test.beffroi.access_tokens_of_a_consent', CanRevokeAccessTokensByConsentInterface::class);
    }

    private static function clientAuthorization(Client $client, ?Uuid $grantId = null): ClientAuthorization
    {
        return new ClientAuthorization(
            Grants::clientCredentials(),
            $grantId ?? Uuid::v7(),
            $client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
    }

    private static function tokens(): AccessTokenRepositoryInterface
    {
        return self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class);
    }

    private static function issued(AuthorizationInterface $authorization, DateTimeImmutable $issuedAt, DateTimeImmutable $expiresAt): string
    {
        $value = Secrets::draw();
        self::tokens()->save($authorization->storedUnder(DrawnSecret::digestOf($value), $issuedAt, $expiresAt));

        return $value;
    }

    private static function revoker(): CanRevokeAccessTokenInterface
    {
        return self::service('test.beffroi.access_tokens_store', CanRevokeAccessTokenInterface::class);
    }

    private static function grantRevoker(): CanRevokeAccessTokensByGrantInterface
    {
        return self::service('test.beffroi.access_tokens_store', CanRevokeAccessTokensByGrantInterface::class);
    }

    /**
     * What a worker revoking the same session writes between this one's read and its removal.
     */
    private static function removedByAnotherWorkerOnceRead(): void
    {
        self::entityManager()
            ->getEventManager()
            ->addEventListener(Events::postLoad, new class {
                public function postLoad(PostLoadEventArgs $event): void
                {
                    $token = $event->getObject();
                    if ($token instanceof StoredUserAccessToken) {
                        $event
                            ->getObjectManager()
                            ->getConnection()
                            ->executeStatement('DELETE FROM beffroi_access_token WHERE token_hash = ?', [
                                $token->tokenHash,
                            ]);
                    }
                }
            });
    }

    private static function sessionRevoker(): CanRevokeAccessTokensBySessionInterface
    {
        return self::service('test.beffroi.access_tokens_store', CanRevokeAccessTokensBySessionInterface::class);
    }

    /**
     * @param list<StoredAccessToken> $tokens
     *
     * @return list<string>
     */
    private static function hashes(array $tokens): array
    {
        return array_map(static fn (StoredAccessToken $token): string => $token->tokenHash, $tokens);
    }
}
