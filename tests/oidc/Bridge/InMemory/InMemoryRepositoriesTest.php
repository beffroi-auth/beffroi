<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\InMemory;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\Grants;
use function array_keys;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\StoredClientAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    #[Test]
    public function anEmptyInteractionRepositoryHasNoLastInteraction(): void
    {
        // When / Then
        static::assertNull(new InMemoryInteractionRepository()->last());
    }

    #[Test]
    public function itFindsAnInteractionByIdentifier(): void
    {
        // Given
        $repository = new InMemoryInteractionRepository();
        $first = $this->interaction();
        $second = $this->interaction();
        $repository->save($first);
        $repository->save($second);

        // When / Then
        static::assertSame($first, $repository->find($first->id));
        static::assertSame($second, $repository->find($second->id));
        static::assertNull($repository->find(Secrets::draw()));
    }

    #[Test]
    public function theLastInteractionSavedIsTheLast(): void
    {
        // Given
        $repository = new InMemoryInteractionRepository();
        $first = $this->interaction();
        $second = $this->interaction();

        // When
        $repository->save($first);
        $repository->save($second);
        $repository->save($first);

        // Then
        static::assertSame($second, $repository->last());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function anEmptyConsentRepositoryHasNoActiveConsent(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();

        // When / Then
        static::assertNull($repository->findActive($this->session->user, $this->client));
    }

    #[Test]
    public function itFindsTheActiveConsentGrantedLast(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $older = $this->consent($alice, $this->client, '-2 days');
        $newer = $this->consent($alice, $this->client, '-1 day');
        $revoked = $this->consent($alice, $this->client, '+0 seconds');
        $revoked->revoke(Fixtures::now());
        foreach ([$newer, $older, $revoked] as $consent) {
            $repository->save($consent);
        }

        // When / Then
        static::assertSame($newer, $repository->findActive($alice, $this->client));
    }

    #[Test]
    public function theConsentOfAnotherUserOrClientIsNotFound(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $bob = Fixtures::user($alice->tenant, 'bob', 'bob-subject');
        $another = Clients::public($alice->tenant, 'another');
        $bobs = $this->consent($bob, $this->client, '+0 seconds');
        $repository->save($bobs);
        $repository->save($this->consent($alice, $another, '+0 seconds'));

        // When / Then
        static::assertSame($bobs, $repository->findActive($bob, $this->client));
        static::assertNull($repository->findActive($bob, $another));
    }

    #[Test]
    public function everyConsentSavedIsKept(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();

        // When
        foreach (['-2 days', '-1 day', '+0 seconds'] as $grantedAt) {
            $repository->save($this->consent($this->session->user, $this->client, $grantedAt));
        }

        // Then
        static::assertCount(3, $repository->all());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function betweenTwoConsentsGrantedAtTheSameInstantTheLastSavedWins(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $repository->save($this->consent($this->session->user, $this->client, '-1 day'));
        $tie = $this->consent($this->session->user, $this->client, '-1 day');

        // When
        $repository->save($tie);

        // Then
        static::assertSame($tie, $repository->findActive($this->session->user, $this->client));
    }

    #[Test]
    public function itListsWhatAUserHasInForce(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $another = Clients::public($alice->tenant, 'another');
        $older = $this->consent($alice, $another, '-2 days');
        $newer = $this->consent($alice, $this->client, '-1 day');
        $revoked = $this->consent($alice, Clients::public($alice->tenant, 'third'), '+0 seconds');
        $revoked->revoke(Fixtures::now());
        foreach ([$older, $newer, $revoked] as $consent) {
            $repository->save($consent);
        }
        $repository->save($this->consent(Fixtures::user($alice->tenant, 'bob', 'bob-subject'), $this->client, '+0 seconds'));

        // When / Then
        static::assertSame([$newer, $older], $repository->activeOf($alice));
    }

    #[Test]
    public function itRevokesTheGrantsAClientHoldsForAUser(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $consent = $this->consent($this->session->user, $this->client, '-1 day');
        $mine = $this->code('mine');
        $elsewhere = Tokens::code('elsewhere', Clients::public($this->session->tenant, 'another'), $this->session, Fixtures::now());
        $repository->save($mine);
        $repository->save($elsewhere);

        // When / Then
        static::assertSame([$mine], $repository->revokeByConsent($consent, Fixtures::now()));
    }

    #[Test]
    public function itFindsTheRefreshTokensAClientHoldsForAUser(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $consent = $this->consent($this->session->user, $this->client, '-1 day');
        $mine = Tokens::refreshToken('mine', $this->client, $this->session, Fixtures::now());
        $repository->save($mine);
        $repository->save(Tokens::refreshToken('elsewhere', Clients::public($this->session->tenant, 'another'), $this->session, Fixtures::now()));

        // When / Then
        static::assertSame([$mine], $repository->ofConsent($consent));
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function itRemovesTheAccessTokensAClientHoldsForAUser(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $consent = $this->consent($this->session->user, $this->client, '-1 day');
        $mine = Tokens::storedAccessToken('mine', $this->client, $this->session, Fixtures::now());
        $ofTheClientItself = Tokens::storedClientAccessToken('its own', $this->client, Fixtures::now());
        $repository->save($mine);
        $repository->save($ofTheClientItself);
        $repository->save(Tokens::storedAccessToken('elsewhere', Clients::public($this->session->tenant, 'another'), $this->session, Fixtures::now()));

        // When
        $removed = $repository->revokeByConsent($consent);

        // Then
        static::assertSame([$mine], $removed);
        static::assertNull($repository->find('mine'));
        static::assertNotNull($repository->find('its own'));
        static::assertNotNull($repository->find('elsewhere'));
    }

    #[Test]
    public function anEmptyCodeRepositoryFindsNothing(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();

        // When / Then
        static::assertSame([], $repository->all());
        static::assertNull($repository->findByCodeHash(DrawnSecret::digestOf('one')));
    }

    #[Test]
    public function itKeepsEachCodeOnceByHash(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');

        // When
        $repository->save($code);
        $repository->save($code);

        // Then
        static::assertSame([$code], $repository->all());
        static::assertSame(2, $repository->saves);
    }

    #[Test]
    public function itFindsACodeByHashNeverByValue(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');
        $repository->save($code);

        // When / Then
        static::assertSame($code, $repository->findByCodeHash(DrawnSecret::digestOf('one')));
        static::assertNull($repository->findByCodeHash(DrawnSecret::digestOf('two')));
        static::assertNull($repository->findByCodeHash('one'), 'the lookup is by hash, never by value');
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    public function onlyTheFirstCallerConsumesACode(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');
        $repository->save($code);

        // When / Then
        static::assertTrue($repository->consume($code, Fixtures::now()));
        static::assertFalse($repository->consume($code, Fixtures::now()->modify('+1 second')));
        static::assertEquals(Fixtures::now(), $code->usedAt);
    }

    #[Test]
    public function anUnknownCodeIsNotConsumed(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();

        // When / Then
        static::assertFalse($repository->consume($this->code('one'), Fixtures::now()));
    }

    #[Test]
    public function itFindsAPushedRequestByTheHashOfItsReferenceNeverByItsValue(): void
    {
        // Given
        $repository = new InMemoryPushedAuthorizationRecordRepository();
        $requestUri = RequestUri::of(Secrets::draw());
        $repository->save($this->pushedRequest($requestUri));

        // When / Then
        static::assertNotNull($repository->findByRequestUriHash($requestUri->hash()));
        static::assertNull($repository->findByRequestUriHash(RequestUri::of(Secrets::draw())->hash()));
        static::assertNull($repository->findByRequestUriHash($requestUri->value), 'the lookup is by hash, never by value');
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function onlyTheFirstCallerConsumesAPushedRequest(): void
    {
        // Given
        $repository = new InMemoryPushedAuthorizationRecordRepository();
        $request = $this->pushedRequest(RequestUri::of(Secrets::draw()));
        $repository->save($request);

        // When / Then
        static::assertTrue($repository->consume($request, Fixtures::now()));
        static::assertFalse($repository->consume($request, Fixtures::now()->modify('+1 second')));
        static::assertEquals(Fixtures::now(), $request->usedAt);
    }

    #[Test]
    public function anUnknownPushedRequestIsNotConsumed(): void
    {
        // Given
        $repository = new InMemoryPushedAuthorizationRecordRepository();

        // When / Then
        static::assertFalse($repository->consume($this->pushedRequest(RequestUri::of(Secrets::draw())), Fixtures::now()));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function theClientsOfASessionComeBackAsAListOfEachClientOnce(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        foreach (['one', 'two'] as $value) {
            $code = $this->code($value);
            $code->consume(Fixtures::now());
            $repository->save($code);
        }

        // When
        $clients = $repository->ofSession($this->session->id);

        // Then
        static::assertSame([0], array_keys($clients));
        static::assertSame($this->client, $clients[0]);
    }

    #[Test]
    public function anEmptyRefreshTokenRepositoryFindsNothing(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), $this->client->tenant, 'first-code');

        // When / Then
        static::assertSame([], $repository->all());
        static::assertNull($repository->findByTokenHash(DrawnSecret::digestOf('first')));
        static::assertSame([], $repository->findByFamily($family->id));
        static::assertSame([], $repository->findByAuthorizationCode(DrawnSecret::digestOf('first-code')));
        static::assertSame([], $repository->findBySession($this->session->id));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itFindsARefreshTokenByHashNeverByValue(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $repository->save($first);

        // When / Then
        static::assertSame($first, $repository->findByTokenHash(DrawnSecret::digestOf('first')));
        static::assertNull($repository->findByTokenHash('first'), 'the lookup is by hash, never by value');
        static::assertNull($repository->findByTokenHash(DrawnSecret::digestOf('unknown')));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itFindsAFamilyWhole(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), $this->client->tenant, 'first-code');
        $lineage = $this->lineage($family);
        $other = Tokens::refreshToken(
            'other',
            $this->client,
            $this->session,
            Fixtures::now(),
            Tokens::family(Fixtures::now(), $this->client->tenant, 'other-code'),
        );
        foreach ([...$lineage, $other] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByFamily($family->id));
        static::assertSame([$other], $repository->findByFamily($other->family->id));
        static::assertSame([], $repository->findByFamily(Uuid::v7()));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itFindsOnlyTheTokensOfTheTenantOfAFamily(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), $this->client->tenant, 'first-code');
        $lineage = $this->lineage($family);
        $elsewhere = Fixtures::tenant('other', 'https://id.other.example');
        $elsewhereFamily = Tokens::family(Fixtures::now(), $elsewhere, 'other-code');
        $stranger = Tokens::refreshToken(
            'stranger',
            Clients::public($elsewhere),
            Fixtures::session(Fixtures::user($elsewhere)),
            Fixtures::now(),
            $elsewhereFamily,
        );
        foreach ([...$lineage, $stranger] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByFamily($family->id));
        static::assertSame([$stranger], $repository->findByFamily($elsewhereFamily->id));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itFindsTheDescendantsOfACode(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), $this->client->tenant, 'first-code');
        $lineage = $this->lineage($family);
        $other = Tokens::refreshToken(
            'other',
            $this->client,
            $this->session,
            Fixtures::now(),
            Tokens::family(Fixtures::now(), $this->client->tenant, 'other-code'),
        );
        foreach ([...$lineage, $other] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByAuthorizationCode(DrawnSecret::digestOf('first-code')));
        static::assertSame([$other], $repository->findByAuthorizationCode(DrawnSecret::digestOf('other-code')));
        static::assertSame([], $repository->findByAuthorizationCode(DrawnSecret::digestOf('unknown')));
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function itFindsEveryTokenOfASession(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $lineage = $this->lineage(Tokens::family(Fixtures::now(), $this->client->tenant, 'first-code'));
        $other = Tokens::refreshToken(
            'other',
            $this->client,
            $this->session,
            Fixtures::now(),
            Tokens::family(Fixtures::now(), $this->client->tenant, 'other-code'),
        );
        $elsewhere = Tokens::refreshToken(
            'elsewhere',
            $this->client,
            Fixtures::session(Fixtures::user($this->session->tenant, 'bob', 'bob-subject')),
            Fixtures::now(),
        );
        foreach ([...$lineage, $other, $elsewhere] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame([...$lineage, $other], $repository->findBySession($this->session->id));
        static::assertSame([$elsewhere], $repository->findBySession($elsewhere->session->id));
        static::assertSame([], $repository->findBySession(Uuid::v7()));
    }

    #[Test]
    public function itKeepsEachRefreshTokenOnce(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $second = Tokens::refreshToken('second', $this->client, $this->session, Fixtures::now());

        // When
        foreach ([$first, $second, $first] as $token) {
            $repository->save($token);
        }

        // Then
        static::assertSame([$first, $second], $repository->all());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function aRefreshTokenIsRevokedOnce(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $token = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $repository->save($token);
        $repository->revokeOnce($token, Fixtures::now()->modify('+1 hour'));

        // When / Then
        static::assertFalse($repository->revokeOnce($token, Fixtures::now()->modify('+2 hours')));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itKeepsAnAccessTokenAndFindsItByItsValue(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'email'],
        ));

        $value = Secrets::draw();

        // When
        $repository->save($authorization->storedUnder(DrawnSecret::digestOf($value), Fixtures::now(), Fixtures::now()->modify('+10 minutes')));

        // Then
        $record = $repository->find($value) ?? static::fail('The token was kept.');
        static::assertInstanceOf(StoredUserAccessToken::class, $record);
        static::assertSame(DrawnSecret::digestOf($value), $record->tokenHash);
        static::assertSame($this->client, $record->client);
        static::assertSame($this->session, $record->session);
        static::assertTrue($authorization->grantId->equals($record->grantId));
        static::assertSame(['openid', 'email'], $record->scopes->values());
        static::assertEquals(Fixtures::now(), $record->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $record->expiresAt);
        static::assertNull($repository->find(DrawnSecret::digestOf($value)), 'the hash is not the value');
    }

    #[Test]
    public function anEmptyAccessTokenRepositoryFindsNothing(): void
    {
        // When / Then
        static::assertNull(new InMemoryAccessTokenRepository()->find('unknown'));
    }

    /**
     * RFC 7009
     */
    #[Test]
    public function itRevokesOneAccessToken(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $revoked = Tokens::storedAccessToken('revoked', $this->client, $this->session, Fixtures::now());
        $kept = Tokens::storedAccessToken('kept', $this->client, $this->session, Fixtures::now());
        $repository->save($revoked);
        $repository->save($kept);

        // When
        $repository->revoke($revoked);

        // Then
        static::assertNull($repository->find('revoked'));
        static::assertSame([$kept], $repository->all());
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    public function itRevokesTheAccessTokensOfAGrant(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $grant = Uuid::v7();
        $first = Tokens::storedAccessToken('first', $this->client, $this->session, Fixtures::now(), $grant);
        $second = Tokens::storedAccessToken('second', $this->client, $this->session, Fixtures::now(), $grant);
        $other = Tokens::storedAccessToken('other', $this->client, $this->session, Fixtures::now());
        foreach ([$first, $second, $other] as $token) {
            $repository->save($token);
        }

        // When
        $revoked = $repository->revokeByGrant($grant);

        // Then
        static::assertSame([$first, $second], $revoked);
        static::assertSame([$other], $repository->all());
        static::assertSame([], $repository->revokeByGrant($grant), 'nothing left');
    }

    /**
     * Architecture §4.6, RFC 6749 §4.4
     */
    #[Test]
    public function itKeepsAnAccessTokenNobodySignedInForAsTheRecordOfItsKind(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $service = Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $service,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );

        $value = Secrets::draw();

        // When
        $repository->save($authorization->storedUnder(DrawnSecret::digestOf($value), Fixtures::now(), Fixtures::now()->modify('+10 minutes')));

        // Then
        $record = $repository->find($value) ?? static::fail('The token was kept.');
        static::assertInstanceOf(StoredClientAccessToken::class, $record);
        static::assertSame($service, $record->client);
        static::assertTrue($authorization->grantId->equals($record->grantId));
        static::assertSame([Clients::CALENDAR], $record->resources?->values());
    }

    /**
     * Architecture §4.9, RFC 6749 §4.4
     */
    #[Test]
    public function aLogoutLeavesTheAccessTokensNobodySignedInFor(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $ofTheSession = Tokens::storedAccessToken('here', $this->client, $this->session, Fixtures::now());
        $ofTheService = Tokens::storedClientAccessToken(
            'batch',
            Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            Fixtures::now(),
        );
        $repository->save($ofTheSession);
        $repository->save($ofTheService);

        // When
        $revoked = $repository->revokeBySession($this->session->id);

        // Then
        static::assertSame([$ofTheSession], $revoked);
        static::assertSame([$ofTheService], $repository->all());
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function itRevokesTheAccessTokensOfASession(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $here = Tokens::storedAccessToken('here', $this->client, $this->session, Fixtures::now());
        $elsewhere = Tokens::storedAccessToken(
            'elsewhere',
            $this->client,
            Fixtures::session(Fixtures::user($this->session->tenant, 'bob', 'bob-subject')),
            Fixtures::now(),
        );
        $repository->save($here);
        $repository->save($elsewhere);

        // When
        $revoked = $repository->revokeBySession($this->session->id);

        // Then
        static::assertSame([$here], $revoked);
        static::assertSame([$elsewhere], $repository->all());
    }

    private function interaction(): Interaction
    {
        return new Interaction(
            Secrets::draw(),
            $this->client->tenant,
            Requests::authorization($this->client),
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }

    private function consent(User $user, Client $client, string $grantedAt): Consent
    {
        return new Consent(Uuid::v7(), $user, $client, new Scopes([Scope::openid()]), Fixtures::now()->modify($grantedAt));
    }

    private function pushedRequest(RequestUri $requestUri): PushedAuthorizationRecord
    {
        return new PushedAuthorizationRecord(
            $requestUri->hash(),
            $this->client,
            [
                'scope' => 'openid',
            ],
            Fixtures::now(),
            Fixtures::now()->modify('+60 seconds'),
        );
    }

    private function code(string $value): AuthorizationCode
    {
        return new AuthorizationCode(
            DrawnSecret::digestOf($value),
            Uuid::v7(),
            $this->client,
            $this->session,
            $this->client->registration->redirectUris[0],
            new Scopes([Scope::openid()]),
            null,
            null,
            null,
            new CodeChallenge(Requests::CHALLENGE, new Sha256CodeChallengeMethod()),
            null,
            null,
            new AuthenticationSnapshot(Fixtures::now(), ['pwd'], '1'),
            Fixtures::now(),
            Fixtures::now()->modify('+60 seconds'),
        );
    }

    /**
     * @return list<RefreshToken>
     */
    private function lineage(RefreshTokenFamily $family): array
    {
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now(), $family);
        $second = Tokens::refreshToken('second', $this->client, $this->session, Fixtures::now()->modify('+1 day'), $family);
        $first->rotate(Fixtures::now()->modify('+1 day'));
        $revoked = Tokens::refreshToken('revoked', $this->client, $this->session, Fixtures::now()->modify('+2 days'), $family);
        $revoked->revoke(Fixtures::now()->modify('+2 days'));

        return [$first, $second, $revoked];
    }
}
