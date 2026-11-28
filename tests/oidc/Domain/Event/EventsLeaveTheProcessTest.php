<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Event;

use function array_map;
use function array_unique;
use function array_values;
use function basename;
use function class_exists;
use function dirname;
use function glob;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Event\ConsentRevoked;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Beffroi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Domain\Event\PushedRequestRefusalReason;
use Beffroi\Oidc\Domain\Event\PushedRequestRefused;
use Beffroi\Oidc\Domain\Event\RefreshTokenOutlivedItsSession;
use Beffroi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenIssued;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenRevoked;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Beffroi\Oidc\Domain\Event\RefreshTokenRotated;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use Beffroi\Oidc\Domain\Event\TokenRevoked;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\SessionsReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\ConsentsReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\JournalReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\MembershipReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\ReadRefusedToAnAdministrator;
use Beffroi\Oidc\Domain\Event\UserInfoAnswered;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\RevokedTokenHashes;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Beffroi\Oidc\Tests\Fixture\UnserializableClientJwksFetcher;
use function is_a;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function serialize;
use function sort;
use function sprintf;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.6
 */
final class EventsLeaveTheProcessTest extends TestCase
{
    /**
     * @return iterable<string, array{DomainEventInterface}>
     */
    public static function events(): iterable
    {
        $session = Fixtures::session();
        $client = self::client($session);
        $clientId = $client->registration->clientId;
        $now = Fixtures::now();
        $code = Tokens::code('the-code', $client, $session, $now);
        $family = Tokens::family($now, $client->tenant);
        $previous = Tokens::refreshToken('previous', $client, $session, $now, $family);
        $next = Tokens::refreshToken('next', $client, $session, $now, $family);
        $accessToken = Tokens::storedAccessToken('opaque', $client, $session, $now);
        $consent = new Consent(Uuid::v7(), $session->user, $client, new Scopes([Scope::openid()]), $now);
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code);
        $context = Fixtures::context();
        $subject = $session->user->subject;

        yield 'an authorization code issued' => [new AuthorizationCodeIssued(
            $code->issuedAt,
            $code->tenant,
            $code->clientId,
            $subject,
            $code->grantId,
            $code->session->id,
            $code->codeHash,
            $code->scopes,
            $code->expiresAt,
            $context,
        )];
        yield 'an authorization code replayed' => [new AuthorizationCodeReplayed(
            $now,
            $code->tenant,
            $code->codeHash,
            $subject,
            $code->clientId,
            $clientId,
            RevokedTokenHashes::of([$previous]),
            $context,
        )];
        yield 'a client that failed to authenticate' => [new ClientAuthenticationFailed(
            $now,
            $session->tenant,
            $context,
            ClientAuthenticationFailureReason::InvalidAssertion,
            $clientId,
            'private_key_jwt',
        )];
        yield 'a backchannel request answered' => [new BackchannelRequestAnswered(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new ClientUri('https://key.example/ciba-notification'),
            'the-auth-req-id',
            'the-notification-token',
            $context,
        )];
        yield 'a consent granted' => [new ConsentGranted(
            $consent->grantedAt,
            $consent->tenant,
            $consent->id,
            $consent->clientId,
            $subject,
            $consent->scopes,
            AuthorizationDetailTypes::details(),
            new ClaimNames(['email']),
            null,
            $context,
        )];
        yield 'a consent taken back' => [new ConsentRevoked(
            $now,
            $consent->tenant,
            $consent->id,
            $consent->clientId,
            $subject,
            [$code->grantId],
            RevokedTokenHashes::of([$previous, $next]),
            RevokedTokenHashes::of([$accessToken]),
            $context,
            new ThePerson(),
        )];
        yield 'an introspection answered' => [new IntrospectionAnswered($now, $client->tenant, $clientId, $subject, $context)];
        yield 'a userinfo answered' => [new UserInfoAnswered($now, $client->tenant, $clientId, $subject, $context)];
        yield 'a person read by an administrator' => [new PersonReadByAnAdministrator(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new Subject('administrator-subject'),
            $context,
        )];
        yield 'their sessions read by an administrator' => [new SessionsReadByAnAdministrator(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new Subject('administrator-subject'),
            $context,
        )];
        yield 'their journal read by an administrator' => [new JournalReadByAnAdministrator(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new Subject('administrator-subject'),
            $context,
        )];
        yield 'their consents read by an administrator' => [new ConsentsReadByAnAdministrator(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new Subject('administrator-subject'),
            $context,
        )];
        yield 'their membership of a group read by an administrator' => [new MembershipReadByAnAdministrator(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new Subject('administrator-subject'),
            $context,
        )];
        yield 'a read refused to an administrator past the budget of their reads' => [new ReadRefusedToAnAdministrator(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            $context,
        )];
        yield 'a registered client that deleted itself' => [new RegisteredClientDeleted($now, $client->tenant, $clientId, $context, new AClient($clientId))];
        yield 'a registered client the host deleted' => [new RegisteredClientDeleted($now, $client->tenant, $clientId, $context, new TheHost())];
        yield 'a registered client deleted by an administrator' => [new RegisteredClientDeleted(
            $now,
            $client->tenant,
            $clientId,
            $context,
            new AnAdministrator(new Subject('administrator-subject')),
        )];
        yield 'an initial access token the host issued' => [new InitialAccessTokenIssued($now, $client->tenant, Uuid::v7(), $context, new TheHost())];
        yield 'an initial access token issued by an administrator' => [new InitialAccessTokenIssued(
            $now,
            $client->tenant,
            Uuid::v7(),
            $context,
            new AnAdministrator(new Subject('administrator-subject')),
        )];
        yield 'an initial access token the host revoked' => [new InitialAccessTokenRevoked($now, $client->tenant, Uuid::v7(), $context, new TheHost())];
        yield 'a logout token given up on' => [new LogoutTokenGivenUp(
            $now,
            $session->tenant,
            $context,
            $clientId,
            $subject,
            $session->id,
            'the client answered 410',
            new ThePerson(),
        )];
        yield 'a logout token issued' => [new LogoutTokenIssued(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new ClientUri('https://key.example/backchannel-logout'),
            $session->id,
            'eyJ.the.token',
            $context,
            new ThePerson(),
        )];
        yield 'a logout token of a session a directory ended' => [new LogoutTokenIssued(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            new ClientUri('https://key.example/backchannel-logout'),
            $session->id,
            'eyJ.the.token',
            $context,
            new ADirectory('Entra ID'),
        )];
        yield 'a pushed request refused' => [new PushedRequestRefused(
            $now,
            $session->tenant,
            PushedRequestRefusalReason::Expired,
            $clientId,
            $clientId,
            $context,
        )];
        yield 'a refresh token reused' => [new RefreshTokenReuseDetected(
            $now,
            $previous->tenant,
            $previous->clientId,
            $subject,
            $previous->family->id,
            $previous->tokenHash,
            RevokedTokenHashes::of([$previous, $next]),
            $context,
        )];
        yield 'a refresh token that outlived its session' => [new RefreshTokenOutlivedItsSession(
            $now,
            $previous->tenant,
            $previous->clientId,
            $subject,
            $session->id,
            $now->modify('-1 minute'),
            $context,
        )];
        yield 'a refresh token rotated' => [new RefreshTokenRotated(
            $next->issuedAt,
            $next->tenant,
            $next->clientId,
            $subject,
            $next->family->id,
            $previous->tokenHash,
            $next->tokenHash,
            $next->expiresAt,
            $context,
        )];
        yield 'the tokens of a client revoked at the end of a session' => [new SessionTokensRevoked(
            $now,
            $session->tenant,
            $clientId,
            $subject,
            $session->id,
            2,
            1,
            $context,
        )];
        yield 'the tokens of a client revoked at the end of a session an administrator ended' => [new SessionTokensRevoked(
            $now,
            $session->tenant,
            $clientId,
            $subject,
            $session->id,
            1,
            0,
            $context,
            new Subject('administrator-subject'),
        )];
        yield 'an access token revoked' => [new TokenRevoked(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            TokenRevoked::ACCESS_TOKEN,
            $accessToken->tokenHash,
            $accessToken->grantId,
            [],
            $context,
        )];
        yield 'a refresh token revoked' => [new TokenRevoked(
            $now,
            $client->tenant,
            $clientId,
            $subject,
            TokenRevoked::REFRESH_TOKEN,
            $previous->tokenHash,
            $previous->family->grantId,
            RevokedTokenHashes::of([$accessToken]),
            $context,
        )];
        yield 'the tokens of a grant issued' => [new TokensIssued(
            $now,
            $authorization->tenant,
            $authorization->grantType,
            $authorization->grantId,
            $clientId,
            $subject,
            $authorization->session->id,
            $authorization->grantedScopes,
            $now->modify('+10 minutes'),
            true,
            $authorization->confirmation,
            $next->tokenHash,
            $authorization->claimsRequest,
            AuthorizationDetailTypes::details(),
            'jwt',
            $context,
        )];
    }

    #[Test]
    #[DataProvider('events')]
    public function anEventIsWrittenToTheQueueAndReadBack(DomainEventInterface $event): void
    {
        // When
        $written = serialize($event);

        // Then
        static::assertInstanceOf($event::class, unserialize($written));
    }

    #[Test]
    public function everyEventOfTheModuleIsWrittenToTheQueue(): void
    {
        // Given
        $covered = array_values(array_unique(array_map(static fn (array $case): string => $case[0]::class, [...self::events()])));
        sort($covered);

        // When
        $declared = self::declaredEvents();

        // Then
        static::assertSame($declared, $covered);
    }

    /**
     * @return list<class-string<DomainEventInterface>>
     */
    private static function declaredEvents(): array
    {
        $reflection = new ReflectionClass(TokensIssued::class);
        $file = $reflection->getFileName();
        if ($file === false) {
            static::fail('The events of the module are read from the directory of one of them.');
        }
        $files = glob(dirname($file) . '/*.php');
        if ($files === false) {
            static::fail(sprintf('The directory of the events cannot be read: %s.', dirname($file)));
        }
        $declared = [];
        foreach ($files as $candidate) {
            /** @var class-string $class */
            $class = $reflection->getNamespaceName() . '\\' . basename($candidate, '.php');
            if (class_exists($class) && is_a($class, DomainEventInterface::class, true)) {
                $declared[] = $class;
            }
        }
        sort($declared);

        return $declared;
    }

    private static function client(AuthenticationSession $session): Client
    {
        return Clients::withKeys(
            $session->tenant,
            method: Methods::privateKeyJwt(Methods::keySetProvider(new UnserializableClientJwksFetcher())),
        );
    }
}
