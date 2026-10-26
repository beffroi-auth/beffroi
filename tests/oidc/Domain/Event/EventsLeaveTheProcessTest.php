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
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
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
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Beffroi\Oidc\Domain\Event\RefreshTokenRotated;
use Beffroi\Oidc\Domain\Event\TokenRevoked;
use Beffroi\Oidc\Domain\Event\TokensIssued;
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
 * Architecture §5.6: the events of the provider are handled asynchronously, so every one of them is
 * written to a queue. A client carries the method that authenticates it, and a method that proves a key
 * or a certificate carries the reader of the "jwks_uri" of the client, which is an HTTP client of the
 * framework: an event that carried a client could not be written at all, and would carry the
 * configuration of that HTTP client to the broker if it could. So an event carries what happened, by
 * identifier, and never the client itself.
 *
 * Each case is built the way the use case that raises it builds it, which is the only way there is: an
 * event has no named constructor, so what a queue is asked to carry is what a call site wrote.
 *
 * The client of each case authenticates with "private_key_jwt" and reads its keys through something that
 * cannot be serialized, which is what a deployment has.
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
        )];
        yield 'an introspection answered' => [new IntrospectionAnswered($now, $client->tenant, $clientId, $subject, $context)];
        yield 'a userinfo answered' => [new UserInfoAnswered($now, $client->tenant, $clientId, $subject, $context)];
        yield 'a registered client deleted' => [new RegisteredClientDeleted($now, $client->tenant, $clientId, $context)];
        yield 'a logout token given up on' => [new LogoutTokenGivenUp(
            $now,
            $session->tenant,
            $context,
            $clientId,
            $subject,
            $session->id,
            'the client answered 410',
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

    /**
     * An event this test does not carry to the queue is an event nothing says a broker can take, so the
     * cases above are the events of the module and not a selection of them.
     */
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
            // an event is a class: an interface that says something of several of them is not one, and
            // there is nothing of it to write to a queue
            if (class_exists($class) && is_a($class, DomainEventInterface::class, true)) {
                $declared[] = $class;
            }
        }
        sort($declared);

        return $declared;
    }

    /**
     * A client whose method cannot be serialized, as the one of a deployment cannot.
     */
    private static function client(AuthenticationSession $session): Client
    {
        return Clients::withKeys(
            $session->tenant,
            method: Methods::privateKeyJwt(Methods::keySetProvider(new UnserializableClientJwksFetcher())),
        );
    }
}
