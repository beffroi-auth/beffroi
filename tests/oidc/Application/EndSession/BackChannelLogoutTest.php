<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Identity\Subject;
use DateInterval;
use function array_column;
use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\EndSession\BackChannelLogout;
use Beffroi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Beffroi\Oidc\Tests\Fixture\FakeLogoutTokenDelivery;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\RecordingLogoutTokenRetries;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Clock\MockClock;

/**
 * Back-Channel Logout 1.0 §2.6
 */
final class BackChannelLogoutTest extends TestCase
{
    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private RecordingEventDispatcher $events;

    private RecordingLogoutTokenRetries $retries;

    private BackChannelLogout $logout;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->events = new RecordingEventDispatcher();
        $this->retries = new RecordingLogoutTokenRetries();
        $unreachable = new FakeClientJwksFetcher([ClientEncryption::publishedKeys()]);
        $unreachable->failure = new ClientKeysUnavailableException('https://unreachable.example/jwks cannot be reached.');
        $this->logout = new BackChannelLogout(
            $this->grants,
            new LogoutTokenIssuer(
                new Jwts($this->session->tenant)->documentsFor($unreachable),
                Subjects::publicKind(),
                new SymfonyUuidGenerator(),
                new FakeLogoutTokenDelivery(new DateInterval('PT200S')),
            ),
            $this->retries,
            $this->events,
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function everyClientOfTheSessionThatRegisteredAUriIsTold(): void
    {
        // Given
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'second', 'https://second.example/logout'));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'third', 'https://third.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame(['first', 'second', 'third'], array_map(
            static fn (LogoutTokenIssued $event): string => $event->clientId,
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientWithoutABackChannelLogoutUriIsNotTold(): void
    {
        // Given
        $this->signedIn(Clients::public($this->session->tenant, 'silent'));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'listening', 'https://listening.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame(['listening'], array_map(
            static fn (LogoutTokenIssued $event): string => $event->clientId,
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientIsToldOnceWhateverTheNumberOfItsGrants(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $this->signedIn($client, 'first-grant');
        $this->signedIn($client, 'second-grant');

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertCount(1, $this->events->of(LogoutTokenIssued::class));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientThatNeverExchangedItsCodeIsNotTold(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $this->grants->save(Tokens::code('unused-code', $client, $this->session, Fixtures::now()));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
    }

    /**
     * Back-Channel Logout 1.0 §2.4
     */
    #[Test]
    public function theClientsOfAnotherSessionAreNotTold(): void
    {
        // Given
        $other = Fixtures::session($this->session->user);
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $grant = Tokens::code('other-code', $client, $other, Fixtures::now());
        $grant->consume(Fixtures::now());
        $this->grants->save($grant);

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function theEventCarriesTheUriAndTheTokenToPostThere(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $this->signedIn($client);

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        [$event] = $this->events->of(LogoutTokenIssued::class);
        static::assertSame('https://first.example/logout', $event->logoutUri->value);
        static::assertSame($this->session->id, $event->sessionId);
        static::assertSame(Fixtures::now()->getTimestamp(), $event->occurredAt->getTimestamp());
        static::assertStringStartsWith('eyJ', $event->token);
    }

    /**
     * Decisions 0038 and 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theLogoutTokenOfASessionNamesWhoEndedIt(AuthorInterface $author): void
    {
        // Given
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), $author);

        // Then
        static::assertSame([$author], array_map(
            static fn (LogoutTokenIssued $event): AuthorInterface => $event->author(),
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * @return iterable<string, array{AuthorInterface}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the person' => [new ThePerson()];
        yield 'an administrator' => [new AnAdministrator(new Subject('administrator-subject'))];
        yield 'a directory' => [new ADirectory('Entra ID')];
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aClientLeftForLaterIsToldInTheNameOfTheAdministratorWhoEndedTheSession(): void
    {
        // Given
        $this->signedIn(self::unreachable($this->session));
        $administrator = new AnAdministrator(new Subject('administrator-subject'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), $administrator);

        // Then
        static::assertSame([$administrator], array_column($this->retries->later, 'author'));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientWhoseEncryptionKeyCannotBeObtainedIsLeftForLater(): void
    {
        // Given
        $this->signedIn(self::unreachable($this->session));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
        static::assertSame(['unreachable'], array_column($this->retries->later, 'clientId'));
        static::assertSame([$this->session], array_column($this->retries->later, 'session'));
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function theOtherClientsAreToldWhileOneIsLeftForLater(): void
    {
        // Given
        $this->signedIn(self::unreachable($this->session));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'listening', 'https://listening.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame(['listening'], array_map(
            static fn (LogoutTokenIssued $event): string => $event->clientId,
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientWhoseKeyReceivesNoJweIsLeftForLater(): void
    {
        // Given
        $this->signedIn(self::offItsCurve($this->session));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
        static::assertSame(['off-its-curve'], array_column($this->retries->later, 'clientId'));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function theOtherClientsAreToldWhileOneWhoseKeyReceivesNoJweIsLeftForLater(): void
    {
        // Given
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'listening', 'https://listening.example/logout'));
        $this->signedIn(self::offItsCurve($this->session));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'also-listening', 'https://also-listening.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame(['listening', 'also-listening'], array_map(
            static fn (LogoutTokenIssued $event): string => $event->clientId,
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aSessionEndThatFailsLeavesNoClientForLater(): void
    {
        // Given
        $this->signedIn(self::unreachable($this->session));
        $this->signedIn(Clients::encryptedFor(
            $this->session->tenant,
            ResponseFormat::signed(Algorithms::es256()),
            clientId: 'signed-with-a-missing-key',
            backChannelLogoutUri: new ClientUri('https://missing.example/logout'),
        ));

        // When
        try {
            $this->logout->sessionEnded($this->ended(), Fixtures::context(), new ThePerson());
        } catch (KeyNotFoundException) {
        }

        // Then
        static::assertSame([], $this->retries->later);
    }

    /**
     * Back-Channel Logout 1.0 §2.4
     */
    #[Test]
    public function aClientToldLaterGetsItsLogoutToken(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');

        // When
        $this->logout->tell($client, $this->ended(), Fixtures::context(), new ThePerson());

        // Then
        [$event] = $this->events->of(LogoutTokenIssued::class);
        static::assertSame('first', $event->clientId);
        static::assertSame('https://first.example/logout', $event->logoutUri->value);
        static::assertStringStartsWith('eyJ', $event->token);
    }

    #[Test]
    public function aClientThatNoLongerRegistersAUriIsNotToldLater(): void
    {
        // When
        $this->logout->tell(Clients::public($this->session->tenant, 'silent'), $this->ended(), Fixtures::context(), new ThePerson());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
    }

    private function signedIn(Client $client, string $code = 'code-of-the-client'): void
    {
        $grant = Tokens::code($code . '-' . $client->registration->clientId, $client, $this->session, Fixtures::now());
        $grant->consume(Fixtures::now());
        $this->grants->save($grant);
    }

    private function ended(): AuthenticationSession
    {
        $this->session->end(SessionEnd::RelyingParty, Fixtures::now());

        return $this->session;
    }

    private static function offItsCurve(AuthenticationSession $session): Client
    {
        return Clients::encryptedFor(
            $session->tenant,
            ResponseFormat::signed(null, ClientEncryption::registration()),
            clientId: 'off-its-curve',
            backChannelLogoutUri: new ClientUri('https://off-its-curve.example/logout'),
            jwks: new ClientJwks([ClientEncryption::keyOffItsCurve()]),
        );
    }

    private static function unreachable(AuthenticationSession $session): Client
    {
        return Clients::encryptedFor(
            $session->tenant,
            ResponseFormat::signed(null, ClientEncryption::registration()),
            clientId: 'unreachable',
            jwksUri: new ClientUri('https://unreachable.example/jwks'),
            backChannelLogoutUri: new ClientUri('https://unreachable.example/logout'),
        );
    }
}
