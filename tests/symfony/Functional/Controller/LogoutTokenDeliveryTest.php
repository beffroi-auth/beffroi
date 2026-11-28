<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_column;
use function array_keys;
use function explode;
use Closure;
use App\Http\LogoutTokenSender;
use App\Message\IssueLogoutToken;
use App\Message\LogoutTokenNotification;
use App\Message\SendLogoutToken;
use App\MessageHandler\IssueLogoutTokenHandler;
use App\MessageHandler\SendLogoutTokenHandler;
use App\Messenger\NotificationNotDeliveredException;
use App\Messenger\NotificationRetryPolicy;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use App\Tests\Symfony\Functional\Messenger\LogoutEndpoints;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Back-Channel Logout 1.0 §2.5, §2.8, Architecture §5.6
 */
final class LogoutTokenDeliveryTest extends ConsoleTestCase
{
    private const string URI = 'https://demo.test/backchannel-logout';

    private const string SESSION = '0199a0f2-7c3e-7000-8000-0000000000a1';

    private const string UNREACHABLE = 'unreachable-keys-app';

    private const string TOKEN = 'eyJ0eXAiOiJsb2dvdXQrand0In0.eyJpc3MiOiJodHRwczovL29wLnRlc3QifQ.signature';

    private LogoutEndpoints $endpoints;

    protected function setUp(): void
    {
        $this->endpoints = new LogoutEndpoints([LogoutEndpoints::answering(200)]);
        parent::setUp();
    }

    protected function configureContainer(): Closure
    {
        return $this->endpoints->takeOver(...);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function theLogoutAnswersWithoutWaitingForTheClient(): void
    {
        // Given
        $this->signedInWith('oidc-demo');

        // When
        $this->logOut();

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], $this->endpoints->requests);
        static::assertCount(1, self::queued());
    }

    /**
     * Back-Channel Logout 1.0 §2.5
     */
    #[Test]
    public function theQueuedTokenIsPostedToTheClient(): void
    {
        // Given
        $session = $this->signedInWith('oidc-demo');
        $this->logOut();

        // When
        $this->deliverQueued();

        // Then
        static::assertCount(1, $this->endpoints->requests);
        [$request] = $this->endpoints->requests;
        static::assertSame(self::URI, $request['url']);
        static::assertSame(['application/x-www-form-urlencoded'], $request['headers']['content-type'] ?? []);
        static::assertSame([LogoutTokenSender::PARAMETER], array_keys($request['parameters']));
        static::assertSame($session->id->toRfc4122(), self::claimsOf(self::string($request['parameters'][LogoutTokenSender::PARAMETER]))['sid']);
        static::assertSame([], self::givenUp());
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    public function aClientThatAnswersOkIsDone(): void
    {
        // When
        $this->deliver();

        // Then
        static::assertSame([self::URI], array_column($this->endpoints->requests, 'url'));
        static::assertSame([], self::givenUp());
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    public function aClientThatFailsForItsOwnReasonsIsAskedAgain(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(500)]);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('the client answered 500');

        // When
        $this->deliver();
    }

    #[Test]
    public function aClientThatComesBackTakesTheSameTokenOnTheNextAttempt(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(500), LogoutEndpoints::answering(200)]);
        $message = self::message();
        try {
            self::handler()($message);
        } catch (NotificationNotDeliveredException) {
        }

        // When
        self::handler()($message);

        // Then
        static::assertSame([self::TOKEN, self::TOKEN], array_column(array_column($this->endpoints->requests, 'parameters'), LogoutTokenSender::PARAMETER));
        static::assertSame([], self::givenUp());
    }

    #[Test]
    public function aClientThatNeverAnswersIsAskedAgain(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::timingOut()]);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('the client cannot be reached');

        // When
        $this->deliver();
    }

    /**
     * Back-Channel Logout 1.0 §2.8, Architecture §5.6
     */
    #[Test]
    public function aClientThatNeverComesBackIsAskedAsOftenAsTheLaneAllows(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(503)]);
        self::queue(self::message());

        // When
        self::work();

        // Then
        static::assertCount(self::policy()->attempts(), $this->endpoints->requests);
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    public function aClientTheLaneRunsOutOnIsGivenUpOn(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(503)]);
        self::queue(self::message());

        // When
        self::work();

        // Then
        $events = self::givenUp();
        static::assertCount(1, $events);
        [$givenUp] = $events;
        static::assertSame('oidc-demo', $givenUp->clientId);
        static::assertStringContainsString('the client answered 503', $givenUp->reason);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aClientThatRedirectsIsNotFollowedAndIsGivenUpOn(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::redirectingTo('https://elsewhere.test/logout')]);

        // When
        $this->deliver();

        // Then
        static::assertSame([self::URI], array_column($this->endpoints->requests, 'url'));
        [$givenUp] = self::givenUp();
        static::assertStringContainsString('https://elsewhere.test/logout', $givenUp->reason);
        static::assertSame('oidc-demo', $givenUp->clientId);
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    #[DataProvider('provideFinalRefusals')]
    public function aClientThatRefusesTheTokenIsGivenUpOnAtOnce(int $status): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering($status)]);

        // When
        $this->deliver();

        // Then
        static::assertCount(1, $this->endpoints->requests);
        [$givenUp] = self::givenUp();
        static::assertStringContainsString((string) $status, $givenUp->reason);
        static::assertSame(self::SESSION, $givenUp->sessionId->toRfc4122());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideFinalRefusals(): iterable
    {
        yield 'the request was invalid' => [400];
        yield 'the client does not implement the logout' => [501];
    }

    /**
     * Back-Channel Logout 1.0 §2.4, Architecture §5.6
     */
    #[Test]
    public function aClientWhoseKeyCannotBeObtainedWhenTheSessionEndsIsLeftToTheLane(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        self::signedInWithoutItsKeys($session);

        // When
        $this->logOut();

        // Then
        $queued = self::queued();
        static::assertCount(1, $queued);
        $issue = $queued[0]->getMessage();
        static::assertInstanceOf(IssueLogoutToken::class, $issue);
        static::assertSame(self::UNREACHABLE, $issue->clientId);
        static::assertSame($session->id->toRfc4122(), $issue->sessionId->toRfc4122());
        static::assertSame([], self::events(LogoutTokenIssued::class));
    }

    /**
     * Back-Channel Logout 1.0 §2.4, Architecture §5.6
     */
    #[Test]
    public function aLogoutTokenWhoseKeyNeverComesIsGivenUpOnceTheLaneRunsOut(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        self::queue(self::issue(self::UNREACHABLE, $session->id));

        // When
        self::work();

        // Then
        static::assertSame([], $this->endpoints->requests);
        $events = self::givenUp();
        static::assertCount(1, $events);
        [$givenUp] = $events;
        static::assertSame(self::UNREACHABLE, $givenUp->clientId);
        static::assertStringContainsString('https://unreachable-keys.test/jwks.json', $givenUp->reason);
    }

    /**
     * Back-Channel Logout 1.0 §2.4, §2.5
     */
    #[Test]
    public function aLogoutTokenIssuedLaterReachesItsClientEncrypted(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        self::queue(self::issue('encrypted-app', $session->id));

        // When
        self::work();

        // Then
        static::assertSame(['https://encrypted.test/backchannel-logout'], array_column($this->endpoints->requests, 'url'));
        static::assertCount(5, explode('.', self::string($this->endpoints->requests[0]['parameters'][LogoutTokenSender::PARAMETER])));
        static::assertSame([], self::givenUp());
    }

    #[Test]
    #[DataProvider('provideWhatIsNoLongerKnown')]
    public function aLogoutTokenIsNotIssuedLaterForWhatTheProviderNoLongerKnows(string $clientId, ?string $session): void
    {
        // Given
        $signedIn = $this->signIn(self::user('alice'));
        self::signingKey();

        // When
        self::issueHandler()(self::issue($clientId, $session === null ? $signedIn->id : Uuid::fromString($session)));

        // Then
        static::assertSame([], self::events(LogoutTokenIssued::class));
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideWhatIsNoLongerKnown(): iterable
    {
        yield 'a client the provider no longer serves' => ['retired-app', null];
        yield 'a session the provider no longer holds' => ['encrypted-app', self::SESSION];
    }

    private function deliver(): void
    {
        self::handler()(self::message());
    }

    private static function queue(LogoutTokenNotification $message): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch($message);
    }

    private static function work(): void
    {
        self::mockTime();
        self::console('messenger:consume', [
            'receivers' => ['async_notifications'],
            '--time-limit' => (string) (2 * self::policy()->waiting()),
            '--no-reset' => null,
        ]);
    }

    private static function policy(): NotificationRetryPolicy
    {
        return self::service(NotificationRetryPolicy::class, NotificationRetryPolicy::class);
    }

    private function deliverQueued(): void
    {
        foreach (self::queued() as $envelope) {
            $message = $envelope->getMessage();
            static::assertInstanceOf(SendLogoutToken::class, $message);
            self::handler()($message);
        }
    }

    private function signedInWith(string $clientId): AuthenticationSession
    {
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient($clientId, 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        return $session;
    }

    private function logOut(): void
    {
        $this->browser->submit($this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
        ])->selectButton('Sign out')->form());
    }

    private static function message(): SendLogoutToken
    {
        return new SendLogoutToken(
            self::tenant(),
            'oidc-demo',
            self::URI,
            self::TOKEN,
            Uuid::fromString(self::SESSION),
            new Subject('alice-subject'),
            self::context(),
            new ThePerson(),
        );
    }

    private static function handler(): SendLogoutTokenHandler
    {
        return self::service('test.beffroi.logout_token_delivery', SendLogoutTokenHandler::class);
    }

    private static function issueHandler(): IssueLogoutTokenHandler
    {
        return self::service('test.beffroi.logout_token_issue', IssueLogoutTokenHandler::class);
    }

    private static function issue(string $clientId, Uuid $session): IssueLogoutToken
    {
        return new IssueLogoutToken(self::tenant(), $clientId, $session, new Subject('alice-subject'), self::context(), new ThePerson());
    }

    /**
     * Its keys cannot be read, so it signs in through a code written in the store and not through the token endpoint.
     */
    private static function signedInWithoutItsKeys(AuthenticationSession $session): void
    {
        $session = self::sessionAgain($session);
        $code = Tokens::code('the-code-of-the-unreachable-client', self::client(self::UNREACHABLE), $session, self::now());
        $code->consume(self::now());
        self::service('test.beffroi.authorization_codes', AuthorizationCodeRepositoryInterface::class)->save($code);
    }

    /**
     * @return list<LogoutTokenGivenUp>
     */
    private static function givenUp(): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LogoutTokenGivenUp) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
