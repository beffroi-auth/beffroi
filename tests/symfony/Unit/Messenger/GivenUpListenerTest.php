<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use App\Message\AdvanceKeyLifecycle;
use App\Message\IssueLogoutToken;
use App\Message\SendLogoutToken;
use App\Message\TellUserOfCredentialChange;
use App\Messenger\GivenUpListener;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialChangeNotTold;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Event\WorkerMessageFailedEvent;
use Symfony\Component\Uid\Uuid;

final class GivenUpListenerTest extends TestCase
{
    private const string SESSION = '0199a0f2-7c3e-7000-8000-0000000000a1';

    private RecordingEventDispatcher $events;

    private GivenUpListener $listener;

    protected function setUp(): void
    {
        $this->events = new RecordingEventDispatcher();
        $this->listener = new GivenUpListener($this->events, new MockClock(Fixtures::now()));
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    public function aLogoutTokenTheTransportGivesUpOnIsAnnounced(): void
    {
        // When
        ($this->listener)(self::failure(self::logoutToken(), willRetry: false));

        // Then
        [$givenUp] = $this->events->of(LogoutTokenGivenUp::class);
        static::assertSame('oidc-demo', $givenUp->clientId);
        static::assertSame(self::SESSION, $givenUp->sessionId->toRfc4122());
        static::assertSame('the client answered 503', $givenUp->reason);
        static::assertSame(Fixtures::now()->getTimestamp(), $givenUp->occurredAt->getTimestamp());
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    public function aLogoutTokenWhoseIssueTheTransportGivesUpOnIsAnnounced(): void
    {
        // When
        ($this->listener)(self::failure(new IssueLogoutToken(
            Fixtures::tenant(),
            'encrypted-app',
            Uuid::fromString(self::SESSION),
            Fixtures::user()->subject,
            Fixtures::context(),
            new ThePerson(),
        ), willRetry: false));

        // Then
        [$givenUp] = $this->events->of(LogoutTokenGivenUp::class);
        static::assertSame('encrypted-app', $givenUp->clientId);
        static::assertSame(self::SESSION, $givenUp->sessionId->toRfc4122());
        static::assertSame('the client answered 503', $givenUp->reason);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aLogoutTokenOfASessionAnAdministratorEndedIsGivenUpInTheirName(): void
    {
        // When
        ($this->listener)(self::failure(new IssueLogoutToken(
            Fixtures::tenant(),
            'encrypted-app',
            Uuid::fromString(self::SESSION),
            Fixtures::user()->subject,
            Fixtures::context(),
            new AnAdministrator(new Subject('administrator-subject')),
        ), willRetry: false));

        // Then
        [$givenUp] = $this->events->of(LogoutTokenGivenUp::class);
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $givenUp->author());
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aNoticeOfAChangeTheTransportGivesUpOnIsAnActOfThePerson(): void
    {
        // When
        ($this->listener)(self::failure(self::notice(), willRetry: false));

        // Then
        [$notTold] = $this->events->of(CredentialChangeNotTold::class);
        static::assertSame('alice-subject', $notTold->subject->value);
        static::assertSame(CredentialEnrolled::NAME, $notTold->act);
        static::assertSame('mail', $notTold->channel);
        static::assertSame('the client answered 503', $notTold->reason);
        static::assertSame(Fixtures::now()->getTimestamp(), $notTold->occurredAt->getTimestamp());
    }

    #[Test]
    public function aNoticeGivenUpOnComesFromNoAddress(): void
    {
        // When
        ($this->listener)(self::failure(self::notice(), willRetry: false));

        // Then
        [$notTold] = $this->events->of(CredentialChangeNotTold::class);
        static::assertSame([null, null], [$notTold->context->ipAddress, $notTold->context->userAgent]);
    }

    #[Test]
    public function aFailureThatWillBeTriedAgainIsNotAnnounced(): void
    {
        // When
        ($this->listener)(self::failure(self::notice(), willRetry: true));

        // Then
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aMessageWhoseGivingUpIsNoActAnnouncesNothing(): void
    {
        // When
        ($this->listener)(self::failure(new AdvanceKeyLifecycle(), willRetry: false));

        // Then
        static::assertSame([], $this->events->events);
    }

    private static function logoutToken(): SendLogoutToken
    {
        return new SendLogoutToken(
            Fixtures::tenant(),
            'oidc-demo',
            'https://demo.test/backchannel-logout',
            'a.logout.token',
            Uuid::fromString(self::SESSION),
            Fixtures::user()->subject,
            Fixtures::context(),
            new ThePerson(),
        );
    }

    private static function notice(): TellUserOfCredentialChange
    {
        return new TellUserOfCredentialChange(new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey'), 'mail');
    }

    private static function failure(object $message, bool $willRetry): WorkerMessageFailedEvent
    {
        $event = new WorkerMessageFailedEvent(new Envelope($message), 'async_notifications', new RuntimeException('the client answered 503'));
        if ($willRetry) {
            $event->setForRetry();
        }

        return $event;
    }
}
