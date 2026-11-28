<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class SessionTerminatorTest extends TestCase
{
    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private AuthenticationSession $kept;

    private AuthenticationSession $ended;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private SessionTerminator $terminator;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->kept = Fixtures::session($this->alice);
        $this->ended = Fixtures::session($this->alice);
        $this->sessions->save($this->kept);
        $this->sessions->save($this->ended);
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now(), '198.51.100.7');
        $this->terminator = new SessionTerminator($this->sessions, $this->clock, $this->events);
    }

    #[Test]
    public function itEndsTheSessionNow(): void
    {
        // When
        $this->terminator->end($this->ended, SessionEnd::User, new ThePerson(), $this->context);

        // Then
        static::assertTrue($this->ended->hasEnded());
        static::assertSame(SessionEnd::User, $this->ended->endedBy);
        static::assertEquals($this->clock->now(), $this->ended->endedAt);
    }

    #[Test]
    public function itSavesTheEndedSessionAndLeavesTheOthersActive(): void
    {
        // Given
        $savesBefore = $this->sessions->saves;

        // When
        $this->terminator->end($this->ended, SessionEnd::User, new ThePerson(), $this->context);

        // Then
        static::assertSame($savesBefore + 1, $this->sessions->saves);
        static::assertSame([$this->kept], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function itAnnouncesTheEndWithTheContextOfTheRequest(): void
    {
        // When
        $this->terminator->end($this->ended, SessionEnd::User, new ThePerson(), $this->context);

        // Then
        static::assertCount(1, $this->events->events);
        $event = $this->events->of(AuthenticationSessionEnded::class)[0];
        static::assertSame($this->ended, $event->session);
        static::assertSame($this->context, $event->context);
        static::assertEquals($this->clock->now(), $event->occurredAt);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theEndAnAdministratorMadeNamesThemInItsAct(): void
    {
        // Given
        $administrator = new Subject('administrator-subject');

        // When
        $this->terminator->endByAnAdministrator($this->ended, $administrator, $this->context);

        // Then
        static::assertEquals(
            [SessionEnd::Administrator, new AnAdministrator($administrator)],
            [$this->ended->endedBy, $this->events->of(AuthenticationSessionEnded::class)[0]->author()],
        );
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theEndNamesItsAuthorInItsAct(AuthorInterface $author): void
    {
        // When
        $this->terminator->end($this->ended, SessionEnd::User, $author, $this->context);

        // Then
        static::assertSame($author, $this->events->of(AuthenticationSessionEnded::class)[0]->author());
    }

    /**
     * @return iterable<string, array{AuthorInterface}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the person' => [new ThePerson()];
        yield 'the host' => [new TheHost()];
        yield 'a directory' => [new ADirectory('Entra ID')];
    }

    #[Test]
    public function endingAnEndedSessionAgainChangesNothing(): void
    {
        // Given
        $this->terminator->end($this->ended, SessionEnd::User, new ThePerson(), $this->context);
        $savesBefore = $this->sessions->saves;

        // When
        $this->terminator->end($this->ended, SessionEnd::Administrator, new TheHost(), $this->context);

        // Then
        static::assertSame(SessionEnd::User, $this->ended->endedBy);
        static::assertSame($savesBefore, $this->sessions->saves);
        static::assertCount(1, $this->events->events);
    }
}
