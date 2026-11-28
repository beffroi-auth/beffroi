<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use function array_map;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Application\Identity\PersonDisabling;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\PersonDisabled;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Clock\MockClock;

/**
 * Decisions 0038 and 0066
 */
final class PersonDisablingTest extends TestCase
{
    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
    }

    #[Test]
    public function aDisabledPersonIsNoLongerEnabled(): void
    {
        // When
        $this->disabling()->disable($this->alice, new TheHost(), Fixtures::context());

        // Then
        static::assertSame([false, $this->clock->now()->getTimestamp()], [$this->alice->isEnabled(), $this->alice->disabledAt?->getTimestamp()]);
    }

    #[Test]
    public function everySessionOfThePersonEnds(): void
    {
        // Given
        $here = $this->signedIn();
        $there = $this->signedIn();

        // When
        $ended = $this->disabling()->disable($this->alice, new TheHost(), Fixtures::context());

        // Then
        static::assertSame([2, true, true], [$ended, $here->hasEnded(), $there->hasEnded()]);
    }

    #[Test]
    public function theAccountIsDisabledBeforeAnySessionEnds(): void
    {
        // Given
        $this->signedIn();
        $alice = $this->alice;
        $events = new class($alice) implements EventDispatcherInterface {
            /**
             * @var list<bool> whether the person was enabled when each session ended
             */
            public array $seen = [];

            public function __construct(
                private readonly User $user,
            ) {
            }

            public function dispatch(object $event): object
            {
                if ($event instanceof AuthenticationSessionEnded) {
                    $this->seen[] = $this->user->isEnabled();
                }

                return $event;
            }
        };

        // When
        new PersonDisabling(
            new InMemoryUserRepository(),
            new OtherSessionsTermination($this->sessions, new SessionTerminator($this->sessions, $this->clock, $events)),
            $events,
            $this->clock,
        )->disable($alice, new TheHost(), Fixtures::context());

        // Then
        static::assertSame([false], $events->seen);
    }

    #[Test]
    public function theDisabledAccountIsSaved(): void
    {
        // Given
        $users = $this->createMock(UserRepositoryInterface::class);

        // Then
        $users->expects(static::once())->method('save')->with($this->alice);

        // When
        $this->disabling($users)->disable($this->alice, new TheHost(), Fixtures::context());
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theDisablingAndTheEndOfEachSessionNameItsAuthor(AuthorInterface $author): void
    {
        // Given
        $session = $this->signedIn();

        // When
        $this->disabling()->disable($this->alice, $author, Fixtures::context());

        // Then
        static::assertSame(
            [[$author], [$author], SessionEnd::Administrator],
            [
                array_map(static fn (PersonDisabled $act): AuthorInterface => $act->author(), $this->events->of(PersonDisabled::class)),
                array_map(static fn (AuthenticationSessionEnded $act): AuthorInterface => $act->author(), $this->events->of(AuthenticationSessionEnded::class)),
                $session->endedBy,
            ],
        );
    }

    /**
     * @return iterable<string, array{AuthorInterface}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the host' => [new TheHost()];
        yield 'an administrator' => [new AnAdministrator(new Subject('administrator-subject'))];
        yield 'a directory' => [new ADirectory('Entra ID')];
    }

    #[Test]
    public function aPersonDisabledAlreadyIsLeftAsTheyAre(): void
    {
        // Given
        $since = $this->clock->now()->modify('-1 day');
        $this->alice->disable($since);
        $session = $this->signedIn();

        // When
        $ended = $this->disabling()->disable($this->alice, new TheHost(), Fixtures::context());

        // Then
        static::assertSame([null, $since, false, []], [$ended, $this->alice->disabledAt, $session->hasEnded(), $this->events->events]);
    }

    private function disabling(?UserRepositoryInterface $users = null): PersonDisabling
    {
        return new PersonDisabling(
            $users ?? new InMemoryUserRepository(),
            new OtherSessionsTermination($this->sessions, new SessionTerminator($this->sessions, $this->clock, $this->events)),
            $this->events,
            $this->clock,
        );
    }

    private function signedIn(): AuthenticationSession
    {
        $session = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($session);

        return $session;
    }
}
