<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use function array_map;
use Beffroi\Core\Application\Identity\PersonEnabling;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Event\PersonEnabled;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Decisions 0038 and 0066
 */
final class PersonEnablingTest extends TestCase
{
    private User $alice;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    protected function setUp(): void
    {
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->alice = Fixtures::user();
        $this->alice->disable($this->clock->now()->modify('-1 day'));
        $this->events = new RecordingEventDispatcher();
    }

    #[Test]
    public function anEnabledPersonMaySignInAgain(): void
    {
        // When
        $this->enabling()->enable($this->alice, new TheHost(), Fixtures::context());

        // Then
        static::assertSame([true, null], [$this->alice->isEnabled(), $this->alice->disabledAt]);
    }

    #[Test]
    public function theEnabledAccountIsSaved(): void
    {
        // Given
        $users = $this->createMock(UserRepositoryInterface::class);

        // Then
        $users->expects(static::once())->method('save')->with($this->alice);

        // When
        $this->enabling($users)->enable($this->alice, new TheHost(), Fixtures::context());
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theEnablingIsAnActThatNamesItsAuthor(AuthorInterface $author): void
    {
        // When
        $this->enabling()->enable($this->alice, $author, Fixtures::context());

        // Then
        static::assertSame([['alice-subject', $author]], array_map(
            static fn (PersonEnabled $act): array => [$act->subject()->value, $act->author()],
            $this->events->of(PersonEnabled::class),
        ));
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
    public function aPersonEnabledAlreadyIsLeftAsTheyAre(): void
    {
        // Given
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');

        // When
        $enabled = $this->enabling()->enable($bob, new TheHost(), Fixtures::context());

        // Then
        static::assertSame([false, []], [$enabled, $this->events->events]);
    }

    private function enabling(?UserRepositoryInterface $users = null): PersonEnabling
    {
        return new PersonEnabling($users ?? new InMemoryUserRepository(), $this->events, $this->clock);
    }
}
