<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Notification;

use function array_map;
use Beffroi\Core\Application\Notification\ChannelChoice;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Event\NotificationChannelsChosen;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sort;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0050
 */
final class ChannelChoiceTest extends TestCase
{
    private InMemoryUserRepository $users;

    private InMemoryClaimHistory $history;

    private RecordingEventDispatcher $events;

    private WritesAsTheyCome $writes;

    private User $alice;

    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->history = new InMemoryClaimHistory();
        $this->events = new RecordingEventDispatcher();
        $this->writes = new WritesAsTheyCome();
        $this->alice = Fixtures::user();
        $this->users->save($this->alice);
    }

    #[Test]
    public function thePersonHoldsTheChannelsTheyChose(): void
    {
        // Given
        $chosen = new ChosenChannels(['web_push'], ['pending_approval' => ['sms']]);

        // When
        $this->choose($chosen);

        // Then
        static::assertEquals($chosen, $this->users->find($this->alice->id)?->notificationChannels);
    }

    #[Test]
    public function eachChoiceThatChangedIsARowOfTheHistoryThePersonMade(): void
    {
        // Given
        $this->alice->chooseChannels(new ChosenChannels(['mail', 'web_push'], ['pending_approval' => ['sms']]), Fixtures::now());

        // When
        $this->choose(new ChosenChannels(['web_push'], ['pending_approval' => ['sms']]));

        // Then
        static::assertSame([['notification_channels', 'mail web_push', 'web_push', 'person']], $this->rows());
    }

    #[Test]
    public function aKindNoLongerSetApartIsARowThatSaysNothingNow(): void
    {
        // Given
        $this->alice->chooseChannels(new ChosenChannels(null, ['pending_approval' => ['sms']]), Fixtures::now());

        // When
        $this->choose(new ChosenChannels(['mail']));

        // Then
        static::assertSame(
            [
                ['notification_channels',                  null,  'mail', 'person'],
                ['notification_channels.pending_approval', 'sms', null,   'person'],
            ],
            $this->rows(),
        );
    }

    #[Test]
    public function theRowsAndTheRecordAreWrittenInOneUnit(): void
    {
        // When
        $this->choose(new ChosenChannels(['web_push'], ['pending_approval' => ['sms']]));

        // Then
        static::assertSame(1, $this->writes->units);
    }

    #[Test]
    public function theChoiceIsOneActOfThePersonThatNamesWhatChanged(): void
    {
        // When
        $this->choose(new ChosenChannels(['web_push'], ['pending_approval' => ['sms']]));

        // Then
        $acts = $this->events->of(NotificationChannelsChosen::class);
        static::assertCount(1, $acts);
        static::assertSame(
            ['alice-subject', ['notification_channels', 'notification_channels.pending_approval']],
            [$acts[0]->subject()->value, $acts[0]->changed],
        );
    }

    #[Test]
    public function aChoiceThatChangesNothingWritesNothingAndAnnouncesNoAct(): void
    {
        // Given
        $this->alice->chooseChannels(new ChosenChannels(['mail']), Fixtures::now());

        // When
        $this->choose(new ChosenChannels(['mail']));

        // Then
        static::assertSame([[], [], 0], [$this->rows(), $this->events->events, $this->writes->units]);
    }

    private function choose(ChosenChannels $chosen): void
    {
        new ChannelChoice(
            $this->users,
            $this->history,
            $this->writes,
            $this->events,
            new MockClock(Fixtures::now()),
        )->choose($this->alice, $chosen, Fixtures::context());
    }

    /**
     * @return list<array{string, string|null, string|null, string}> each row of the history of the person, by the name of what changed and the kind of its author
     */
    private function rows(): array
    {
        $rows = array_map(
            static fn (ClaimChange $change): array => [$change->claim, $change->was, $change->became, $change->author->kind()],
            $this->history->lastOf($this->alice, 50),
        );
        sort($rows);

        return $rows;
    }
}
