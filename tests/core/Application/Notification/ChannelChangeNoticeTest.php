<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Notification;

use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;
use Beffroi\Core\Tests\Fixture\FakeChannelChangeWindow;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0049
 */
final class ChannelChangeNoticeTest extends TestCase
{
    private RecordingCredentialChangeNotifier $notifier;

    private User $alice;

    protected function setUp(): void
    {
        $this->notifier = new RecordingCredentialChangeNotifier();
        $this->alice = Fixtures::user();
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3
     */
    #[Test]
    public function theChangeThatOpensAWindowIsToldAtOnce(): void
    {
        // Given
        $before = $this->anAddressChanged();

        // When
        $this->notice(new FakeChannelChangeWindow())->tell($before, $this->alice, Fixtures::now());

        // Then
        static::assertEquals([Fixtures::now()], $this->notifier->toldAt);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aChangeAfterItInTheWindowIsToldAtItsEnd(): void
    {
        // Given
        $before = $this->anAddressChanged();

        // When
        $this->notice(new FakeChannelChangeWindow(['+1 hour']))->tell($before, $this->alice, Fixtures::now());

        // Then
        static::assertEquals([Fixtures::now()->modify('+1 hour')], $this->notifier->toldAt);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aChangeTheWindowFoldsIntoAnotherIsNotToldAgain(): void
    {
        // Given
        $before = $this->anAddressChanged();

        // When
        $this->notice(new FakeChannelChangeWindow([null]))->tell($before, $this->alice, Fixtures::now());

        // Then
        static::assertSame([], $this->notifier->told);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function eachChannelIsCountedInAWindowOfItsOwn(): void
    {
        // Given
        $window = new FakeChannelChangeWindow();
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());
        $this->alice->changePhoneNumber('+44 1865 000000', false, Fixtures::now());

        // When
        $this->notice($window)->tell($before, $this->alice, Fixtures::now());

        // Then
        static::assertSame([[$this->alice->id->toRfc4122(), 'email'], [$this->alice->id->toRfc4122(), 'phone_number']], $window->asked);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theNoticeSaysWhichChannelChangedAndWhen(): void
    {
        // Given
        $before = $this->anAddressChanged();
        $moment = new DateTimeImmutable('2026-11-28T10:00:00+00:00');

        // When
        $this->notice(new FakeChannelChangeWindow())->tell($before, $this->alice, $moment);

        // Then
        static::assertEquals(
            [ChannelChangeNotice::ACT, 'email', $moment],
            [$this->notifier->told[0]->act, $this->notifier->told[0]->kind, $this->notifier->told[0]->occurredAt],
        );
    }

    #[Test]
    public function aWriteThatChangesNoChannelTellsNothing(): void
    {
        // Given
        $before = ChannelSnapshot::of($this->alice);

        // When
        $this->notice(new FakeChannelChangeWindow())->tell($before, $this->alice, Fixtures::now());

        // Then
        static::assertSame([], $this->notifier->told);
    }

    private function anAddressChanged(): ChannelSnapshot
    {
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());

        return $before;
    }

    private function notice(FakeChannelChangeWindow $window): ChannelChangeNotice
    {
        return new ChannelChangeNotice($window, $this->notifier);
    }
}
