<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\CredentialChangeChannelInterface;
use App\Credential\CredentialChangeChannels;
use App\Credential\QueuedCredentialChangeNotifier;
use App\Credential\ReplacedChannelInterface;
use App\Message\TellUserOfCredentialChange;
use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DelayStamp;

/**
 * NIST SP 800-63B-4 §4.6, Architecture §5.6
 */
final class QueuedCredentialChangeNotifierTest extends TestCase
{
    /**
     * @var list<object>
     */
    private array $dispatched = [];

    /**
     * @var list<array<mixed>> the stamps each message was dispatched with
     */
    private array $stamps = [];

    #[Test]
    public function eachChannelIsHandedANoticeOfItsOwn(): void
    {
        // Given
        $change = new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey');

        // When
        $this->notifier(['web_push', 'mail', 'sms'])->tell($change);

        // Then
        static::assertEquals(
            [
                new TellUserOfCredentialChange($change, 'web_push'),
                new TellUserOfCredentialChange($change, 'mail'),
                new TellUserOfCredentialChange($change, 'sms'),
            ],
            $this->dispatched,
        );
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function aChangeThatReplacedAChannelHandsTheChannelsThatReachItANoticeOfTheirOwn(): void
    {
        // Given
        $change = new CredentialChange(
            Fixtures::user(),
            ChannelChangeNotice::ACT,
            Fixtures::now(),
            'email',
            ReplacedChannel::address(new EmailAddress('alice@acme.example'), null),
        );

        // When
        $this->notifier(['mail', 'sms'], ['email' => 'replaced_address', 'phone_number' => 'replaced_number'])->tell($change);

        // Then
        static::assertEquals(
            [
                new TellUserOfCredentialChange($change, 'mail'),
                new TellUserOfCredentialChange($change, 'sms'),
                new TellUserOfCredentialChange($change, 'replaced_address'),
            ],
            $this->dispatched,
        );
    }

    /**
     * Decision 0048, decision 0049
     */
    #[Test]
    public function aChangeThatReplacedNothingVerifiedHandsNothingToTheChannelsOfAReplacedOne(): void
    {
        // Given
        $change = new CredentialChange(Fixtures::user(), ChannelChangeNotice::ACT, Fixtures::now(), 'email');

        // When
        $this->notifier(['mail'], ['email' => 'replaced_address'])->tell($change);

        // Then
        static::assertEquals([new TellUserOfCredentialChange($change, 'mail')], $this->dispatched);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aNoticeToldLaterWaitsOnTheLaneUntilThen(): void
    {
        // Given
        $change = new CredentialChange(Fixtures::user(), ChannelChangeNotice::ACT, Fixtures::now(), 'email');

        // When
        $this->notifier(['mail'])->tell($change, Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertEquals([[new DelayStamp(3_600_000)]], $this->stamps);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aNoticeToldNowWaitsForNothing(): void
    {
        // Given
        $change = new CredentialChange(Fixtures::user(), ChannelChangeNotice::ACT, Fixtures::now(), 'email');

        // When
        $this->notifier(['mail'])->tell($change, Fixtures::now());

        // Then
        static::assertSame([[]], $this->stamps);
    }

    #[Test]
    public function aDeploymentWithoutChannelsQueuesNothing(): void
    {
        // When
        $this->notifier([])->tell(new CredentialChange(Fixtures::user(), CredentialEnrolled::NAME, Fixtures::now(), 'passkey'));

        // Then
        static::assertSame([], $this->dispatched);
    }

    /**
     * @param list<string>          $names
     * @param array<string, string> $replacing the name of the channel that reaches each claim once replaced
     */
    private function notifier(array $names, array $replacing = []): QueuedCredentialChangeNotifier
    {
        $bus = self::createStub(MessageBusInterface::class);
        $bus->method('dispatch')->willReturnCallback(function (object $message, array $stamps = []): Envelope {
            $this->dispatched[] = $message;
            $this->stamps[] = $stamps;

            return new Envelope($message);
        });
        $channels = [];
        foreach ($names as $name) {
            $channel = self::createStub(CredentialChangeChannelInterface::class);
            $channel->method('name')->willReturn($name);
            $channels[] = $channel;
        }
        foreach ($replacing as $claim => $name) {
            $channel = self::createStub(ReplacedChannelInterface::class);
            $channel->method('name')->willReturn($name);
            $channel->method('claim')->willReturn($claim);
            $channels[] = $channel;
        }

        return new QueuedCredentialChangeNotifier($bus, new CredentialChangeChannels($channels), new MockClock(Fixtures::now()));
    }
}
