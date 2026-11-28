<?php

declare(strict_types=1);

namespace App\Credential;

use App\Message\TellUserOfCredentialChange;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DelayStamp;

final readonly class QueuedCredentialChangeNotifier implements CredentialChangeNotifierInterface
{
    public function __construct(
        private MessageBusInterface $commandBus,
        private CredentialChangeChannels $channels,
        private ClockInterface $clock,
    ) {
    }

    /**
     * NIST SP 800-63B-4 §4.6, decision 0049
     *
     * A notice per channel, the one a change replaced included: the lane brings a failed message back whole, so a
     * channel that failed is tried again on its own and one that reached the person is not.
     */
    public function tell(CredentialChange $change, ?DateTimeImmutable $at = null): void
    {
        $channels = $this->channels->names();
        if ($change->replaced !== null) {
            $channels = [...$channels, ...$this->channels->reaching($change->replaced->claim)];
        }
        $stamps = $this->delayedTo($at);
        foreach ($channels as $channel) {
            $this->commandBus->dispatch(new TellUserOfCredentialChange($change, $channel), $stamps);
        }
    }

    /**
     * @return list<DelayStamp>
     */
    private function delayedTo(?DateTimeImmutable $at): array
    {
        if ($at === null) {
            return [];
        }
        $seconds = $at->getTimestamp() - $this->clock->now()->getTimestamp();

        return $seconds > 0 ? [new DelayStamp($seconds * 1000)] : [];
    }
}
