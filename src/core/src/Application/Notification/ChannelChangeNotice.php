<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Notification;

use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;
use Beffroi\Core\Port\ChannelChangeWindowInterface;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;
use DateTimeImmutable;

/**
 * Decision 0049, NIST SP 800-63A-4 §5.3: a change of the address or of the number of a person is told to every channel
 * of hers and to the one it replaced, whoever wrote it. Called by every write that changes either, once it is written.
 */
final readonly class ChannelChangeNotice
{
    public const string ACT = 'channel.changed';

    public function __construct(
        private ChannelChangeWindowInterface $window,
        private CredentialChangeNotifierInterface $notifier,
    ) {
    }

    public function tell(ChannelSnapshot $before, User $after, DateTimeImmutable $at): void
    {
        foreach ($before->changedIn($after) as $claim => $replaced) {
            $toldAt = $this->window->toldAt($after, $claim, $at);
            if ($toldAt !== null) {
                $this->notifier->tell(new CredentialChange($after, self::ACT, $at, $claim, $replaced), $toldAt);
            }
        }
    }
}
