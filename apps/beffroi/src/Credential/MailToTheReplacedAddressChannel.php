<?php

declare(strict_types=1);

namespace App\Credential;

use App\Mail\MailSender;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;

/**
 * Decision 0049, CNIL délibération n° 2022-100 point 55
 */
final readonly class MailToTheReplacedAddressChannel implements ReplacedChannelInterface
{
    public const string NAME = 'replaced_address';

    public function __construct(
        private CredentialChangeNotices $notices,
        private MailSender $sender,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function claim(): string
    {
        return ChannelSnapshot::EMAIL;
    }

    public function tell(User $user, CredentialChange $change): void
    {
        $replaced = $change->replaced;
        if ($replaced === null) {
            return;
        }
        $notice = $this->notices->of($user, $change);
        $this->sender->sendToTheReplaced($user, $replaced, $notice->subject, $notice->mailText());
    }
}
