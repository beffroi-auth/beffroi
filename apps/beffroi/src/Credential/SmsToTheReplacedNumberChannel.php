<?php

declare(strict_types=1);

namespace App\Credential;

use App\Sms\SmsSender;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;

/**
 * Decision 0049, CNIL délibération n° 2022-100 point 55
 */
final readonly class SmsToTheReplacedNumberChannel implements ReplacedChannelInterface
{
    public const string NAME = 'replaced_number';

    public function __construct(
        private CredentialChangeNotices $notices,
        private SmsSender $sender,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function claim(): string
    {
        return ChannelSnapshot::PHONE_NUMBER;
    }

    public function tell(User $user, CredentialChange $change): void
    {
        $replaced = $change->replaced;
        if ($replaced === null) {
            return;
        }
        $this->sender->sendToTheReplaced($user, $replaced, $this->notices->of($user, $change)->text());
    }
}
