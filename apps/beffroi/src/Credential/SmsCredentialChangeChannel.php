<?php

declare(strict_types=1);

namespace App\Credential;

use App\Sms\SmsSender;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Identity\User;

/**
 * NIST SP 800-63B-4 §4.6
 */
final readonly class SmsCredentialChangeChannel implements CredentialChangeChannelInterface
{
    public function __construct(
        private CredentialChangeNotices $notices,
        private SmsSender $sender,
    ) {
    }

    public function name(): string
    {
        return SmsSender::CHANNEL;
    }

    public function tell(User $user, CredentialChange $change): void
    {
        $notice = $this->notices->of($user, $change);
        $this->sender->send($user, $notice->text());
    }
}
