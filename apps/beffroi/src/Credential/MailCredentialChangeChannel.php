<?php

declare(strict_types=1);

namespace App\Credential;

use App\Mail\MailSender;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Identity\User;

/**
 * NIST SP 800-63B-4 §4.6
 */
final readonly class MailCredentialChangeChannel implements CredentialChangeChannelInterface
{
    public function __construct(
        private CredentialChangeNotices $notices,
        private MailSender $sender,
    ) {
    }

    public function name(): string
    {
        return MailSender::CHANNEL;
    }

    public function tell(User $user, CredentialChange $change): void
    {
        $notice = $this->notices->of($user, $change);
        $this->sender->send($user, $notice->subject, $notice->mailText());
    }
}
