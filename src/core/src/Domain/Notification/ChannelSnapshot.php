<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Notification;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\User;

/**
 * Decision 0049: the address and the number of a person as a write found them, taken before it, so that what it changed
 * of either is still known, with what it replaced, once it is written.
 */
final readonly class ChannelSnapshot
{
    /**
     * OIDC Core §5.1, the claims of the two channels a person holds.
     */
    public const string EMAIL = 'email';

    public const string PHONE_NUMBER = 'phone_number';

    private function __construct(
        private ?EmailAddress $email,
        private bool $emailVerified,
        private ?MailEncryptionKey $mailEncryption,
        private ?string $phoneNumber,
        private bool $phoneNumberVerified,
    ) {
    }

    public static function of(User $user): self
    {
        return new self($user->email, $user->emailVerified, $user->mailEncryption, $user->phoneNumber, $user->phoneNumberVerified);
    }

    /**
     * A channel changes with its value, never with its verification alone; what it replaced is told only when it was
     * verified, a channel nobody verified receiving nothing.
     *
     * @return array<string, ReplacedChannel|null> by the claim of each channel the write changed, the address first
     */
    public function changedIn(User $user): array
    {
        $changed = [];
        if ($this->email?->value !== $user->email?->value) {
            $changed[self::EMAIL] = $this->emailVerified && $this->email !== null
                ? ReplacedChannel::address($this->email, $this->mailEncryption)
                : null;
        }
        if ($this->phoneNumber !== $user->phoneNumber) {
            $changed[self::PHONE_NUMBER] = $this->phoneNumberVerified && $this->phoneNumber !== null
                ? ReplacedChannel::number($this->phoneNumber)
                : null;
        }

        return $changed;
    }
}
