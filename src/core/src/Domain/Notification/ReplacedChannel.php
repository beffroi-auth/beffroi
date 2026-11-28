<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Notification;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;

/**
 * Decision 0049: an address or a number a change took from a person while she held it verified, which the notice of
 * the change still reaches once the change is written.
 */
final readonly class ReplacedChannel
{
    /**
     * @param string                 $claim          the claim of the channel, OIDC Core §5.1
     * @param MailEncryptionKey|null $mailEncryption what mail to the address was encrypted to, which the change took back
     */
    private function __construct(
        public string $claim,
        public string $value,
        public ?MailEncryptionKey $mailEncryption,
    ) {
    }

    public static function address(EmailAddress $address, ?MailEncryptionKey $mailEncryption): self
    {
        return new self(ChannelSnapshot::EMAIL, $address->value, $mailEncryption);
    }

    public static function number(string $number): self
    {
        return new self(ChannelSnapshot::PHONE_NUMBER, $number, null);
    }
}
