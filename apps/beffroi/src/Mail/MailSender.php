<?php

declare(strict_types=1);

namespace App\Mail;

use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Exception\InvalidArgumentException;
use Closure;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use function sprintf;
use Symfony\Component\Mailer\Exception\ExceptionInterface as MailerException;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Exception\ExceptionInterface as MimeException;
use Symfony\Component\Mime\Message;

/**
 * Writes to the address of a person once it is verified, and to no other, but for the confirmation that establishes
 * an address, which goes to that address before it is verified (decision 0048), and for the notice of a change, which
 * goes to the address it replaced as well while the person held it verified (decision 0049).
 */
final readonly class MailSender
{
    public const string CHANNEL = 'mail';

    /**
     * @param Closure(): TransportInterface $transport built at the first mail, so that a DSN no installed factory reads
     *                                                 fails the mail alone and never the channels beside it
     * @param ?string $sender an address, alone or behind a name; none writes no mail
     */
    public function __construct(
        private Closure $transport,
        private ?string $sender,
        private MailProtection $protection,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * @return bool false for a person who has no address this sender may write to, or when the deployment cannot write
     *              a mail at all, and who is sent nothing
     *
     * @throws NotificationNotDeliveredException when the transport did not take the mail, or when the mail cannot be
     *                                           signed or encrypted as it must be
     */
    public function send(User $user, string $subject, string $text): bool
    {
        $verified = $user->verifiedEmail();
        if ($verified === null) {
            return false;
        }

        return $this->write($user, $verified->value, $subject, $text, $this->protection->of(...));
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55: the notice of a change goes to the address it replaced,
     * which the person held verified before it, encrypted to what mail to that address was encrypted to.
     *
     * @return bool false for a channel that is not an address, or when the deployment cannot write a mail at all, and
     *              which is sent nothing
     *
     * @throws NotificationNotDeliveredException when the transport did not take the mail, or when the mail cannot be
     *                                           signed or encrypted as it must be
     */
    public function sendToTheReplaced(User $user, ReplacedChannel $replaced, string $subject, string $text): bool
    {
        if ($replaced->claim !== ChannelSnapshot::EMAIL) {
            return false;
        }

        return $this->write(
            $user,
            $replaced->value,
            $subject,
            $text,
            fn (User $user, EmailAddress $sender, Email $mail): Message => $this->protection->ofTheReplaced($user, $replaced, $sender, $mail),
        );
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2: the confirmation goes to the address it establishes while the person holds it,
     * verified or not, and to no other.
     *
     * It is signed as every mail of the tenant, and encrypted to no one (`MailProtection::ofAConfirmation()`).
     *
     * @return bool false for a person who no longer holds that address, or when the deployment cannot write a mail at
     *              all, and who is sent nothing
     *
     * @throws NotificationNotDeliveredException when the transport did not take the mail, or when the mail cannot be
     *                                           signed as it must be
     */
    public function sendTheConfirmation(User $user, string $address, string $subject, #[SensitiveParameter] string $text): bool
    {
        $held = $user->email;
        if ($held === null || $held->value !== $address) {
            return false;
        }

        return $this->write($user, $held->value, $subject, $text, $this->protection->ofAConfirmation(...));
    }

    /**
     * @param Closure(User, EmailAddress, Email): Message $protect what the mail becomes before it leaves, from the
     *                                                        person and the sender
     *
     * @throws NotificationNotDeliveredException
     */
    private function write(User $user, string $to, string $subject, #[SensitiveParameter] string $text, Closure $protect): bool
    {
        try {
            $recipient = new Address($to);
        } catch (MimeException $refusal) {
            $this->logger->warning('An address of the person is not one a mail can carry.', [
                'tenant' => $user->tenant->slug,
                'reason' => $refusal::class,
            ]);

            return false;
        }
        try {
            $transport = ($this->transport)();
            $sender = Address::create($this->sender ?? '');
            $from = new EmailAddress($sender->getAddress());
        } catch (MailerException|MimeException|InvalidArgumentException $fault) {
            // No later attempt would write it: the deployment names a transport or a sender that cannot be.
            $this->logger->error('This deployment writes no mail: {reason}', [
                'reason' => $fault->getMessage(),
            ]);

            return false;
        }
        $mail = new Email()
            ->from($sender)
            ->to($recipient)
            ->subject($subject)
            ->text($text);
        // RFC 3834 §5.2, §2: a process wrote it, and an automatic responder that reads it answers nothing back.
        $mail->getHeaders()->addTextHeader('Auto-Submitted', 'auto-generated');
        $protected = $protect($user, $from, $mail);
        try {
            $transport->send($protected);
        } catch (TransportExceptionInterface $refusal) {
            // Never what the server said: it may write back the address it refused, which the lane keeps in clear.
            throw new NotificationNotDeliveredException(sprintf(
                'The mail transport did not take the message (%s, code %d).',
                $refusal::class,
                $refusal->getCode(),
            ));
        }

        return true;
    }
}
