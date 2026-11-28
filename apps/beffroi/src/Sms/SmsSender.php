<?php

declare(strict_types=1);

namespace App\Sms;

use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Closure;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use function sprintf;
use Symfony\Component\Notifier\Exception\ExceptionInterface as NotifierException;
use Symfony\Component\Notifier\Exception\TransportExceptionInterface;
use Symfony\Component\Notifier\Message\SmsMessage;
use Symfony\Component\Notifier\Transport\TransportInterface;

/**
 * Texts the number of a person once it is verified, and no other, but for the confirmation that establishes a
 * number, which goes to that number before it is verified (decision 0048), and for the notice of a change, which goes
 * to the number it replaced as well while the person held it verified (decision 0049).
 */
final readonly class SmsSender
{
    public const string CHANNEL = 'sms';

    /**
     * @param Closure(): TransportInterface $transport built at the first text, so that a DSN no installed bridge reads
     *                                                 fails the text alone and never the channels beside it
     */
    public function __construct(
        private Closure $transport,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * @return bool false for a person who has no number this sender may text, or when the deployment cannot send a
     *              text at all, and who is sent nothing
     *
     * @throws NotificationNotDeliveredException when the transport did not take the text
     */
    public function send(User $user, string $text): bool
    {
        $verified = $user->verifiedPhoneNumber();
        if ($verified === null) {
            return false;
        }

        return $this->text($user, $verified, $text);
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55: the notice of a change goes to the number it replaced,
     * which the person held verified before it.
     *
     * @return bool false for a channel that is not a number, or when the deployment cannot send a text at all, and
     *              which is sent nothing
     *
     * @throws NotificationNotDeliveredException when the transport did not take the text
     */
    public function sendToTheReplaced(User $user, ReplacedChannel $replaced, string $text): bool
    {
        if ($replaced->claim !== ChannelSnapshot::PHONE_NUMBER) {
            return false;
        }

        return $this->text($user, $replaced->value, $text);
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2: the confirmation goes to the number it establishes while the person holds it,
     * verified or not, and to no other.
     *
     * @return bool false for a person who no longer holds that number, or when the deployment cannot send a text at
     *              all, and who is sent nothing
     *
     * @throws NotificationNotDeliveredException when the transport did not take the text
     */
    public function sendTheConfirmation(User $user, string $number, #[SensitiveParameter] string $text): bool
    {
        if ($user->phoneNumber !== $number) {
            return false;
        }

        return $this->text($user, $number, $text);
    }

    /**
     * @throws NotificationNotDeliveredException
     */
    private function text(User $user, string $number, #[SensitiveParameter] string $text): bool
    {
        try {
            $transport = ($this->transport)();
        } catch (NotifierException $fault) {
            // No later attempt would send it: the deployment names a transport no installed bridge reads.
            $this->logger->error('This deployment sends no text: {reason}', [
                'reason' => $fault->getMessage(),
            ]);

            return false;
        }
        try {
            $transport->send(new SmsMessage($number, $text));
        } catch (TransportExceptionInterface $refusal) {
            // Never what the provider said: it may write back the number it refused, which the lane keeps in clear.
            throw new NotificationNotDeliveredException(sprintf('The SMS transport did not take the message (%s).', $refusal::class));
        } catch (NotifierException $refusal) {
            $this->logger->error('A text was refused before it left.', [
                'tenant' => $user->tenant->slug,
                'reason' => $refusal::class,
            ]);

            return false;
        }

        return true;
    }
}
