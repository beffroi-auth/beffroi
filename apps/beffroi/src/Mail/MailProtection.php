<?php

declare(strict_types=1);

namespace App\Mail;

use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Key\MailSigningKey;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException as CoreRuntimeException;
use Beffroi\Core\Port\MailSigningKeyRepositoryInterface;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Exception\ExceptionInterface as MimeException;
use Symfony\Component\Mime\Message;

/**
 * What a mail becomes before it leaves: signed when the tenant holds a key, in one format, then encrypted to the person
 * who asked for it (RFC 8551 §3.7, RFC 3156 §6.1). The signature is made in the format of the key the person gave when
 * the tenant holds a key of it, otherwise in the first format wired that the tenant holds a key of.
 */
final readonly class MailProtection
{
    /**
     * @param iterable<MailSignerInterface>    $signers    in the order a format signs when the person gave no key
     * @param iterable<MailEncrypterInterface> $encrypters
     */
    public function __construct(
        private iterable $signers,
        private iterable $encrypters,
        private MailSigningKeyRepositoryInterface $keys,
        private OpenedMailSigningKeys $opened,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws NotificationNotDeliveredException when the tenant signs and cannot sign this mail, when the person asked
     *                                           for it encrypted and it cannot be, or when the KMS does not open the
     *                                           signing key
     */
    public function of(User $user, EmailAddress $sender, Email $mail): Message
    {
        return $this->protected($user, $user->mailEncryption, $sender, $mail);
    }

    /**
     * Decision 0049, decision 0051: the notice of a change to the address it replaced, encrypted to what the person gave
     * for that address, which the change took back from her.
     *
     * @throws NotificationNotDeliveredException when the tenant signs and cannot sign this mail, when the person asked
     *                                           for it encrypted and it cannot be, or when the KMS does not open the
     *                                           signing key
     */
    public function ofTheReplaced(User $user, ReplacedChannel $replaced, EmailAddress $sender, Email $mail): Message
    {
        return $this->protected($user, $replaced->mailEncryption, $sender, $mail);
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2, decision 0051: the confirmation of an address, signed as every mail of the tenant and
     * encrypted to no one, since what the person gave names their verified address and not the one it establishes.
     *
     * @throws NotificationNotDeliveredException when the tenant signs and cannot sign this mail, or when the KMS does
     *                                           not open the signing key
     */
    public function ofAConfirmation(User $user, EmailAddress $sender, Email $mail): Message
    {
        return $this->signed($user, $user->mailEncryption, $sender, $mail);
    }

    /**
     * @throws NotificationNotDeliveredException
     */
    private function protected(User $user, ?MailEncryptionKey $encryption, EmailAddress $sender, Email $mail): Message
    {
        return $this->encrypted($user, $encryption, $this->signed($user, $encryption, $sender, $mail));
    }

    /**
     * @param MailEncryptionKey|null $encryption what the person gave, whose format the mail is signed in when the tenant holds a key of it
     *
     * @throws NotificationNotDeliveredException
     */
    private function signed(User $user, ?MailEncryptionKey $encryption, EmailAddress $sender, Email $mail): Message
    {
        [$signer, $key] = $this->signingKey($user, $encryption?->kind);
        if ($signer === null || $key === null) {
            return $mail;
        }
        // A tenant that signs never writes unsigned: a mail of it without its signature is what someone else would write.
        if (! $key->signsFor($sender, $this->clock->now())) {
            throw new NotificationNotDeliveredException(sprintf(
                'The tenant "%s" signs its mail and its %s key %s cannot sign this one: it is past its certificate, or it was set for another sender.',
                $user->tenant->slug,
                $key->kind,
                $key->fingerprint,
            ));
        }
        try {
            return $signer->sign($mail, $key, $this->opened->privateHalfOf($key));
        } catch (KmsUnavailableException $outage) {
            throw new NotificationNotDeliveredException('The KMS did not open the key the mail is signed with (' . $outage::class . ').');
        } catch (CoreRuntimeException|MimeException $refusal) {
            throw new NotificationNotDeliveredException(sprintf(
                'The tenant "%s" signs its mail and its %s key could not sign this one (%s).',
                $user->tenant->slug,
                $key->kind,
                $refusal::class,
            ));
        }
    }

    /**
     * @return array{MailSignerInterface|null, MailSigningKey|null}
     */
    private function signingKey(User $user, ?string $asked): array
    {
        $first = [null, null];
        foreach ($this->signers as $signer) {
            $key = $this->keys->current($user->tenant, $signer->kind());
            if ($key === null) {
                continue;
            }
            if ($signer->kind() === $asked) {
                return [$signer, $key];
            }
            if ($first[0] === null) {
                $first = [$signer, $key];
            }
        }

        return $first;
    }

    /**
     * @throws NotificationNotDeliveredException
     */
    private function encrypted(User $user, ?MailEncryptionKey $key, Message $mail): Message
    {
        if ($key === null) {
            return $mail;
        }
        // Never in clear to a person who asked otherwise: what cannot be encrypted to them is not sent.
        if (! $key->isValidAt($this->clock->now())) {
            throw new NotificationNotDeliveredException(sprintf(
                'A person of the tenant "%s" asked for their mail encrypted, and the %s certificate or key they gave is not valid now.',
                $user->tenant->slug,
                $key->kind,
            ));
        }
        foreach ($this->encrypters as $encrypter) {
            if ($encrypter->kind() !== $key->kind) {
                continue;
            }
            try {
                return $encrypter->encrypt($mail, $key);
            } catch (MimeException $refusal) {
                throw new NotificationNotDeliveredException(sprintf(
                    'A person of the tenant "%s" asked for their mail encrypted, and it could not be encrypted to the %s certificate or key they gave (%s).',
                    $user->tenant->slug,
                    $key->kind,
                    $refusal::class,
                ));
            }
        }

        throw new NotificationNotDeliveredException(sprintf(
            'A person of the tenant "%s" asked for their mail encrypted in the format %s, which this deployment does not write.',
            $user->tenant->slug,
            $key->kind,
        ));
    }
}
