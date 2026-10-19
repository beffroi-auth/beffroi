<?php

declare(strict_types=1);

namespace App\Lead;

use App\Entity\Lead;
use App\Repository\LeadRepository;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;

/**
 * Records a sign-up and confirms it by email.
 *
 * One lead per email address: signing up again updates the lead and sends no second confirmation, so the form never
 * mails the same address twice, and its answer is the same whether the address was known or not. A confirmation that
 * could not be sent is logged and tried again at the next sign-up of that address; the sign-up itself is kept.
 */
final readonly class Registration
{
    public function __construct(
        private LeadRepository $leads,
        private EntityManagerInterface $entityManager,
        private MailerInterface $mailer,
        private ClockInterface $clock,
        private LoggerInterface $logger,
        #[Autowire('%app.mail_from%')]
        private string $mailFrom,
    ) {
    }

    public function register(LeadRequest $request, string $source): Lead
    {
        $email = mb_strtolower(trim((string) $request->email));
        $firstName = trim((string) $request->firstName);
        $lastName = trim((string) $request->lastName);
        $company = self::optional($request->company);
        $provider = $request->provider ?? throw new \LogicException('A validated sign-up names a provider.');
        $providerOther = self::optional($request->providerOther);
        $now = $this->clock->now();

        $lead = $this->leads->findOneByEmail($email);
        if (null === $lead) {
            $lead = new Lead($email, $firstName, $lastName, $company, $provider, $providerOther, $source, $now);
            $this->entityManager->persist($lead);
        } else {
            $lead->signedUpAgain($firstName, $lastName, $company, $provider, $providerOther, $source, $now);
        }
        $this->entityManager->flush();

        if (null === $lead->confirmationSentAt) {
            $this->confirm($lead);
        }

        return $lead;
    }

    private function confirm(Lead $lead): void
    {
        $email = new TemplatedEmail()
            ->from(new Address($this->mailFrom, 'Beffroi'))
            ->to(new Address($lead->email, trim($lead->firstName.' '.$lead->lastName)))
            ->subject('You are on the Beffroi list')
            ->htmlTemplate('email/confirmation.html.twig')
            ->textTemplate('email/confirmation.txt.twig')
            ->context(['firstName' => $lead->firstName]);

        try {
            $this->mailer->send($email);
        } catch (TransportExceptionInterface $exception) {
            $this->logger->error('The confirmation of a sign-up could not be sent.', [
                'lead' => $lead->id->toRfc4122(),
                'exception' => $exception,
            ]);

            return;
        }

        $lead->confirmationSent($this->clock->now());
        $this->entityManager->flush();
    }

    private static function optional(?string $value): ?string
    {
        $value = trim((string) $value);

        return '' === $value ? null : $value;
    }
}
