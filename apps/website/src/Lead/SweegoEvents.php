<?php

declare(strict_types=1);

namespace App\Lead;

use App\Repository\LeadRepository;
use DateTimeZone;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\RemoteEvent\Attribute\AsRemoteEventConsumer;
use Symfony\Component\RemoteEvent\Consumer\ConsumerInterface;
use Symfony\Component\RemoteEvent\Event\Mailer\AbstractMailerEvent;
use Symfony\Component\RemoteEvent\Event\Mailer\MailerDeliveryEvent;
use Symfony\Component\RemoteEvent\Event\Mailer\MailerEngagementEvent;
use Symfony\Component\RemoteEvent\RemoteEvent;

/**
 * What Sweego reports of the confirmations it carried, written on the lead of the recipient: delivered, opened,
 * clicked, bounced, reported as spam, unsubscribed. An event for an address no lead holds any more is dropped, and
 * still accepted, so that Sweego does not send it again.
 */
#[AsRemoteEventConsumer('sweego')]
final readonly class SweegoEvents implements ConsumerInterface
{
    public function __construct(
        private LeadRepository $leads,
        private EntityManagerInterface $entityManager,
    ) {
    }

    public function consume(RemoteEvent $event): void
    {
        if (! $event instanceof AbstractMailerEvent) {
            return;
        }

        $lead = $this->leads->findOneByEmail(mb_strtolower($event->getRecipientEmail()));
        if (null === $lead) {
            return;
        }

        // Sweego dates its events in UTC; the other dates of a lead are in the timezone of the application.
        $at = $event->getDate()->setTimezone(new DateTimeZone(date_default_timezone_get()));
        switch ($event->getName()) {
            case MailerDeliveryEvent::DELIVERED:
                $lead->confirmationDelivered($at);
                break;
            case MailerEngagementEvent::OPEN:
                $lead->confirmationOpened($at);
                break;
            case MailerEngagementEvent::CLICK:
                $lead->confirmationClicked($at);
                break;
            case MailerDeliveryEvent::BOUNCE:
                $lead->confirmationBounced($at);
                break;
            case MailerEngagementEvent::SPAM:
                $lead->markedAsSpam($at);
                break;
            case MailerEngagementEvent::UNSUBSCRIBE:
                $lead->unsubscribed($at);
                break;
            default:
                return;
        }

        $this->entityManager->flush();
    }
}
