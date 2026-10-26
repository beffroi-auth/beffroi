<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Saml\Application\SingleLogout\SessionParticipants;
use Beffroi\Saml\Domain\Event\ServiceProviderSignedIn;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Each service provider's part in a session recorded on the event single sign-on announces (beffroi/saml,
 * spec/saml.md S-26), on the lane the events travel and never on the path of the request: the assertion needs nothing
 * of the row, so the write waits for the queue, as every write the protocol does not need the result of does
 * (architecture §5.6).
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class RecordTheServiceProviderOfTheSessionHandler
{
    public function __construct(
        private SessionParticipants $participants,
    ) {
    }

    public function __invoke(ServiceProviderSignedIn $event): void
    {
        $this->participants->signedIn($event);
    }
}
