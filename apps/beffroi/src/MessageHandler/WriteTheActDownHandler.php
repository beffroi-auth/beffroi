<?php

declare(strict_types=1);

namespace App\MessageHandler;

use Beffroi\Core\Application\Journal\ActRecording;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\MayConcernAClientInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Core\Domain\Event\SaysWhyItWasRefusedInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler(bus: 'event.bus')]
final readonly class WriteTheActDownHandler
{
    public function __construct(
        private ActRecording $recording,
    ) {
    }

    public function __invoke(DomainEventInterface $event): void
    {
        $this->recording->record(
            $event->tenant,
            $event->name(),
            $event->occurredAt,
            $event->context,
            $event instanceof ConcernsAPersonInterface ? $event->subject() : null,
            $event instanceof MayConcernAClientInterface ? $event->clientId : null,
            $event instanceof NamesItsAuthorInterface ? $event->author() : null,
            $event instanceof SaysWhyItWasRefusedInterface ? $event->refusalReason() : null,
            $event instanceof SaysWhyItWasRefusedInterface ? $event->refusedMethod() : null,
        );
    }
}
