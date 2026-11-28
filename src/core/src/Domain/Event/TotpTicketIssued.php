<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Ticket\TotpTicket;
use DateTimeImmutable;

final readonly class TotpTicketIssued implements ConcernsAPersonInterface, NamesItsAuthorInterface
{
    public const string NAME = 'totp_ticket.issued';

    public Tenant $tenant;

    public function __construct(
        public TotpTicket $ticket,
        public DateTimeImmutable $occurredAt,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
        $this->tenant = $ticket->tenant;
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->ticket->user->subject;
    }

    public function author(): AuthorInterface
    {
        return $this->author;
    }
}
