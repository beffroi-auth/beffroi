<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 7592 §2.3
 *
 * Records naming the client stay: they resolve through the sources, so nothing of a removed client can be spent.
 */
final readonly class RegisteredClientRemoval
{
    public function __construct(
        private ClientStoreInterface $clients,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * The act names its author: the client itself (RFC 7592 §2.3), or the host by its retention or its console (decision
     * 0066).
     */
    public function remove(ClientRecord $record, AuthorInterface $author, RequestContext $context): void
    {
        $this->removeOnce($record, $context, $author);
    }

    /**
     * The act names the administrator (decision 0038).
     */
    public function removeByAnAdministrator(ClientRecord $record, Subject $administrator, RequestContext $context): void
    {
        $this->removeOnce($record, $context, new AnAdministrator($administrator));
    }

    private function removeOnce(ClientRecord $record, RequestContext $context, AuthorInterface $author): void
    {
        $this->clients->remove($record);
        $this->events->dispatch(new RegisteredClientDeleted($context->receivedAt, $record->tenant, $record->clientId, $context, $author));
    }
}
