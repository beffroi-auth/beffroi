<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * The logout token a client is owed for a session, issued or still to issue: a lane that runs out on it gives it up.
 */
interface LogoutTokenNotification extends Notification, GivenUpAsAnAct
{
    public Tenant $tenant { get; }

    public string $clientId { get; }

    public Uuid $sessionId { get; }

    /**
     * The subject of the person's account, never the "sub" the token names.
     */
    public Subject $subject { get; }

    public RequestContext $context { get; }

    /**
     * Who ended the session, whom the logout token names as the author of its act.
     */
    public AuthorInterface $author { get; }
}
