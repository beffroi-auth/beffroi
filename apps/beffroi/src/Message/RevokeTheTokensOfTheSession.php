<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * A message of its own: its revocations are written in its transaction, and its act leaves after them, whatever the
 * other handlers of the end of the session do.
 */
final readonly class RevokeTheTokensOfTheSession implements Command
{
    /**
     * @param Subject      $subject       the person of the session, by the subject of their account
     * @param Subject|null $administrator the administrator of the tenant who ended the session, by the subject of their account
     */
    public function __construct(
        public Tenant $tenant,
        public Uuid $sessionId,
        public DateTimeImmutable $endedAt,
        public Subject $subject,
        public RequestContext $context,
        public ?Subject $administrator = null,
    ) {
    }
}
