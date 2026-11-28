<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * Back-Channel Logout 1.0 §2.4
 */
final readonly class IssueLogoutToken implements LogoutTokenNotification
{
    use LogoutTokenGivenUpTrait;

    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public Uuid $sessionId,
        public Subject $subject,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
    }
}
