<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class SendLogoutToken implements LogoutTokenNotification
{
    use LogoutTokenGivenUpTrait;

    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public string $logoutUri,
        public string $logoutToken,
        public Uuid $sessionId,
        public Subject $subject,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
    }
}
