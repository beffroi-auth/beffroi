<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
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

    /**
     * What a queue holds, a body written before acts named the kind of their author included, which names its
     * administrator or nobody (decision 0066).
     *
     * @param array<array-key, mixed> $data
     *
     * @throws InvalidArgumentException
     */
    public function __unserialize(array $data): void
    {
        $read = new SerializedProperties($data);
        $context = $read->object('context', RequestContext::class);
        $this->tenant = $read->object('tenant', Tenant::class);
        $this->clientId = $read->string('clientId');
        $this->sessionId = $read->object('sessionId', Uuid::class);
        $this->subject = $read->object('subject', Subject::class);
        $this->context = $context;
        $this->author = $read->author($context, new ThePerson());
    }
}
