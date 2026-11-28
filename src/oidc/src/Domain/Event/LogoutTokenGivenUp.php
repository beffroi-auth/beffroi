<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
use Beffroi\Core\Domain\Author\AuthorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class LogoutTokenGivenUp implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'logout_token.given_up';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public string $clientId,
        public Subject $subject,
        public Uuid $sessionId,
        public string $reason,
        public AuthorInterface $author,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->subject;
    }

    public function author(): AuthorInterface
    {
        return $this->author;
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
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->tenant = $read->object('tenant', Tenant::class);
        $this->context = $context;
        $this->clientId = $read->string('clientId');
        $this->subject = $read->object('subject', Subject::class);
        $this->sessionId = $read->object('sessionId', Uuid::class);
        $this->reason = $read->string('reason');
        $this->author = $read->author($context, new ThePerson());
    }
}
