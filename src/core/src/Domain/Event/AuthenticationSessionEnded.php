<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
use Beffroi\Core\Domain\Author\AuthorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LogicException;

final readonly class AuthenticationSessionEnded implements ConcernsAPersonInterface
{
    public const string NAME = 'session.ended';

    public Tenant $tenant;

    public SessionEnd $endedBy;

    public function __construct(
        public AuthenticationSession $session,
        public DateTimeImmutable $occurredAt,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
        $this->tenant = $session->tenant;
        $this->endedBy = $session->endedBy ?? throw new LogicException('The session has not ended.');
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->session->user->subject;
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
        $this->tenant = $read->object('tenant', Tenant::class);
        $this->endedBy = $read->object('endedBy', SessionEnd::class);
        $this->session = $read->object('session', AuthenticationSession::class);
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->context = $context;
        $this->author = $read->author($context, new ThePerson());
    }
}
