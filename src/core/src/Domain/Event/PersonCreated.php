<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * Never carries what the person was created with, which stays sealed in their row.
 */
final readonly class PersonCreated implements ConcernsAPersonInterface
{
    public const string NAME = 'person.created';

    public function __construct(
        public Tenant $tenant,
        public Subject $person,
        public DateTimeImmutable $occurredAt,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->person;
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
        $this->person = $read->object('person', Subject::class);
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->context = $context;
        $this->author = $read->author($context, new TheHost());
    }
}
