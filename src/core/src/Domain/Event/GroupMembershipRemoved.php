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
use Symfony\Component\Uid\Uuid;

final readonly class GroupMembershipRemoved implements ConcernsAPersonInterface
{
    public const string NAME = 'group_membership.removed';

    /**
     * Null in a body the version before queued, which named the group by its name alone.
     */
    public ?Uuid $groupId;

    /**
     * @param string $group the name of the group when it happened, which names an organisational unit and not a person; a rename leaves its identifier
     */
    public function __construct(
        public Tenant $tenant,
        public Subject $person,
        Uuid $groupId,
        public string $group,
        public DateTimeImmutable $occurredAt,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
        $this->groupId = $groupId;
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
        $this->groupId = $read->nullableObject('groupId', Uuid::class);
        $this->group = $read->string('group');
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->context = $context;
        $this->author = $read->author($context, new TheHost());
    }
}
