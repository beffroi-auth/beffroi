<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Event;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Encoding\SerializedProperties;
use Beffroi\Core\Domain\Author\AuthorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class CredentialRevoked implements ConcernsAPersonInterface
{
    public const string NAME = 'credential.revoked';

    public Tenant $tenant;

    public function __construct(
        public Credential&RevocableCredentialInterface $credential,
        public DateTimeImmutable $occurredAt,
        public RequestContext $context,
        public AuthorInterface $author,
    ) {
        $this->tenant = $credential->tenant;
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->credential->user->subject;
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
        $credential = $read->object('credential', Credential::class);
        if (! $credential instanceof RevocableCredentialInterface) {
            throw new InvalidArgumentException('The credential a revocation read back names is one that revokes.');
        }
        $this->credential = $credential;
        $this->occurredAt = $read->object('occurredAt', DateTimeImmutable::class);
        $this->context = $context;
        $this->author = $read->author($context, new ThePerson());
    }
}
