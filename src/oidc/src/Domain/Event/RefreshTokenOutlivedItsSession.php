<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\AuthorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final readonly class RefreshTokenOutlivedItsSession implements ConcernsAClientInterface, ConcernsAPersonInterface
{
    public const string NAME = 'refresh_token.outlived_its_session';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public Subject $subject,
        public Uuid $sessionId,
        public DateTimeImmutable $sessionEndedAt,
        public RequestContext $context,
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
        return new AClient($this->clientId);
    }
}
