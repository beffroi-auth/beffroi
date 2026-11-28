<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\MayConcernAClientInterface;
use Beffroi\Core\Domain\Event\SaysWhyItWasRefusedInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * The "request_uri" itself is never carried: an audit trail must not let its reader replay it. The journal names the
 * client that presented the reference, when the tenant holds it (decision 0062).
 */
final class PushedRequestRefused implements MayConcernAClientInterface, SaysWhyItWasRefusedInterface
{
    public const string NAME = 'pushed_request.refused';

    public ?string $clientId {
        get => $this->presentedBy;
    }

    /**
     * @param string|null $presentedBy the client the request named, when the tenant holds it: an identifier anybody may present names no client otherwise (decision 0062)
     * @param string|null $pushedBy    the client that pushed the reference, when the reference is one of the tenant's
     */
    public function __construct(
        public readonly DateTimeImmutable $occurredAt,
        public readonly Tenant $tenant,
        public readonly PushedRequestRefusalReason $reason,
        public readonly ?string $presentedBy,
        public readonly ?string $pushedBy,
        public readonly RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function refusalReason(): string
    {
        return $this->reason->value;
    }

    public function refusedMethod(): ?string
    {
        return null;
    }
}
