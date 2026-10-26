<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Port\ResponseReceiverInterface;

/**
 * The receiver of the suite: what the model accepted is the assertion it is given, and what it was asked is recorded.
 */
final class RecordingResponseReceiver implements ResponseReceiverInterface
{
    /**
     * @var list<array{string, array<array-key, mixed>, string}>
     */
    public private(set) array $received = [];

    public function __construct(
        private readonly VerifiedAssertion $verified,
    ) {
    }

    public function receive(Tenant $tenant, UpstreamIdentityProvider $provider, array $fields, string $requestId): VerifiedAssertion
    {
        $this->received[] = [$provider->entityId, $fields, $requestId];

        return $this->verified;
    }
}
