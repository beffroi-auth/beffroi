<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Http\WaitingPage;
use DateTimeImmutable;

/**
 * A request the service provider of a tenant sent an upstream identity provider for a login of this browser, as
 * UpstreamSignOns kept it under its RelayState (beffroi/saml, spec/saml.md S-50): its ID, the entity ID of the provider
 * it went to, whether it carried ForceAuthn, the instant it was issued, and either the interaction it serves or the
 * page of the provider that waits for the login, what the assertion consumer service resumes and nothing else (S-59).
 */
final readonly class RememberedSignOn
{
    private function __construct(
        public string $requestId,
        public string $identityProvider,
        public bool $forceAuthn,
        public DateTimeImmutable $issuedAt,
        public ?string $interaction,
        public ?WaitingPage $page,
    ) {
    }

    public static function forInteraction(string $interaction, string $requestId, string $identityProvider, bool $forceAuthn, DateTimeImmutable $issuedAt): self
    {
        return new self($requestId, $identityProvider, $forceAuthn, $issuedAt, $interaction, null);
    }

    public static function forPage(WaitingPage $page, string $requestId, string $identityProvider, bool $forceAuthn, DateTimeImmutable $issuedAt): self
    {
        return new self($requestId, $identityProvider, $forceAuthn, $issuedAt, null, $page);
    }
}
