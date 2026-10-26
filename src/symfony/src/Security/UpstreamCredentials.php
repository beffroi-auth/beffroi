<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use DateTimeImmutable;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;

/**
 * What an upstream identity provider proved of the person its assertion names (beffroi/saml S-57): the methods of
 * RFC 8176 its authentication context maps to exactly, "fed" first, the AuthnInstant, when it proved them, and the
 * SessionNotOnOrAfter, the instant the session must end by. The assertion consumer service verified the response
 * before it put this on the passport (S-53).
 */
final readonly class UpstreamCredentials implements CredentialsInterface
{
    /**
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public function __construct(
        public array $methods,
        public DateTimeImmutable $provenAt,
        public ?DateTimeImmutable $sessionNotOnOrAfter = null,
    ) {
    }

    public function isResolved(): bool
    {
        return true;
    }
}
