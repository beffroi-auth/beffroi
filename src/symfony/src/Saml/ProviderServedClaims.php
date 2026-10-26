<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_fill_keys;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;

/**
 * The claims a SAML attribute is mapped from are the claims the provider serves (beffroi/saml, spec/saml.md S-16),
 * read from the claims providers the wiring gave OpenID Connect: a claim is one thing whatever protocol carries it, and
 * a claim a deployment adds is mappable the day its class is wired. Each is asked for by name, as a request of OpenID
 * Connect asks for one (OIDC Core §5.5), no scope standing for any.
 *
 * The bundle holds it because it sees both modules, which never see each other.
 */
final readonly class ProviderServedClaims implements ServedClaimsInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
    ) {
    }

    public function names(): array
    {
        return $this->claims->supportedClaims();
    }

    public function of(User $user, array $names): array
    {
        return $this->claims->claims($user, null, array_fill_keys($names, new ClaimRequest()));
    }
}
