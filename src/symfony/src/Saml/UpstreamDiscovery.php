<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use DateTimeImmutable;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Where the login page of an interaction sends an address of a domain the tenant federates (beffroi/saml S-61, S-62):
 * the sign-on of S-51 at the one provider of that domain, for that interaction, and nothing read of a person. The
 * upstream providers are the SAML upstream identity providers of the tenant (SamlUpstreamProviders), so the sign-on is
 * theirs; a deployment that does not enable the service provider declares none, and no page asks for an address.
 */
final readonly class UpstreamDiscovery
{
    public function __construct(
        private FederatedDomains $federated,
        private FormTarget $formTargets,
        private UpstreamSignOnReferences $references,
        private ?UpstreamSignOn $signOn = null,
    ) {
    }

    /**
     * S-61: whether the login page of an interaction asks for the address first.
     */
    public function asksForAnAddress(Tenant $tenant): bool
    {
        return $this->federated->federates($tenant);
    }

    /**
     * S-62: the provider the "login_hint" of the request of the interaction is federated to, when it is an address of a
     * federated domain, read for its domain alone; null for any other hint, the page then asked as without one.
     */
    public function hintedProvider(Tenant $tenant, Interaction $interaction): ?UpstreamProvider
    {
        $hint = $interaction->request->loginHint;
        if ($hint === null) {
            return null;
        }
        try {
            return $this->federated->providerOf($tenant, $hint);
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /**
     * S-51: the parameters of the sign-on of that interaction at that provider, or of the login a page of the provider
     * waits for when there is none (S-61), at the route of the interaction plane ServiceProviderRoutes::UPSTREAM_SIGN_ON
     * names, with the one-time reference drawn for it in the HTTP session of the browser, without which the sign-on
     * starts nothing (UpstreamSignOnReferences).
     *
     * @return array<string, string>
     */
    public function signOn(SessionInterface $httpSession, ?Interaction $interaction, UpstreamProvider $provider, DateTimeImmutable $now): array
    {
        $parameters = [
            ServiceProviderRoutes::IDENTITY_PROVIDER_PARAMETER => $provider->name,
            ServiceProviderRoutes::REFERENCE_PARAMETER => $this->references->issue($httpSession, $interaction, $provider->name, $now),
        ];

        return $interaction === null ? $parameters : [AuthorizationResponder::INTERACTION_PARAMETER => $interaction->id, ...$parameters];
    }

    /**
     * S-61: the origin of the single sign-on service of each provider of the tenant, named in the "form-action" of the
     * page of the address, whose submission ends there over HTTP-Redirect (FormTarget).
     */
    public function mayReachTheProviders(Request $request, Tenant $tenant): void
    {
        foreach ($this->signOn?->destinations($tenant) ?? [] as $destination) {
            $this->formTargets->mayReach($request, SamlPostPage::originOf($destination));
        }
    }
}
