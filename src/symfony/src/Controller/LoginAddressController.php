<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\FormToken;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Saml\UpstreamDiscovery;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Exception\InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use function trim;

/**
 * The step of the address of the login page, when the tenant federates a domain (beffroi/saml S-61, decision 0029), for
 * an interaction or for the login a page of the provider waits for (LoginTarget): an address of a federated domain is
 * sent to the sign-on of its provider for that interaction or that page, under the one-time reference drawn for that
 * sign-on (S-51), kept in the HTTP session for that sign-on, which carries it to a provider that reads one (S-68); any
 * other address, and a username, go on to the usual page, the field of the username holding what was typed; an address
 * whose domain the rule of the core does not read comes back to the step, which says so. An empty value goes back to
 * the step, for another address.
 *
 * **Nothing here reads a person.** Where the browser goes is a function of the domain and of the declarations of the
 * tenant (FederatedDomains), so that the answer, its status, its headers and its body, is the same whether somebody
 * holds the address or not, and waits on no lookup a clock could tell apart. Every answer is a redirection, as every
 * form of these pages answers (InteractionPages::afterTheForm()).
 */
#[AsController]
final readonly class LoginAddressController
{
    public const string ROUTE = 'beffroi_interaction_login_address';

    public const string CSRF_TOKEN_ID = 'beffroi_login_address';

    public const string ADDRESS_PARAMETER = '_address';

    /**
     * The code of an address whose domain the rule does not read, which the page of the address translates.
     */
    public const string UNREADABLE = 'address_unreadable';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private AuthorizationResponderInterface $responder,
        private FormToken $formTokens,
        private FederatedDomains $federated,
        private LoginAddresses $addresses,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
        private LoginTarget $loginTargets,
        private ClockInterface $clock,
        private UpstreamDiscovery $discovery,
    ) {
    }

    #[Route('/login/address', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $id = $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER);
        // an interaction this browser began, or none for the login a page of the provider waits for (S-61)
        $interaction = $id === '' ? null : $this->browser->pending($request, $tenant, $id);
        if ($interaction === null && ($id !== '' || ! $this->loginTargets->isPending($request->getSession()))) {
            return $this->responder->unknownInteraction();
        }
        $refusal = $this->formTokens->refusal($request->request->get(FormToken::PARAMETER), self::CSRF_TOKEN_ID);
        if ($refusal !== null) {
            return $refusal;
        }
        $back = $interaction === null
            ? []
            : [
                AuthorizationResponder::INTERACTION_PARAMETER => $interaction->id,
            ];
        $address = trim($request->request->getString(self::ADDRESS_PARAMETER));
        if ($address === '') {
            $this->addresses->forget($request->getSession(), $interaction);

            return $this->pages->afterTheForm(LoginController::ROUTE, $back);
        }
        try {
            $provider = $this->federated->providerOf($tenant, $address);
        } catch (InvalidArgumentException) {
            $this->refusals->keep($request, self::UNREADABLE, self::ADDRESS_PARAMETER);

            return $this->pages->afterTheForm(LoginController::ROUTE, $back);
        }
        if ($provider !== null) {
            $now = $this->clock->now();
            $this->addresses->sendOn($request->getSession(), $interaction, $address, $now);

            // S-51: under the one-time reference drawn for that sign-on, which no page of another site reads
            return $this->pages->afterTheForm(ServiceProviderRoutes::UPSTREAM_SIGN_ON, $this->discovery->signOn(
                $request->getSession(),
                $interaction,
                $provider,
                $now,
            ));
        }
        $this->addresses->pass($request->getSession(), $interaction, $address);

        return $this->pages->afterTheForm(LoginController::ROUTE, $back);
    }
}
