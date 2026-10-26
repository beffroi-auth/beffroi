<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\LogoutChainCookie;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\SingleLogout\ProviderLogout;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where the page of Front-Channel Logout 1.0 sends the browser once the clients of OpenID Connect of the ended sessions
 * are loaded: the chain of SAML logout resumed by the reference the provider drew for it (beffroi/saml, spec/saml.md
 * S-32, S-35, section 6.6 step 2), with the cookie of the browser the chain is bound to (LogoutChainCookie), its next
 * step given to the browser. A reference no open chain holds, one presented without that cookie or with another, or
 * one another request took first, gets the page of a refusal: nothing is resumed twice, nor by another client.
 */
#[AsController]
final readonly class SamlSingleLogoutContinueController
{
    public function __construct(
        private TenantProvider $tenants,
        private ProviderLogout $logout,
        private LogoutChainPages $chain,
        private InteractionPages $pages,
        private LogoutChainCookie $cookie,
    ) {
    }

    #[Route(IdentityProviderRoutes::SINGLE_LOGOUT_CONTINUE_PATH, name: IdentityProviderRoutes::SINGLE_LOGOUT_CONTINUE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $secret = $this->cookie->presented($request);
        try {
            return $this->chain->step($this->logout->resume($tenant, $request->query->getString(IdentityProviderRoutes::CHAIN_PARAMETER), $secret), $secret);
        } catch (LogoutRefusedException $exception) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, SamlSingleLogoutController::REFUSED, $exception->getMessage());
        } catch (KeyNotFoundException) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, SamlSingleLogoutController::REFUSED, 'This tenant serves no SAML identity provider.');
        }
    }
}
