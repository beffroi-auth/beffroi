<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Saml\UpstreamLoginRequirement;
use Beffroi\Bundle\Saml\UpstreamSignOnAnswer;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Saml\UpstreamSignOnReferences;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where an interaction of the browser starts a sign-on at an upstream identity provider of the SAML service provider of
 * the tenant (beffroi/saml, spec/saml.md S-51, section 6.11): an interaction this browser began and can still resume,
 * or none, for the login a page of the provider waits for (LoginTarget, S-61), the entity ID of a provider the tenant
 * declares, and the one-time reference the login page drew for that login and that provider, nothing else; the request
 * forces a login by the one rule of S-49, read from the rule of the login page (UpstreamLoginRequirement), is
 * remembered in the HTTP session of the browser under its RelayState with the interaction or the page it serves
 * (S-50), and is carried to the provider by a redirection over HTTP-Redirect or by the page that posts it over
 * HTTP-POST, with the address the discovery kept for that interaction or that page, taken from the HTTP session once
 * and never from the query, for a provider that reads one (S-68). Which provider an address goes to is the discovery
 * of the login page (S-61), which sends the browser here.
 *
 * **It starts only from the login page.** The reference is drawn in the HTTP session of the browser when the step of
 * the address, posted under its form token, or the "login_hint" that skips it sends the browser here
 * (UpstreamSignOnReferences), and taken once; a sign-on without it, with another, one used already, one drawn for
 * another provider or more than a minute ago is refused before anything is decided, signs no request and remembers
 * nothing, so that a page of another site, which can send the browser here but reads no session, starts no login at
 * a provider that would answer for the session it holds (login CSRF).
 *
 * A deployment that does not enable "beffroi.saml.service_provider" wires no sign-on and answers 404, as the metadata
 * of the role does (S-41); so does a tenant that holds no SAML key.
 */
#[AsController]
final readonly class SamlUpstreamSignOnController
{
    /**
     * The code of the page a sign-on that cannot start is shown, which the template of the error explains.
     */
    public const string REFUSED = 'saml_upstream_sign_on_refused';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private AuthorizationResponderInterface $responder,
        private UpstreamSignOns $signOns,
        private UpstreamSignOnAnswer $answers,
        private InteractionPages $pages,
        private ClockInterface $clock,
        private LoginTarget $loginTargets,
        private UpstreamLoginRequirement $requirement,
        private LoginAddresses $addresses,
        private UpstreamSignOnReferences $references,
        private ?UpstreamSignOn $signOn = null,
    ) {
    }

    #[Route(ServiceProviderRoutes::UPSTREAM_SIGN_ON_PATH, name: ServiceProviderRoutes::UPSTREAM_SIGN_ON, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        if (! $this->signOn instanceof UpstreamSignOn) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        }
        $tenant = $this->tenants->provide();
        $session = $this->browser->authenticationSession($request, $tenant);
        $now = $this->clock->now();
        $identityProvider = $request->query->getString(ServiceProviderRoutes::IDENTITY_PROVIDER_PARAMETER);
        $reference = $request->query->getString(ServiceProviderRoutes::REFERENCE_PARAMETER);
        $id = $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER);
        if ($id === '') {
            // the login a page of the provider waits for (LoginTarget, S-61): it comes back to that page, and a
            // person signed in already is asked for a fresh proof, which is all such a page asks of one (S-49)
            $for = $this->loginTargets->waiting($request->getSession());
            if ($for === null) {
                return $this->responder->unknownInteraction();
            }
            if (! $this->references->take($request->getSession(), null, $identityProvider, $reference, $now)) {
                return $this->unrequested();
            }
            $forceAuthn = $this->requirement->forcesALogin(null, $session, $now);
            $address = $this->addresses->takeSent($request->getSession(), null, $now);
        } else {
            $for = $this->browser->pending($request, $tenant, $id);
            if ($for === null) {
                return $this->responder->unknownInteraction();
            }
            try {
                $for->assertResumable($now);
            } catch (InteractionExpiredException|InteractionCompletedException $exception) {
                return $this->responder->unresumable($request, $for, $exception);
            }
            if (! $this->references->take($request->getSession(), $for, $identityProvider, $reference, $now)) {
                return $this->unrequested();
            }
            try {
                $forceAuthn = $this->requirement->forcesALogin($for, $session, $now);
            } catch (OAuth2Exception $exception) {
                return $this->responder->failure($request, $for->request->redirectTarget(), $exception, $for);
            }
            $address = $this->addresses->takeSent($request->getSession(), $for, $now);
        }
        try {
            $sent = $this->signOn->start($tenant, $identityProvider, $forceAuthn, $address);
        } catch (UpstreamSignOnRefusedException $exception) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED, $exception->getMessage());
        } catch (KeyNotFoundException $exception) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.', $exception);
        }
        $this->signOns->keep($request->getSession(), $tenant, $for, $sent);

        return $this->answers->of($sent);
    }

    /**
     * S-51: a sign-on the login page of this browser did not send it to under the reference it drew, which starts
     * nothing.
     */
    private function unrequested(): Response
    {
        return $this->pages->error(
            Response::HTTP_BAD_REQUEST,
            self::REFUSED,
            'The sign-on starts from the login page of this browser, under the reference it drew (spec/saml.md S-51).',
        );
    }
}
