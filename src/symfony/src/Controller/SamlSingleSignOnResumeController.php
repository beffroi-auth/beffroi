<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\SignOnAnswers;
use Beffroi\Bundle\Saml\WaitingSignOns;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where the login of the provider sends back a browser whose SAML request waited for it (beffroi/saml, spec/saml.md
 * S-18, section 6.4 step 3): the request found in the session of that browser under the reference this provider wrote,
 * and answered as the single sign-on service answers it. A reference this browser does not hold, one already answered
 * among them, is the page of a refusal, without telling which.
 */
#[AsController]
final readonly class SamlSingleSignOnResumeController
{
    public function __construct(
        private TenantProvider $tenants,
        private WaitingSignOns $waiting,
        private LoginTarget $loginTargets,
        private SignOnAnswers $answers,
        private InteractionPages $pages,
    ) {
    }

    #[Route(IdentityProviderRoutes::SINGLE_SIGN_ON_RESUME_PATH, name: IdentityProviderRoutes::SINGLE_SIGN_ON_RESUME, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $reference = $request->query->getString(IdentityProviderRoutes::REFERENCE_PARAMETER);
        $signOn = $reference === '' || ! $request->hasPreviousSession() ? null : $this->waiting->find($request->getSession(), $tenant, $reference);
        if ($signOn === null) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, AuthorizationResponder::UNKNOWN_INTERACTION);
        }
        // the page that was waiting for the login is this one, and it is served: a next login is somebody else's
        $this->loginTargets->forgetIfItIsWaitingFor($request->getSession(), IdentityProviderRoutes::SINGLE_SIGN_ON_RESUME);

        return $this->answers->answer($request, $tenant, $signOn, $reference);
    }
}
