<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\SignOnAnswers;
use Beffroi\Saml\Application\SingleSignOn\SingleSignOn;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The single sign-on service of the SAML identity provider of the tenant (beffroi/saml, spec/saml.md section 6.4),
 * at the one URL its metadata publish for both bindings: HTTP-Redirect by GET, its raw query string read from
 * QUERY_STRING and never from the parsed query, whose octets the signature covers (B-2); HTTP-POST by POST, the
 * fields of a form and nothing else (spec/saml.md section 6.8), posted again from the origin of the provider when it came
 * from another site without the session cookie (S-28). A request refused gets the page of a refusal and no
 * SAML answer; one accepted is answered from the session of the browser, or waits for its login.
 */
#[AsController]
final readonly class SamlSingleSignOnController
{
    public function __construct(
        private TenantProvider $tenants,
        private SingleSignOn $singleSignOn,
        private SignOnAnswers $answers,
        private InteractionPages $pages,
        private CrossSitePost $crossSitePost,
    ) {
    }

    #[Route(IdentityProviderRoutes::SINGLE_SIGN_ON_PATH, name: IdentityProviderRoutes::SINGLE_SIGN_ON, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        try {
            if ($request->isMethod(Request::METHOD_POST)) {
                if (! CrossSitePost::isAForm($request)) {
                    return $this->pages->error(
                        Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                        SignOnAnswers::REFUSED,
                        'A request posted to the single sign-on service is a form, application/x-www-form-urlencoded (spec/saml.md section 6.8).',
                    );
                }
                $again = $this->crossSitePost->postAgain($request);
                if ($again !== null) {
                    return $again;
                }
                $signOn = $this->singleSignOn->receivePost($tenant, $request->request->all());
            } else {
                $signOn = $this->singleSignOn->receiveRedirect($tenant, $request->server->getString('QUERY_STRING'));
            }
        } catch (SignOnRefusedException $exception) {
            return $this->answers->refused($exception);
        }

        return $this->answers->answer($request, $tenant, $signOn);
    }
}
