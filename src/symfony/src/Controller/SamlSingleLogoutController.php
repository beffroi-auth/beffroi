<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\LogoutChainCookie;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\SingleLogout\SingleLogout;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The single logout service of the SAML identity provider of the tenant (beffroi/saml, spec/saml.md sections 6.5 and
 * 6.6), at the one URL its metadata publish for both bindings: HTTP-Redirect by GET, its raw query string read from
 * QUERY_STRING and never from the parsed query, whose octets the signature covers (B-2); HTTP-POST by POST, the fields
 * of a form and nothing else (spec/saml.md section 6.8), posted again from the origin of the provider when it came from
 * another site without the session cookie, before anything of the message is read (S-28). A message refused ends
 * nothing and gets the page of a refusal
 * and no SAML answer (S-22, S-23, S-33). A request accepted ends the sessions it names, then the other service
 * providers of those sessions are told, the page of Front-Channel Logout 1.0 first (S-35), before it is answered at
 * the single logout service of the metadata of its service provider (S-27, S-34); one that ended none is answered at
 * once. The answer of a service provider a chain waits for moves the chain on (section 6.6 step 4), read only with the
 * cookie of the browser the chain is bound to (LogoutChainCookie, S-32, S-33). Each step is a 302
 * over HTTP-Redirect with the caching headers of the binding (SAML Bindings §3.4.5.1), or the page that posts the form
 * over HTTP-POST (LogoutChainPages). A tenant whose SAML key cannot be opened, which is opened before the message is
 * read, ends nothing and remembers nothing, whatever the message: a 404 when it holds no active key, the 503 of
 * KmsUnavailableListener when the KMS does not answer (S-23, S-27).
 *
 * The browser that held a session it ended finds none at its next request, the session of the core having ended.
 */
#[AsController]
final readonly class SamlSingleLogoutController
{
    /**
     * The error code of the page a refused logout request is shown, which the template of the error explains.
     */
    public const string REFUSED = 'saml_logout_refused';

    public function __construct(
        private TenantProvider $tenants,
        private SingleLogout $singleLogout,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private LogoutChainPages $chain,
        private LogoutChainCookie $cookie,
        private CrossSitePost $crossSitePost,
    ) {
    }

    #[Route(IdentityProviderRoutes::SINGLE_LOGOUT_PATH, name: IdentityProviderRoutes::SINGLE_LOGOUT, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $context = $this->contexts->fromRequest($request);
        $secret = $this->cookie->presented($request);
        try {
            if ($request->isMethod(Request::METHOD_POST)) {
                if (! CrossSitePost::isAForm($request)) {
                    return $this->pages->error(
                        Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                        self::REFUSED,
                        'A request posted to the single logout service is a form, application/x-www-form-urlencoded (spec/saml.md section 6.8).',
                    );
                }
                $again = $this->crossSitePost->postAgain($request);
                if ($again !== null) {
                    return $again;
                }
                $answer = $this->singleLogout->post($tenant, $request->request->all(), $context, $secret);
            } else {
                $answer = $this->singleLogout->redirect($tenant, $request->server->getString('QUERY_STRING'), $context, $secret);
            }

            return $answer instanceof LogoutChainStarted ? $this->chain->started($tenant, $answer) : $this->chain->step($answer, $secret);
        } catch (LogoutRefusedException $exception) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED, $exception->getMessage());
        } catch (KeyNotFoundException) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, self::REFUSED, 'This tenant serves no SAML identity provider.');
        }
    }
}
