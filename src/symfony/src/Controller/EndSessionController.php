<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Bundle\Http\InteractionLocale;
use Beffroi\Bundle\Http\FormToken;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Beffroi\Oidc\Application\EndSession\EndSessionHandler;
use Beffroi\Oidc\Application\EndSession\EndSessionRequestParser;
use Beffroi\Oidc\Domain\EndSession\LoggedOut;
use Beffroi\Oidc\Domain\EndSession\LogoutConfirmationRequired;
use Beffroi\Oidc\Exception\OAuth2Exception;
use function is_string;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The end session endpoint (RP-Initiated Logout §2), GET or POST. A request a client posted from another site
 * without the session cookie is posted again from the origin of the provider first (CrossSitePost), so that the
 * session it would end is the one the browser holds and the confirmation page is one the browser can answer. An error
 * is a page, never a redirection (§4). The confirmation page re-submits the same parameters with the answer and the CSRF
 * token; a "no" ends nothing and sends the user nowhere. A session that ended and whose clients
 * registered a front-channel logout URI leaves through the page that loads them (Front-Channel Logout
 * 1.0 §3), then through the SAML service providers it signed in, each told in turn (beffroi/saml S-29 to
 * S-35), which is what then sends the browser back to the client that asked.
 */
#[AsController]
final readonly class EndSessionController
{
    public const string CSRF_TOKEN_ID = 'beffroi_logout';

    public const string CONFIRM_PARAMETER = 'confirm';

    public const string CONFIRM_YES = 'yes';

    /**
     * The parameters of §2 the confirmation page carries over.
     */
    public const array PARAMETERS = ['id_token_hint', 'client_id', 'post_logout_redirect_uri', 'state', 'logout_hint', 'ui_locales'];

    public function __construct(
        private TenantProvider $tenants,
        private EndSessionRequestParser $parser,
        private EndSessionHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private FormToken $formTokens,
        private InteractionLocale $locale,
        private LogoutChainPages $logoutChain,
        private FormTarget $formTargets,
        private CrossSitePost $crossSitePost,
    ) {
    }

    #[Route('/logout', name: 'beffroi_interaction_logout', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $again = $this->crossSitePost->postAgainWithItsUiLocales($request);
        if ($again !== null) {
            return $again;
        }
        $tenant = $this->tenants->provide();
        $parameters = RequestParameters::ofBrowserRequest($request);
        try {
            $endSessionRequest = $this->parser->parse($tenant, $parameters);
        } catch (OAuth2Exception $exception) {
            return $this->pages->error($exception->statusCode, $exception->error, $exception->errorDescription);
        }
        $this->locale->apply($request, $this->locale->choose($request, $endSessionRequest->uiLocales));
        $session = $this->browser->authenticationSession($request, $tenant);
        $context = $this->contexts->fromRequest($request);

        $answer = $request->isMethod('POST') ? $parameters[self::CONFIRM_PARAMETER] ?? null : null;
        if ($answer === null) {
            $decision = $this->handler->begin($endSessionRequest, $session, $context);
        } else {
            $refusal = $this->formTokens->refusal($parameters[FormToken::PARAMETER] ?? null, self::CSRF_TOKEN_ID);
            if ($refusal !== null) {
                return $refusal;
            }
            if ($answer !== self::CONFIRM_YES) {
                return $this->pages->render('logged_out.html.twig', [
                    'logged_out' => false,
                    'client' => $endSessionRequest->client,
                ]);
            }
            $decision = $this->handler->confirm($endSessionRequest, $session, $context);
        }

        if ($decision instanceof LogoutConfirmationRequired) {
            $postLogoutRedirectUri = $decision->request->postLogoutRedirectUri;
            if ($postLogoutRedirectUri !== null) {
                // a confirmed logout ends where the client asked to be sent back, which this page names for
                // the browser to follow the redirection that goes there (FormTarget)
                $this->formTargets->mayEndAt($request, $postLogoutRedirectUri);
            }
            // and the confirmed logout goes through the SAML service providers of the session first,
            // redirections of the same submission (beffroi/saml S-36)
            $this->logoutChain->mayEnd($request, $decision->session);

            return $this->pages->render('logout.html.twig', [
                'client' => $decision->request->client,
                'user' => $decision->session->user,
                'reason' => $decision->reason,
                'parameters' => self::carriedOver($parameters),
            ]);
        }
        if (! $decision instanceof LoggedOut) {
            throw new LogicException(sprintf('The decision "%s" is not one the end session endpoint knows.', $decision::class));
        }
        if ($decision->endedSession !== null) {
            $this->browser->unbind($request->getSession());
            // Front-Channel Logout 1.0 §3: the frames of the clients of the session, then each SAML
            // service provider it signed in (beffroi/saml S-35), before the browser is sent back to the
            // one that asked; a session nobody of those kinds signed in has none of it
            $page = $this->logoutChain->begin($tenant, [$decision->endedSession], $decision->redirect?->toUri());
            if ($page !== null) {
                return $page;
            }
        }
        if ($decision->redirect !== null) {
            return $this->pages->redirect($decision->redirect->toUri());
        }

        return $this->pages->render('logged_out.html.twig', [
            'logged_out' => true,
            'client' => $decision->request->client,
        ]);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return array<string, string> the ones that were single strings, which is what the parser accepted
     */
    private static function carriedOver(array $parameters): array
    {
        $carried = [];
        foreach (self::PARAMETERS as $name) {
            $value = $parameters[$name] ?? null;
            if (is_string($value) && $value !== '') {
                $carried[$name] = $value;
            }
        }

        return $carried;
    }
}
