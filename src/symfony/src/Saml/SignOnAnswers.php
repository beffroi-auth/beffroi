<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\SingleSignOn\SingleSignOn;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * What the browser is answered with once a SAML request is accepted, at the single sign-on service and where the
 * login sends it back (beffroi/saml, spec/saml.md section 6.4): the page that posts the form, from the session the
 * browser holds; or the login of the provider, the request waiting in the session of that browser (S-18), through the
 * same LoginTarget every page of the provider that is not an authorization request signs in with, its second factor
 * included; or the page of a refusal, which gets no SAML answer.
 */
final readonly class SignOnAnswers
{
    /**
     * The error code of the page a refused request is shown, which the template of the error explains.
     */
    public const string REFUSED = 'saml_request_refused';

    public function __construct(
        private SingleSignOn $singleSignOn,
        private BrowserSession $browser,
        private WaitingSignOns $waiting,
        private LoginTarget $loginTargets,
        private InteractionPages $pages,
        private SamlPostPage $page,
        private RequestContextFactory $contexts,
    ) {
    }

    /**
     * @param string|null $reference the reference the request waits under, null when it has just been received
     */
    public function answer(Request $request, Tenant $tenant, SignOnRequest $signOn, ?string $reference = null): Response
    {
        try {
            $form = $this->singleSignOn->answer(
                $tenant,
                $signOn,
                $this->browser->authenticationSession($request, $tenant),
                $this->contexts->fromRequest($request),
            );
        } catch (SignOnRefusedException $exception) {
            if ($reference !== null) {
                $this->waiting->forget($request->getSession(), $reference);
            }

            return $this->refused($exception);
        } catch (KeyNotFoundException) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, self::REFUSED, 'This tenant serves no SAML identity provider.');
        }
        if ($form === null) {
            $httpSession = $request->getSession();

            return $this->loginTargets->sendToLogin($httpSession, IdentityProviderRoutes::SINGLE_SIGN_ON_RESUME, [
                IdentityProviderRoutes::REFERENCE_PARAMETER => $reference ?? $this->waiting->keep($httpSession, $tenant, $signOn),
            ]);
        }
        if ($reference !== null) {
            $this->waiting->forget($request->getSession(), $reference);
        }

        return $this->page->signOnResponse($form);
    }

    /**
     * The page of a refusal: the message names a rule and never a value of the message (M-16, B-11), and is what the
     * developer of the service provider needs to fix its request.
     */
    public function refused(SignOnRefusedException $exception): Response
    {
        return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED, $exception->getMessage());
    }
}
