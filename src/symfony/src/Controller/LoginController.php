<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use function str_contains;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Bundle\Http\InteractionLocale;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\OfferedLogins;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Saml\UpstreamDiscovery;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\StepUpOffer;
use Beffroi\Oidc\Application\Authorization\AuthorizationHandler;
use Beffroi\Oidc\Application\Hint\LoginHints;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequired;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * The login page of an interaction (architecture §4.3, §5.2), shown while a login is still required. The
 * POST is the check path of the form login of the firewall (§5.4), which sends the browser back here; a
 * refused login is one flat message whatever the reason (decision 0006). On a step-up (decision 0010) the
 * page says which of the credentials the user holds would satisfy the client, by their kinds as the
 * StepUp names them, a passkey, the password, a TOTP after the password; both forms stay offered, a login
 * that satisfies nothing being the way back to the client with what the session has.
 *
 * When the tenant federates an e-mail domain to an upstream provider (decision 0029, beffroi/saml S-61,
 * S-62), the page asks for the address first and offers nothing else, for an interaction as for a page of
 * the provider, the domain of what is typed sending the browser to the sign-on of its provider or on to
 * this page (LoginAddressController), and a "login_hint" that is an address of a federated domain skips the
 * page of an interaction; both read the domain and never a person, so that the answer says nothing of who
 * holds an address.
 *
 * A page of the provider that is not an authorization request asks for the same two things through the
 * same form (LoginTarget): a login, when nobody is signed in, and one more proof, when somebody is and
 * what they hold does not prove what was asked of them (CIBA Core §7.1). It names no client, there being
 * no request of a browser behind it.
 */
#[AsController]
final readonly class LoginController
{
    public const string ROUTE = 'beffroi_interaction_login';

    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private AuthorizationResponderInterface $responder,
        private InteractionPages $pages,
        private AuthenticationUtils $authentication,
        private InteractionLocale $locale,
        private LoginTarget $loginTargets,
        private LoginHints $hints,
        private FormTarget $formTargets,
        private OfferedLogins $offered,
        private UpstreamDiscovery $discovery,
        private LoginAddresses $addresses,
        private WhatWasRefused $refusals,
        private ClockInterface $clock,
    ) {
    }

    #[Route('/login', name: self::ROUTE, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $interaction = $this->browser->pending($request, $tenant, $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER));
        if ($interaction === null) {
            // a page of the provider that is not an authorization request asked for this login and is
            // waiting for it: the form is the same one, and there is no interaction to resume
            if (! $this->loginTargets->isPending($request->getSession())) {
                return $this->responder->unknownInteraction();
            }
            $stepUp = $this->loginTargets->pendingStepUp($request->getSession());
            $requirement = $stepUp === null ? null : LoginRequirement::StrongerFactorRequired;
            // beffroi/saml S-61: the address first here too, the sign-on of a federated domain coming back to the
            // page that waits (S-51)
            $asksForAnAddress = $this->discovery->asksForAnAddress($tenant);
            if ($asksForAnAddress && ! $this->addresses->passed($request->getSession(), null)) {
                return $this->address($request, $tenant, null, $requirement, $stepUp);
            }

            return $this->form($tenant, null, $requirement, $stepUp, $asksForAnAddress);
        }
        $this->locale->resume($request, $interaction);
        try {
            $decision = $this->handler->resume(
                $interaction,
                $this->browser->authenticationSession($request, $tenant),
                $this->contexts->fromRequest($request),
            );
        } catch (InteractionExpiredException|InteractionCompletedException $exception) {
            return $this->responder->unresumable($request, $interaction, $exception);
        } catch (OAuth2Exception $exception) {
            return $this->responder->failure($request, $interaction->request->redirectTarget(), $exception, $interaction);
        }
        if (! $decision instanceof LoginRequired) {
            return $this->responder->respond($request, $decision);
        }
        // the login this page asks for ends where the client asked to be answered, which its policy names
        // for the browser to follow the redirection that carries the code there (FormTarget)
        $this->formTargets->mayEndAt($request, $interaction->request->redirectUri);
        $stepUp = $decision->stepUp;
        $offer = $stepUp === null ? null : StepUpOffer::of($stepUp);
        // beffroi/saml S-61, S-62: a tenant that federates a domain asks for the address first, and a hint that is an
        // address of a federated domain skips the page, read for its domain and never for a person (decision 0029)
        $asksForAnAddress = $this->discovery->asksForAnAddress($tenant);
        if ($asksForAnAddress) {
            $hinted = $this->discovery->hintedProvider($tenant, $interaction);
            $hint = $interaction->request->loginHint;
            if ($hinted !== null && $hint !== null) {
                // beffroi/saml S-68: the hint goes on to the provider that reads one, as a typed address does
                $now = $this->clock->now();
                $this->addresses->sendOn($request->getSession(), $interaction, $hint, $now);

                return $this->pages->redirectToRoute(ServiceProviderRoutes::UPSTREAM_SIGN_ON, $this->discovery->signOn(
                    $request->getSession(),
                    $interaction,
                    $hinted,
                    $now,
                ));
            }
            if (! $this->addresses->passed($request->getSession(), $interaction)) {
                return $this->address($request, $tenant, $interaction, $decision->requirement, $offer);
            }
        }

        return $this->form($tenant, $interaction, $decision->requirement, $offer, $asksForAnAddress);
    }

    /**
     * The step of the address (beffroi/saml S-61), of an interaction or of the login a page of the provider waits for:
     * one field, and no password, no passkey and no autofill of one, the domain of what is typed deciding where the
     * browser goes (LoginAddressController). Nothing on it reads a person: the field holds what this browser typed
     * last, or the "login_hint" of the request when it is an address, as the client wrote it. Its submission ends at the
     * single sign-on service of a provider over HTTP-Redirect, whose origin it names in its "form-action".
     */
    private function address(Request $request, Tenant $tenant, ?Interaction $interaction, ?LoginRequirement $requirement, ?StepUpOffer $stepUp): Response
    {
        $this->discovery->mayReachTheProviders($request, $tenant);
        $lastUsername = $this->authentication->getLastUsername();
        // the hint as the client wrote it when it is an address, and never the person a reading of it finds: what
        // a lookup filled in would say whether an account holds what the client named (S-61)
        $hint = $interaction?->request->loginHint;
        $hinted = $hint !== null && str_contains($hint, '@') ? $hint : null;

        return $this->pages->render('login_address.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction?->request->client,
            'requirement' => $requirement,
            'step_up' => $stepUp,
            'address' => $lastUsername === '' ? $hinted : $lastUsername,
            'refusal' => $this->refusals->take($request),
        ]);
    }

    /**
     * The form, for the interaction that is waiting for a login or for the page that is: what the page says
     * of a client and of what is missing, it says of the request it serves, and a login asked for by a page
     * of the provider serves none.
     *
     * OIDC Core §3.1.2.1: the name offered is the one the person types, so a "login_hint" is read into the
     * user it names and the field carries that user's name; a hint that names nobody leaves the field
     * empty rather than asking somebody to delete a "sub" they never wrote. What the browser last tried
     * comes first, a login just refused being what the person was correcting.
     *
     * What it offers is what the firewall wires and the floor of the tenant admits (OfferedLogins, issue
     * #327): a tenant that signs its users in by passkey is shown no password field and no username to
     * type it against. After the step of the address (beffroi/saml S-61), it offers to go back to it.
     */
    private function form(Tenant $tenant, ?Interaction $interaction, ?LoginRequirement $requirement, ?StepUpOffer $stepUp, bool $afterTheAddress): Response
    {
        $lastUsername = $this->authentication->getLastUsername();
        $hinted = $interaction === null ? null : $this->hints->userNamedBy($interaction->request);

        return $this->pages->render('login.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction?->request->client,
            'requirement' => $requirement,
            'step_up' => $stepUp,
            'username' => $lastUsername === '' ? $hinted?->username : $lastUsername,
            'failed' => $this->authentication->getLastAuthenticationError() !== null,
            'offered' => $this->offered->kinds($tenant),
            'after_the_address' => $afterTheAddress,
        ]);
    }
}
