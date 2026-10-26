<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Controller\LoginController;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Http\CrossSiteSessionCookie;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Saml\RememberedSignOn;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Saml\UpstreamLoginRequirement;
use Beffroi\Bundle\Saml\UpstreamSignOnAnswer;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusalReason;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusedException;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\AccountSelectionRequiredException;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\LoginRequiredException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Saml\Application\Upstream\AssertionConsumerService;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Domain\Upstream\AuthnContextMethods;
use Beffroi\Saml\Domain\Upstream\UpstreamAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;
use Beffroi\Saml\Exception\UpstreamAuthenticationFailedException;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use function is_string;

/**
 * The assertion consumer service of the service provider of the tenant, a login of the firewall of the interaction
 * pages (beffroi/saml, spec/saml.md S-52 to S-59, section 6.14): the response an upstream identity provider posted,
 * taken for the request this browser remembers under its RelayState, and once (S-53); the person it names resolved or
 * created with its groups (S-56); what the client asked of the login read by the rule of the login page, the request
 * sent once more with ForceAuthn at most (S-58); then the passport, whose session LoginSuccessListener opens dated by
 * the AuthnInstant (S-57), and the browser sent to the interaction or the page the request was remembered for, and
 * nowhere else (S-59).
 *
 * It takes no post from another site that came without the session cookie (S-28): the route posts it again from the
 * provider's own origin, and the second post, which carries the HTTP session the request was remembered in, is the one
 * read. No form token: the form is the provider's, and what binds it to this browser is the request remembered in its
 * HTTP session under the RelayState. A deployment that does not enable the service provider wires no use case, and
 * the route answers 404 (S-41).
 */
final readonly class UpstreamAssertionAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface
{
    /**
     * The code of the page a response that signs nobody in is shown, which the template of the error explains.
     */
    public const string REFUSED = 'saml_assertion_refused';

    /**
     * Where the request remembered travels from authenticate() to the answer of a login, an attribute of the request
     * and never anything the browser sent.
     */
    private const string REMEMBERED = '_beffroi_upstream_sign_on';

    private const string RELAY_STATE = 'RelayState';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private UpstreamSignOns $signOns,
        private UpstreamLoginRequirement $requirement,
        private RequestContextFactory $contexts,
        private AuthorizationResponderInterface $responder,
        private InteractionPages $pages,
        private UpstreamSignOnAnswer $answers,
        private ClockInterface $clock,
        private ?AssertionConsumerService $consumer = null,
        private ?UpstreamSignOn $signOn = null,
    ) {
    }

    /**
     * A post to the route of S-52, a form, of a deployment that serves the service provider, and none from another site
     * that came without the session cookie, which the route posts again (S-28).
     */
    public function supports(Request $request): bool
    {
        return (
            $this->consumer instanceof AssertionConsumerService
            && $request->isMethod('POST')
            && $request->attributes->getString('_route') === ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE
            && CrossSitePost::isAForm($request)
            && ! CrossSiteSessionCookie::withheldFrom($request)
        );
    }

    public function authenticate(Request $request): Passport
    {
        $consumer = $this->consumer ?? throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        $tenant = $this->tenants->provide();
        $now = $this->clock->now();
        $relayState = $request->request->get(self::RELAY_STATE);
        $remembered = is_string($relayState) && $relayState !== '' ? $this->signOns->take($request->getSession(), $tenant, $relayState, $now) : null;
        if (! $remembered instanceof RememberedSignOn) {
            // S-53: an unsolicited response, or one for a request this browser does not remember (decision 0029)
            throw $this->refused(
                'The response answers no request this browser remembers (spec/saml.md S-53).',
                AuthenticationFailureReason::UpstreamResponseRefused,
            );
        }
        $interaction = $remembered->interaction === null ? null : $this->resumable($request, $tenant, $remembered->interaction, $now);
        try {
            $assertion = $consumer->receive($tenant, $request->request->all(), $remembered->identityProvider, $remembered->requestId);
        } catch (UpstreamAuthenticationFailedException $failure) {
            throw $this->failedAtTheProvider($request, $interaction, $failure);
        } catch (AssertionRefusedException $exception) {
            throw $this->refused($exception->getMessage(), AuthenticationFailureReason::UpstreamResponseRefused);
        } catch (KeyNotFoundException) {
            // S-66: a key of the provider retired between the reading of the store and its opening
            throw $this->refused(
                'A key of the identity provider retired while the response was read (spec/saml.md S-66).',
                AuthenticationFailureReason::UpstreamResponseRefused,
            );
        }
        // S-57: held to the floor of the tenant before the person is written, the opening of the session refusing it
        // past the firewall otherwise, where nothing catches it
        if (! $tenant->loginFloor->isSatisfiedBy($assertion->methods)) {
            throw $this->refused(
                'The login of the identity provider proves less than this tenant requires of every login (spec/saml.md S-57).',
                AuthenticationFailureReason::BelowTheFloor,
            );
        }
        if ($assertion->sessionNotOnOrAfter !== null && $assertion->sessionNotOnOrAfter <= $now) {
            throw $this->refused('The session the identity provider allows is over (spec/saml.md S-57).', AuthenticationFailureReason::UpstreamResponseRefused);
        }
        $context = $this->contexts->fromRequest($request);
        try {
            $person = $consumer->personOf($tenant, $assertion, $context);
        } catch (UpstreamProvisioningRefusedException $exception) {
            // a disabled person is announced as such, under the page of every refusal of the person, which says
            // nothing of the state of the account (S-56)
            throw $this->personRefused(
                $exception->reason === UpstreamProvisioningRefusalReason::PersonDisabled
                    ? AuthenticationFailureReason::DisabledUser
                    : AuthenticationFailureReason::UpstreamPersonRefused,
            );
        } catch (InvalidArgumentException) {
            throw $this->personRefused(AuthenticationFailureReason::UpstreamPersonRefused);
        }
        $held = $this->browser->authenticationSession($request, $tenant);
        if ($interaction instanceof Interaction) {
            $this->assertNothingMoreAsked($request, $tenant, $interaction, $remembered, $person, $assertion, $held, $context, $now);
        } else {
            $this->assertThePageIsAnswered($remembered, $person, $assertion, $held, $context, $now);
        }
        $request->attributes->set(self::REMEMBERED, $remembered);

        return new SelfValidatingPassport(
            new UserBadge($person->username, static fn (): SecurityUser => new SecurityUser($person, null)),
            [new UpstreamCredentials($assertion->methods, $assertion->authenticatedAt, $assertion->sessionNotOnOrAfter)],
        );
    }

    /**
     * The token of AbstractAuthenticator, which a readonly class cannot extend.
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }

    /**
     * S-59: the login page of the interaction, which resumes it and answers the client, or the page that waited, its
     * route and its parameters as LoginTarget wrote them; nothing a response or a request carried.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $remembered = $request->attributes->get(self::REMEMBERED);
        if (! $remembered instanceof RememberedSignOn) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED);
        }
        if ($remembered->page !== null) {
            return $this->pages->redirectToRoute($remembered->page->route, $remembered->page->parameters);
        }

        return $this->pages->redirectToRoute(LoginController::ROUTE, [
            AuthorizationResponder::INTERACTION_PARAMETER => (string) $remembered->interaction,
        ]);
    }

    /**
     * What authenticate() decided, or the page of a refusal for what the firewall refused after it, a person whose
     * account is disabled.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        if ($exception instanceof UpstreamLoginRefusedException) {
            return $exception->answer;
        }

        return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED);
    }

    public function isInteractive(): bool
    {
        return true;
    }

    /**
     * S-53: the interaction of the request remembered, one this browser began and can still resume.
     *
     * @throws UpstreamLoginRefusedException
     */
    private function resumable(Request $request, Tenant $tenant, string $id, DateTimeImmutable $now): Interaction
    {
        $interaction = $this->browser->pending($request, $tenant, $id);
        if (! $interaction instanceof Interaction) {
            throw new UpstreamLoginRefusedException($this->responder->unknownInteraction());
        }
        try {
            $interaction->assertResumable($now);
        } catch (InteractionExpiredException|InteractionCompletedException $exception) {
            throw new UpstreamLoginRefusedException($this->responder->unresumable($request, $interaction, $exception), previous: $exception);
        }

        return $interaction;
    }

    /**
     * S-58: what the client still asks of the login, read by the rule of the login page against the session this login
     * leaves; asked, the request is sent once more with ForceAuthn when the one answered did not carry it, and the
     * client is answered login_required when it did.
     *
     * @throws UpstreamLoginRefusedException
     */
    private function assertNothingMoreAsked(
        Request $request,
        Tenant $tenant,
        Interaction $interaction,
        RememberedSignOn $remembered,
        User $person,
        UpstreamAssertion $assertion,
        ?AuthenticationSession $held,
        RequestContext $context,
        DateTimeImmutable $now,
    ): void {
        try {
            $asked = $this->requirement->stillAsked($interaction, $person, $assertion->methods, $assertion->authenticatedAt, $held, $context, $now);
            if ($asked === null) {
                return;
            }
            if ($remembered->forceAuthn) {
                throw $asked === LoginRequirement::AccountSelectionRequested
                    ? new AccountSelectionRequiredException('The identity provider answered for the person it holds a session of, ForceAuthn notwithstanding.')
                    : new LoginRequiredException('The identity provider did not authenticate the person as the request asks, ForceAuthn notwithstanding.');
            }
        } catch (OAuth2Exception $exception) {
            throw new UpstreamLoginRefusedException(
                $this->responder->failure($request, $interaction->request->redirectTarget(), $exception, $interaction),
                previous: $exception,
            );
        }
        $signOn = $this->signOn ?? throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        try {
            $sent = $signOn->start($tenant, $remembered->identityProvider, true);
        } catch (UpstreamSignOnRefusedException $exception) {
            // no refused login: the request could not be sent again, which the sign-on refuses with the same message
            throw $this->refused($exception->getMessage(), null);
        } catch (KeyNotFoundException $exception) {
            // as the route of the sign-on answers a tenant that holds no SAML key any more (S-51)
            throw new NotFoundHttpException('This tenant serves no SAML service provider.', $exception);
        }
        $this->signOns->keep($request->getSession(), $tenant, $interaction, $sent);

        throw new UpstreamLoginRefusedException($this->answers->of($sent), 'The request is sent once more with ForceAuthn (spec/saml.md S-58).');
    }

    /**
     * S-59: a page that asked a person signed in for a fresh proof is answered by an authentication after its request
     * was issued, and one that asked for one more by a login that proves one of the classes it asked for; neither is
     * sent again, its request having carried ForceAuthn already.
     *
     * @throws UpstreamLoginRefusedException
     */
    private function assertThePageIsAnswered(
        RememberedSignOn $remembered,
        User $person,
        UpstreamAssertion $assertion,
        ?AuthenticationSession $held,
        RequestContext $context,
        DateTimeImmutable $now,
    ): void {
        if ($remembered->forceAuthn && $assertion->authenticatedAt < $remembered->issuedAt) {
            throw $this->refused(
                'The identity provider did not authenticate the person again, ForceAuthn notwithstanding (spec/saml.md S-59).',
                AuthenticationFailureReason::UpstreamResponseRefused,
                $person,
            );
        }
        $stepUp = $remembered->page?->stepUp;
        if ($stepUp !== null && ! $this->requirement->meets($stepUp, $person, $assertion->methods, $assertion->authenticatedAt, $held, $context, $now)) {
            throw $this->refused(
                'The identity provider proved none of the classes the page asks for (spec/saml.md S-59).',
                AuthenticationFailureReason::UpstreamResponseRefused,
                $person,
            );
        }
    }

    /**
     * S-58: the provider authenticated nobody, the person having cancelled or failed there. The client is answered
     * access_denied at its redirection URI with its state, login_required for NoPassive under prompt=none, the
     * interaction over; a page that waited is the page of a refusal. Nothing of the provider travels in either.
     */
    private function failedAtTheProvider(
        Request $request,
        ?Interaction $interaction,
        UpstreamAuthenticationFailedException $failure,
    ): UpstreamLoginRefusedException {
        if (! $interaction instanceof Interaction) {
            return $this->refused($failure->getMessage(), null);
        }
        $answer = $failure->noPassive && $interaction->request->hasPrompt(Prompt::None)
            ? new LoginRequiredException('The identity provider authenticated nobody without asking the person.')
            : new AccessDeniedException('The identity provider authenticated nobody.');

        return new UpstreamLoginRefusedException(
            $this->responder->failure($request, $interaction->request->redirectTarget(), $answer, $interaction),
            $failure->getMessage(),
        );
    }

    /**
     * S-56: the person the response named refused, by the core or by the profile. The refusal of the core names no
     * value, and the claim the profile refuses would: neither travels on (S-53), and the page is the same whatever the
     * reason the audit trail is told.
     */
    private function personRefused(AuthenticationFailureReason $reason): UpstreamLoginRefusedException
    {
        return $this->refused('The person the identity provider named is not one this provider signs in (spec/saml.md S-56).', $reason);
    }

    /**
     * The page of a refusal, and what the audit trail is told of it (S-53): a federated assertion refused for that
     * reason, nothing typed, the person when one was resolved; none when it is no refused login. No exception it
     * caught travels on: the message of the rule is all a refusal carries, whatever the chain under it named.
     */
    private function refused(string $description, ?AuthenticationFailureReason $reason, ?User $person = null): UpstreamLoginRefusedException
    {
        return new UpstreamLoginRefusedException(
            $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED, $description),
            $description,
            null,
            $reason === null ? null : new LoginFailure(new AuthenticationMethod(AuthnContextMethods::FEDERATED), $reason, null, $person),
        );
    }
}
