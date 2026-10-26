<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Controller\PasskeyLoginController;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\PasskeyOptionsStore;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Port\PasskeyAuthenticatorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

/**
 * The passkey login on the firewall of the interaction pages (architecture §5.4), next to the form login:
 * the assertion the browser signed, posted by the login page as a form with the same CSRF token, verified
 * by the ceremony of the core against the options this browser was given, the passport carrying what was
 * proven (PasskeyCredentials) for the one LoginSuccessListener that sees both logins. A passkey of another
 * tenant, a revoked one, an assertion whose backup eligibility is not the one of the enrolment and the
 * passkey of a person of a federated domain (decision 0029) are refused after the signature, so that a
 * refusal costs the same; a disabled user is refused by the UserChecker after, as with a password.
 */
final readonly class PasskeyLoginAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface
{
    public const string CSRF_TOKEN_ID = 'authenticate';

    public const string CSRF_TOKEN_PARAMETER = '_csrf_token';

    public const string ASSERTION_PARAMETER = '_passkey';

    public function __construct(
        private TenantProvider $tenants,
        private PasskeyOptionsStore $options,
        private PasskeyAuthenticatorInterface $ceremony,
        private InteractionLoginHandler $handler,
        private FederatedDomains $federated,
    ) {
    }

    public function supports(Request $request): bool
    {
        return $request->isMethod('POST') && $request->attributes->getString('_route') === PasskeyLoginController::ROUTE;
    }

    public function authenticate(Request $request): Passport
    {
        $assertion = $request->request->getString(self::ASSERTION_PARAMETER);
        $token = $request->request->getString(self::CSRF_TOKEN_PARAMETER);
        if ($assertion === '') {
            throw new AuthenticationException('The login carries no assertion.');
        }
        $options = $this->options->takeRequest($request->getSession()) ?? throw new AuthenticationException('No passkey ceremony is pending for this browser.');
        $tenant = $this->tenants->provide();
        try {
            $verified = $this->ceremony->verifyAssertion($tenant, $options, $assertion);
        } catch (PasskeyCeremonyFailedException $exception) {
            throw new PasskeyLoginException(AuthenticationFailureReason::InvalidCredential, previous: $exception);
        }
        $credential = $verified->credential;
        $method = $credential->methods($verified->authenticatorData)[0];
        if (! $credential->tenant->equals($tenant)) {
            throw new PasskeyLoginException(AuthenticationFailureReason::InvalidCredential, $method);
        }
        if ($credential->backupEligibilityChanged($verified->authenticatorData)) {
            throw new PasskeyLoginException(AuthenticationFailureReason::InvalidCredential, $method, $credential->user);
        }
        if ($credential->isRevoked()) {
            throw new PasskeyLoginException(AuthenticationFailureReason::RevokedCredential, $method, $credential->user);
        }
        // decision 0029, beffroi/saml S-63: a person of a federated domain signs in through their provider and
        // through nothing else, whatever the page offered them
        if (! $this->federated->admitsLocalCredentials($credential->user)) {
            throw new PasskeyLoginException(AuthenticationFailureReason::FederatedDomain, $method, $credential->user);
        }

        return new Passport(
            new UserBadge($credential->user->username),
            new PasskeyCredentials($verified),
            [new CsrfTokenBadge(self::CSRF_TOKEN_ID, $token)],
        );
    }

    /**
     * The token of AbstractAuthenticator, which a readonly class cannot extend.
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        return $this->handler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->handler->onAuthenticationFailure($request, $exception);
    }

    public function isInteractive(): bool
    {
        return true;
    }
}
