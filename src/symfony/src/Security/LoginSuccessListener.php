<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use function array_map;
use DateTimeImmutable;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Opens the session of the core after a login of the firewall, with a password, with a passkey, with the
 * code that completes a password or with the assertion of an upstream identity provider, through the SessionOpener of the core, and binds the browser to it
 * (architecture §3.2, §5.4). A password of a user who holds a second factor opens nothing yet: the
 * SecondFactorGate holds the login until the code. A re-login records its proofs on the session the
 * browser holds rather than opening another; a browser bound to someone else's session ends it first.
 * The proofs are copied into the token of Symfony (symfony/symfony#66064).
 */
final readonly class LoginSuccessListener
{
    /**
     * @param iterable<DatesItsCredentialInterface> $logins the logins that date what they proved
     */
    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionOpener $opener,
        private SessionTerminator $terminator,
        private RequestContextFactory $contexts,
        private PassportProofs $proofs,
        private SecondFactorGate $gate,
        private iterable $logins,
    ) {
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        if (! $user instanceof SecurityUser) {
            return;
        }
        $passport = $event->getPassport();
        $methods = $this->proofs->methods($passport);
        $request = $event->getRequest();
        $context = $this->contexts->fromRequest($request);
        $now = $context->receivedAt;
        if ($this->gate->holds($event, $user, $methods, $now)) {
            return;
        }
        $tenant = $this->tenants->provide();

        // what an upstream identity provider proved is dated by its AuthnInstant (beffroi/saml S-57), every other
        // login by the request
        $provenAt = $this->proofs->provenAt($passport);
        // and ends no later than that provider allows (beffroi/saml S-57)
        $notOnOrAfter = $this->proofs->sessionNotOnOrAfter($passport);
        $session = $this->browser->authenticationSession($request, $tenant);
        if ($session !== null && $session->user->id->equals($user->id)) {
            foreach ($methods as $method) {
                $session->recordProof($method, $context, $provenAt);
            }
            if ($notOnOrAfter !== null) {
                $session->endNoLaterThan($notOnOrAfter);
            }
            $this->sessions->save($session);
        } else {
            if ($session !== null) {
                $this->terminator->end($session, SessionEnd::User, $context);
            }
            $session = $this->opener->open($tenant, $user->user(), $methods, $context, $provenAt, $notOnOrAfter);
        }

        $this->recordUse($passport, $user, $now, $context);

        $this->browser->bind($request->getSession(), $session);
        $event
            ->getAuthenticatedToken()
            ->setAuthenticationProofs(array_map(
                static fn (DateTimeImmutable $provenAt): int => $provenAt->getTimestamp(),
                $session->proofs->entries,
            ));
    }

    /**
     * Each login dates what it proved and announces what its kind announces; the first that recognises
     * the passport answers, they being mutually exclusive. A login that records nothing implements
     * nothing, and nothing here knows which is which.
     */
    private function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): void
    {
        foreach ($this->logins as $login) {
            if ($login->recordUse($passport, $user, $now, $context)) {
                return;
            }
        }
    }
}
