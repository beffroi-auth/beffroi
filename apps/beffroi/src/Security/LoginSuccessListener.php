<?php

declare(strict_types=1);

namespace App\Security;

use Beffroi\Core\Domain\Author\TheHost;
use function array_map;
use DateTimeImmutable;
use App\Doctrine\TenantProvider;
use App\Http\BrowserSession;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Opens the session of the core after a firewall login and binds the browser to it.
 */
final readonly class LoginSuccessListener
{
    /**
     * @param iterable<DatesItsCredentialInterface> $logins
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

        $provenAt = $this->proofs->provenAt($passport);
        $notOnOrAfter = $this->proofs->sessionNotOnOrAfter($passport);
        $session = $this->browser->authenticationSession($request, $tenant);
        if ($session !== null && $session->user->id->equals($user->id)) {
            foreach ($methods as $method) {
                $session->recordProof($method, $context, $provenAt);
            }
            if ($notOnOrAfter !== null) {
                $session->expireNoLaterThan($notOnOrAfter);
            }
            $this->sessions->save($session);
        } else {
            // The person who signed in did not end the session of another: one browser holds one session, by the host's rule.
            if ($session !== null) {
                $this->terminator->end($session, SessionEnd::Security, new TheHost(), $context);
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

    private function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): void
    {
        foreach ($this->logins as $login) {
            if ($login->recordUse($passport, $user, $now, $context)) {
                return;
            }
        }
    }
}
