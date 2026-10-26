<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_filter;
use function array_slice;
use function array_values;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use function in_array;
use function is_array;
use function is_string;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The cookie side of architecture §3.2: the AuthenticationSession the browser is bound to, and the
 * interactions it began, which only it may resume (§4.3). The list of interactions is bounded, the oldest
 * forgotten first. An interaction forgotten takes with it what the step of the address kept for it
 * (LoginAddresses, beffroi/saml S-68), the address of a sign-on it never reached among it.
 */
final readonly class BrowserSession
{
    public const string AUTHENTICATION_SESSION_KEY = '_beffroi_session';

    public const string INTERACTIONS_KEY = '_beffroi_interactions';

    public const int MAX_PENDING_INTERACTIONS = 8;

    public function __construct(
        private AuthenticationSessionRepositoryInterface $sessions,
        private InteractionRepositoryInterface $interactions,
        private ClockInterface $clock,
        private LoginAddresses $addresses = new LoginAddresses(),
    ) {
    }

    /**
     * Null unless the session named is of this tenant and still active.
     */
    public function authenticationSession(Request $request, Tenant $tenant): ?AuthenticationSession
    {
        if (! $request->hasPreviousSession()) {
            return null;
        }
        $httpSession = $request->getSession();
        $id = $httpSession->get(self::AUTHENTICATION_SESSION_KEY);
        if (! is_string($id) || ! Uuid::isValid($id)) {
            return null;
        }
        $session = $this->sessions->find(Uuid::fromString($id));
        if ($session === null || ! $session->tenant->equals($tenant) || ! $session->isActive($this->clock->now())) {
            $httpSession->remove(self::AUTHENTICATION_SESSION_KEY);

            return null;
        }

        return $session;
    }

    /**
     * The HTTP session identifier is regenerated against fixation.
     */
    public function bind(SessionInterface $httpSession, AuthenticationSession $session): void
    {
        $httpSession->migrate(true);
        $httpSession->set(self::AUTHENTICATION_SESSION_KEY, $session->id->toRfc4122());
    }

    public function unbind(SessionInterface $httpSession): void
    {
        $httpSession->invalidate();
    }

    public function begin(SessionInterface $httpSession, Interaction $interaction): void
    {
        $ids = self::pendingIds($httpSession);
        if (! in_array($interaction->id, $ids, true)) {
            $ids[] = $interaction->id;
        }
        $httpSession->set(self::INTERACTIONS_KEY, array_slice($ids, -self::MAX_PENDING_INTERACTIONS));
    }

    /**
     * Null unless the interaction exists, serves this tenant and was begun by this browser, without telling which.
     */
    public function pending(Request $request, Tenant $tenant, ?string $id): ?Interaction
    {
        if ($id === null || $id === '' || ! $request->hasPreviousSession()) {
            return null;
        }
        if (! in_array($id, self::pendingIds($request->getSession()), true)) {
            return null;
        }
        $interaction = $this->interactions->find($id);
        if ($interaction === null || ! $interaction->tenant->equals($tenant)) {
            return null;
        }

        return $interaction;
    }

    public function forget(SessionInterface $httpSession, Interaction $interaction): void
    {
        $this->addresses->forget($httpSession, $interaction);
        $ids = array_values(array_filter(self::pendingIds($httpSession), static fn (string $id): bool => $id !== $interaction->id));
        if ($ids === []) {
            $httpSession->remove(self::INTERACTIONS_KEY);

            return;
        }
        $httpSession->set(self::INTERACTIONS_KEY, $ids);
    }

    /**
     * @return list<string>
     */
    private static function pendingIds(SessionInterface $httpSession): array
    {
        $ids = $httpSession->get(self::INTERACTIONS_KEY);
        if (! is_array($ids)) {
            return [];
        }
        $strings = [];
        foreach ($ids as $id) {
            if (is_string($id)) {
                $strings[] = $id;
            }
        }

        return $strings;
    }
}
