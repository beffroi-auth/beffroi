<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Controller\LoginController;
use function array_is_list;
use function is_array;
use function is_string;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The page of this provider that asked for a login and where the browser goes once it has one
 * (architecture §5.2, §5.4). Most pages that need a signed-in user are the pages of an authorization
 * request and are named by their interaction; the page where a user approves what an appliance asked
 * (RFC 8628 §3.3) is not, and it is the login of the same firewall that it needs.
 *
 * What is remembered is a route of this provider and the parameters our own code wrote, in the HTTP
 * session and never in the request: the login page reads no target path from a body, a query or a referer,
 * so a browser is never sent anywhere by whoever filled the form.
 *
 * A page that asks for one more proof rather than for a login says so, with the classes and the kinds of
 * credential the login page names (StepUpOffer, decision 0010): the page where a user answers a request
 * made for them somewhere else is not there when the browser reaches the login, so what it is asking for
 * travels in the same place as where the browser goes back to.
 *
 * It is forgotten by the page that was waiting for it, and not by the login that answered: a password
 * verified for a user who holds a second factor is not a login yet (SecondFactorGate), and a page that let
 * go of what it was waiting for at the first step would have nowhere to send the browser after the second.
 * A page that forgets it names itself (forgetIfItIsWaitingFor()) when it is reached by a browser a login
 * was sent to rather than by the login it asked for, a login that is demanded a password being sent to the
 * page of the password and not to the page that was waiting (Account\BreachedPasswordDemand).
 */
final readonly class LoginTarget
{
    public const string SESSION_KEY = '_beffroi_login_target';

    public function __construct(
        private InteractionPages $pages,
        private LoginAddresses $addresses = new LoginAddresses(),
    ) {
    }

    /**
     * Remembers the page and sends the browser to the login of the firewall, which is the login every other
     * page of the provider uses.
     *
     * @param string $route a route of this provider
     * @param array<string, string> $parameters what our own code writes into it, never what a request carried
     * @param StepUpOffer|null $stepUp what this login has to add, when the page asks for one more proof of a
     *                                 user who is signed in already rather than for a login
     */
    public function sendToLogin(
        SessionInterface $httpSession,
        string $route,
        array $parameters = [],
        ?StepUpOffer $stepUp = null,
    ): RedirectResponse {
        $httpSession->set(self::SESSION_KEY, [
            'route' => $route,
            'parameters' => $parameters,
            'step_up' => $stepUp === null
                ? null
                : [
                    'classes' => $stepUp->classes,
                    'kinds' => $stepUp->kinds,
                ],
        ]);
        // a login a page asks for begins at the step of the address when the tenant federates a domain (beffroi/saml
        // S-61), whatever was typed for the login another page asked for before
        $this->addresses->forget($httpSession, null);

        return $this->pages->redirectToRoute(LoginController::ROUTE);
    }

    /**
     * Whether a page of this provider is waiting for a login, which is what makes the login page worth
     * showing to a browser that named no interaction.
     */
    public function isPending(SessionInterface $httpSession): bool
    {
        return self::remembered($httpSession) !== null;
    }

    /**
     * The page that is waiting for a login, null when none is: what a sign-on at an upstream provider remembers
     * for the login it serves (beffroi/saml S-50), with the step-up it asked for, which the assertion consumer
     * service holds the answer of the provider to (S-59).
     */
    public function waiting(SessionInterface $httpSession): ?WaitingPage
    {
        $remembered = self::remembered($httpSession);
        if ($remembered === null) {
            return null;
        }

        return new WaitingPage($remembered['route'], $remembered['parameters'], $this->pendingStepUp($httpSession));
    }

    /**
     * What the page that is waiting asked this login to add, null when it asked for a login and not for one
     * more proof.
     */
    public function pendingStepUp(SessionInterface $httpSession): ?StepUpOffer
    {
        $remembered = self::remembered($httpSession);
        if ($remembered === null || $remembered['step_up'] === null) {
            return null;
        }

        return new StepUpOffer($remembered['step_up']['classes'], $remembered['step_up']['kinds']);
    }

    /**
     * The page served, or let go of: what the step of the address kept for its login goes with it (beffroi/saml S-68).
     */
    public function forget(SessionInterface $httpSession): void
    {
        $httpSession->remove(self::SESSION_KEY);
        $this->addresses->forget($httpSession, null);
    }

    /**
     * Forgets the page that was waiting when it is the page named, and leaves the page of somebody else
     * waiting: a login sent somewhere else on its way back (Account\BreachedPasswordDemand) lands on a page
     * that is not the one that asked for it, and that one has not been served yet.
     *
     * @param string $route the page calling, a route of this provider
     */
    public function forgetIfItIsWaitingFor(SessionInterface $httpSession, string $route): void
    {
        $remembered = self::remembered($httpSession);
        if ($remembered !== null && $remembered['route'] === $route) {
            $this->forget($httpSession);
        }
    }

    /**
     * The redirection to the page that asked, or null when none asked.
     */
    public function resume(SessionInterface $httpSession): ?RedirectResponse
    {
        $remembered = self::remembered($httpSession);

        return $remembered === null ? null : $this->pages->redirectToRoute($remembered['route'], $remembered['parameters']);
    }

    /**
     * @return array{route: string, parameters: array<string, string>, step_up: array{classes: non-empty-list<string>, kinds: non-empty-list<string>}|null}|null
     */
    private static function remembered(SessionInterface $httpSession): ?array
    {
        $remembered = $httpSession->get(self::SESSION_KEY);
        if (! is_array($remembered)) {
            return null;
        }
        $route = $remembered['route'] ?? null;
        $parameters = $remembered['parameters'] ?? null;
        if (! is_string($route) || $route === '' || ! is_array($parameters)) {
            return null;
        }
        $written = [];
        foreach ($parameters as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $written[$name] = $value;
            }
        }
        $stepUp = $remembered['step_up'] ?? null;
        $classes = is_array($stepUp) ? self::words($stepUp['classes'] ?? null) : [];
        $kinds = is_array($stepUp) ? self::words($stepUp['kinds'] ?? null) : [];

        return [
            'route' => $route,
            'parameters' => $written,
            'step_up' =>
                $classes === [] || $kinds === []
                    ? null
                    : [
                        'classes' => $classes,
                        'kinds' => $kinds,
                    ],
        ];
    }

    /**
     * A list of words this provider wrote, read back as one; anything else is nothing.
     *
     * @return list<string>
     */
    private static function words(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return [];
        }
        $words = [];
        foreach ($value as $word) {
            if (! is_string($word) || $word === '') {
                return [];
            }
            $words[] = $word;
        }

        return $words;
    }
}
