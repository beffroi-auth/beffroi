<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Plane\Plane;
use function in_array;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * The session cookie a request from another site is not answered with (beffroi/saml, spec/saml.md S-28). Under
 * "SameSite=Lax" a browser sends the cookie with a top-level GET from another site and with no other method, and stores
 * all the same the cookie a top-level navigation from another site is answered with (RFC 6265bis, "SameSite" cookies):
 * any page of any site that posts a form to an endpoint of the interaction plane reaches it without the session the
 * browser holds, the endpoint starts one, a login form or the token of a form written in it, and its cookie replaces
 * the one the browser held, signing the browser out of the provider while the session of the core stays active.
 *
 * So a request of the interaction plane that the browser says came from another site ("Sec-Fetch-Site: cross-site",
 * Fetch Metadata Request Headers), by a method other than GET or HEAD, and that carries no session cookie, is answered
 * with none: the one the session listener of Symfony wrote is taken off the answer once written. What the endpoint
 * wrote in that session is saved, and read by nobody, no browser holding its identifier. Not saving it would mean
 * emptying the session before that listener saves it, a second hook earlier in the answer, for rows the store expires
 * anyway; it is not done. A GET is left alone: one from another site carries the cookie, so a GET without it is a
 * browser that holds no session, and the authorization endpoint starts one for the request that waits for its login.
 * A browser that does not send "Sec-Fetch-Site" is answered as before.
 *
 * An endpoint a party posts a browser to from another site on purpose, the single sign-on service, the single logout
 * service and the two endpoints of OpenID Connect, answers that post with the page that posts it again from the
 * provider's own origin (CrossSitePost), which the cookie accompanies; the page the others answer with is no page the
 * browser can go on from, its form bound to a session the browser never receives.
 */
final readonly class CrossSiteSessionCookie
{
    /**
     * After the session listener of Symfony saved the session and wrote its cookie (AbstractSessionListener, -1000).
     */
    public const int AFTER_THE_SESSION_IS_WRITTEN = -1024;

    /**
     * The methods of a top-level navigation from another site that a cookie set "SameSite=Lax" accompanies.
     */
    private const array LAX = [Request::METHOD_GET, Request::METHOD_HEAD];

    /**
     * Whether the browser sent $request from another site without the session cookie it may hold, which a cookie set
     * "SameSite=Lax" does not accompany: a method other than GET or HEAD, "Sec-Fetch-Site: cross-site", and no session
     * cookie.
     */
    public static function withheldFrom(Request $request): bool
    {
        return (
            ! in_array($request->getMethod(), self::LAX, true)
            && $request->headers->get('Sec-Fetch-Site') === 'cross-site'
            && ! $request->hasPreviousSession()
        );
    }

    #[AsEventListener(event: ResponseEvent::class, priority: self::AFTER_THE_SESSION_IS_WRITTEN)]
    public function onKernelResponse(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        if (
            ! $event->isMainRequest()
            || Plane::ofRoute($request->attributes->getString('_route')) !== Plane::Interaction
            || ! $request->hasSession(true)
            || ! self::withheldFrom($request)
        ) {
            return;
        }
        $name = $request->getSession()->getName();
        $headers = $event->getResponse()->headers;
        foreach ($headers->getCookies() as $cookie) {
            if ($cookie->getName() === $name) {
                $headers->removeCookie($name, $cookie->getPath(), $cookie->getDomain());
            }
        }
    }
}
