<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The cookie that binds a chain of SAML logout to the browser that began it (beffroi/saml, spec/saml.md S-32): the
 * secret the chain keeps the SHA-256 of, given to that browser when the chain begins and again at each of its steps,
 * read back at every step, cleared where the chain ends. It binds and holds nothing else: where the chain stands is
 * the row of the chain, never this cookie.
 */
final readonly class LogoutChainCookie
{
    /**
     * The "__Host-" prefix of the name reverses who checks three of the attributes below: a browser refuses the cookie
     * outright unless it is Secure, its path "/" and no Domain named, so that a subdomain of the provider can neither
     * write it nor read it.
     */
    public const string NAME = '__Host-beffroi_saml_logout';

    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    /**
     * The secret the browser presents, null when it presents none.
     */
    public function presented(Request $request): ?LogoutChainSecret
    {
        $value = $request->cookies->getString(self::NAME);

        return $value === '' ? null : new LogoutChainSecret($value);
    }

    /**
     * $response given the cookie of $secret, for the ten minutes the chain is open from this step.
     */
    public function given(Response $response, LogoutChainSecret $secret): Response
    {
        /**
         * No script reads it (HttpOnly), it is never sent in clear (Secure), and it goes with the answer a service
         * provider posts from its site over HTTP-POST, a cross-site post under which a browser holds back a cookie that
         * says Lax (SameSite=None); the chain is a series of top-level navigations, so the blocking of third-party
         * cookies does not apply to it.
         */
        $response->headers->setCookie(Cookie::create(
            self::NAME,
            $secret->value,
            $this->clock->now()->getTimestamp() + LogoutChain::TTL,
            '/',
            null,
            true,
            true,
            false,
            Cookie::SAMESITE_NONE,
        ));

        return $response;
    }

    /**
     * $response clearing the cookie, the chain being over.
     */
    public function cleared(Response $response): Response
    {
        $response->headers->clearCookie(self::NAME, '/', null, true, true, Cookie::SAMESITE_NONE);

        return $response;
    }
}
