<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * How the browser carries a request of the service provider of a tenant to an upstream identity provider (beffroi/saml,
 * spec/saml.md S-51): a 302 to the URL of HTTP-Redirect, or the page that posts the form of HTTP-POST, both never
 * cached (Bindings §3.4.5.1, §3.5.5.1). The answer of the route of the sign-on, and of the assertion consumer service
 * when it sends the request once more (S-58).
 */
final readonly class UpstreamSignOnAnswer
{
    public function __construct(
        private SamlPostPage $page,
    ) {
    }

    public function of(SentAuthnRequest $sent): Response
    {
        if ($sent->message instanceof RedirectedMessage) {
            return new RedirectResponse($sent->message->url, Response::HTTP_FOUND, [
                ...InteractionPages::HEADERS,
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ]);
        }

        return $this->page->signOnRequest($sent->message);
    }
}
