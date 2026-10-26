<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Oidc\Domain\Client\RedirectUri;
use LogicException;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * Where a form of a page of the interaction plane may send the browser (CSP Level 3 §6.1, §6.3.2): the URI
 * a client registered, which is where a page that completes an authorization request or a logout request
 * sends it.
 *
 * A browser checks "form-action" over the whole redirect chain of a submission and not over the URL the
 * form names: a login page whose policy says "form-action 'self'" posts the password to this provider,
 * follows the redirection that answers it, and refuses the next one, which is the one carrying the code to
 * the client. Nothing reaches the client, the browser stays on the page it posted from and the interaction
 * is spent, so a page that may answer a client names the origin of that client.
 *
 * A deployment cannot name it: a redirection URI belongs to a client, a client may register itself
 * (RFC 7591), and which one is asking is read from the request the page is resuming. So the page names it
 * here and the directive of the policy the answer carries is completed with it, whichever policy that is
 * (PolicyCompletion). A policy naming no "form-action" allows every submission and is left alone, the
 * directive falling back to no other.
 */
final readonly class FormTarget
{
    /**
     * Where the origins of a page wait between the controller that names them and the answer that carries
     * them.
     */
    private const string ATTRIBUTE = '_beffroi_form_targets';

    private const string DIRECTIVE = 'form-action';

    private PolicyCompletion $completion;

    public function __construct()
    {
        $this->completion = new PolicyCompletion(self::ATTRIBUTE, self::DIRECTIVE);
    }

    /**
     * Named by a page that may send the browser to this client, once per client it may answer.
     */
    public function mayEndAt(Request $request, RedirectUri $uri): void
    {
        $this->mayReach($request, $uri->origin);
    }

    /**
     * Named by a page whose submission may be answered with redirections through this origin, once per origin: the
     * single logout service of a SAML service provider a chain of logout goes to (beffroi/saml S-36).
     *
     * @throws LogicException when the value is not an origin (SourceOrigin)
     */
    public function mayReach(Request $request, string $origin): void
    {
        $this->completion->mayReach($request, $origin);
    }

    #[AsEventListener(event: ResponseEvent::class, priority: PolicyCompletion::AFTER_THE_POLICY_IS_WRITTEN)]
    public function onKernelResponse(ResponseEvent $event): void
    {
        $this->completion->complete($event);
    }
}
