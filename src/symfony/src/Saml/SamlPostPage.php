<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_map;
use function array_unique;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\SourceOrigin;
use Beffroi\Oidc\Domain\Page\InlineScript;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use function implode;
use LogicException;
use function parse_url;
use const PHP_URL_HOST;
use const PHP_URL_PORT;
use const PHP_URL_SCHEME;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page that posts a form of SAML (beffroi/saml, spec/saml.md section 6.8, spec/bindings.md section 6.7): the form
 * PostSender returned, from a template an application may override, submitted by one script its
 * Content-Security-Policy names by its hash (CSP Level 3 §6.6.2.2), as the page of the form post response mode names
 * its own; nothing loads and nothing frames it. The caching headers are those of the binding (SAML Bindings
 * §3.5.5.1). Three renderings, one per kind of endpoint the form posts to, since where its submission goes next is not
 * the same (S-36, S-51):
 *
 * - a response of single sign-on, to an assertion consumer service, names no "form-action": that service answers the
 *   post with a redirection to where its application lives, often another origin nobody states (Entra's login.srf
 *   sends the browser on to the client that asked it), a browser checks the directive over every redirection of the
 *   submission, and the directive does not fall back to "default-src" (CSP Level 2 §7.6). This is where the page
 *   parts from the page of the form post response mode, which names the origin of the redirection URI;
 * - an AuthnRequest of the service provider of the tenant, to the single sign-on service of an upstream identity
 *   provider, names none either, for the same reason: that service answers the post with a redirection to its login
 *   page, at an origin no metadata state; its words say the browser goes to the sign-in of its organisation, and not
 *   back to an application;
 * - a message of Single Logout, to a single logout service, names in its "form-action" the origin of its action and
 *   of each URL the form reaches: a LogoutRequest of a chain may be answered by a redirection of the submission back
 *   to the provider, which carries the chain on by redirections; a LogoutResponse, which nobody answers, reaches
 *   nothing more.
 */
final readonly class SamlPostPage
{
    public const string TEMPLATE = 'saml_post.html.twig';

    /**
     * What submits the form where the browser runs scripts. A constant, because the hash of the policy is computed
     * from it.
     */
    public const string SCRIPT = 'document.forms[0].submit();';

    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    /**
     * A response of single sign-on, a success or a failure, posted to the assertion consumer service.
     */
    public function signOnResponse(PostedForm $form): Response
    {
        return $this->render($form, self::policyWithoutFormAction());
    }

    /**
     * An AuthnRequest of the service provider of the tenant, posted to the single sign-on service of an upstream
     * identity provider (spec/saml.md S-51).
     */
    public function signOnRequest(PostedForm $form): Response
    {
        return $this->render($form, self::policyWithoutFormAction(), upstream: true);
    }

    /**
     * A LogoutRequest or a LogoutResponse, posted to the single logout service of a service provider.
     */
    public function logoutMessage(PostedForm $form): Response
    {
        return $this->render($form, sprintf(
            "default-src 'none'; script-src '%s'; form-action %s; base-uri 'none'; frame-ancestors 'none'",
            new InlineScript(self::SCRIPT)->cspHashSource(),
            implode(' ', array_unique(array_map(self::originOf(...), [$form->action, ...$form->reaches]))),
        ));
    }

    /**
     * @param bool $upstream whether the form goes to an upstream identity provider, which the words of the page say
     */
    private function render(PostedForm $form, string $policy, bool $upstream = false): Response
    {
        return $this->pages->render(
            self::TEMPLATE,
            [
                'action' => $form->action,
                'fields' => $form->fields,
                'script' => self::SCRIPT,
                'upstream' => $upstream,
            ],
            headers: [
                'Content-Security-Policy' => $policy,
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ],
        );
    }

    /**
     * The one script by its hash, nothing else loaded or framing the page, and no "form-action" (S-36, S-51).
     */
    private static function policyWithoutFormAction(): string
    {
        return sprintf(
            "default-src 'none'; script-src '%s'; base-uri 'none'; frame-ancestors 'none'",
            new InlineScript(self::SCRIPT)->cspHashSource(),
        );
    }

    /**
     * The scheme, the host and the port of the URL, which a "form-action" names (CSP Level 3 §2.3.1), and nothing that
     * would split the policy it is written into (SourceOrigin, S-36).
     *
     * @throws LogicException when the URL has no such origin, which the reading of the metadata refuses first (S-11)
     */
    public static function originOf(string $url): string
    {
        $port = parse_url($url, PHP_URL_PORT);

        return SourceOrigin::of(sprintf(
            '%s://%s%s',
            (string) parse_url($url, PHP_URL_SCHEME),
            (string) parse_url($url, PHP_URL_HOST),
            $port === null || $port === false ? '' : ':' . $port,
        ));
    }
}
