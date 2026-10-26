<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_pad;
use Beffroi\Oidc\Application\Request\RequestParameters as OidcRequestParameters;
use Beffroi\Oidc\Domain\Page\InlineScript;
use Beffroi\Oidc\Exception\InvalidRequestException;
use function explode;
use function preg_match;
use function sprintf;
use function str_contains;
use function strtolower;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use function trim;
use function urldecode;

/**
 * A form a browser posted from another site, which a session cookie set "SameSite=Lax" does not accompany, posted
 * again from this provider's own origin, which it does (beffroi/saml, spec/saml.md S-28). Under "Lax" a browser sends
 * the cookie with a top-level GET from another site and with no POST from one (RFC 6265bis, "SameSite" cookies), so that a
 * request a service provider or a client posts reaches the endpoint without the session the browser holds: a user
 * signed in is asked to sign in again, a logout finds no session to end and no confirmation page the browser can
 * answer, and the cookie of a new session would replace the one the browser held, which no answer to such a post
 * carries (CrossSiteSessionCookie).
 *
 * The page is served only where all of these hold, and the request is served as it came otherwise: it was posted, as
 * a form; the browser says it came from another site ("Sec-Fetch-Site: cross-site", Fetch Metadata Request Headers), which no
 * browser says of a post from this provider's own page; it carries no session cookie; and every pair of its body comes
 * back from a browser as it went, which a pair that is not UTF-8, holds a control character or a line break other than
 * CR LF, or is named "_charset_" or by nothing would not. A browser that does not send "Sec-Fetch-Site" is served as
 * today.
 *
 * What is posted again is the body the browser posted, pair by pair and in its order, repeated names included, so
 * that the endpoint reads the second post as it would have read the first and refuses what it would have refused.
 * The marker travels in the query of the action, which no endpoint reads on a post: nothing is added to the
 * fields. It names the second post and decides nothing: the second post is posted from this provider's own page, so
 * no browser says it came from another site, and that is what stops the loop. A post from another site that carries
 * the marker already is posted again as one that does not, the marker not added twice, so that no post from another
 * site, the marker forged or not, is served without the session the browser holds.
 *
 * Nothing here reads or starts the HTTP session: a cookie set on this answer would replace the one the browser holds,
 * which is what the page exists to avoid. Each endpoint a party posts a browser to from another site opts in by asking
 * first, before anything of the request is read, so that the first post spends nothing the second needs: the single
 * sign-on service and the single logout service of SAML, the authorization endpoint and the end session endpoint of
 * OpenID Connect.
 *
 * The page speaks the language every page of the interaction plane chooses (InteractionLocale, architecture §5.7):
 * the "ui_locales" of the posted body at an endpoint of OpenID Connect, then "Accept-Language". It is chosen here
 * because the endpoint has not chosen it yet, the page coming before anything reads the request.
 */
final readonly class CrossSitePost
{
    public const string TEMPLATE = 'post_again.html.twig';

    /**
     * What submits the form where the browser runs scripts. A constant, because the hash of the policy is computed
     * from it.
     */
    public const string SCRIPT = 'document.forms[0].submit();';

    /**
     * The parameter of the query of the action that says a post comes from this page (S-28).
     */
    public const string MARKER = '_beffroi_posted_again';

    /**
     * The one body posted again, whose pairs a browser writes back as they came; a multipart body is not one.
     */
    private const string FORM = 'application/x-www-form-urlencoded';

    /**
     * What a browser does not send back as it was given in a hidden field (HTML, "preprocessing the input stream" and "converting an entry list to a list of name-value pairs"):
     * a control character, which the parser drops or rewrites, a carriage return or a line feed that is not one of a
     * CR LF pair, both written back as that pair.
     */
    private const string REWRITTEN = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]|\r(?!\n)|(?<!\r)\n/';

    /**
     * The one hidden field a browser gives a value of its own, the name of its encoding (HTML, "constructing the entry list").
     */
    private const string CHARSET = '_charset_';

    public function __construct(
        private InteractionPages $pages,
        private InteractionLocale $locale,
    ) {
    }

    /**
     * Whether the body of the request is a form, `application/x-www-form-urlencoded`, its parameters aside: the one
     * body a post of HTTP-POST carries (SAML Bindings §3.5.4), and the one a browser posts back as it went, read here
     * and at every endpoint that takes one.
     */
    public static function isAForm(Request $request): bool
    {
        return strtolower(trim(explode(';', $request->headers->get('Content-Type') ?? '')[0])) === self::FORM;
    }

    /**
     * The page that posts the request again, or null when the endpoint serves the request as it came.
     */
    public function postAgain(Request $request): ?Response
    {
        return $this->page($request, []);
    }

    /**
     * postAgain() at an endpoint of OpenID Connect, its page in the "ui_locales" of the posted body (OIDC Core §3.1.2.1,
     * RP-Initiated Logout §2), read as the endpoint reads it, and none when the endpoint would refuse it, which the
     * second post then does. Nothing else of the request is resolved for it, a pushed request being spent by whoever
     * reads its reference.
     */
    public function postAgainWithItsUiLocales(Request $request): ?Response
    {
        try {
            $uiLocales = OidcRequestParameters::of(RequestParameters::ofForm($request))->uiLocales();
        } catch (InvalidRequestException) {
            $uiLocales = [];
        }

        return $this->page($request, $uiLocales);
    }

    /**
     * @param list<string> $uiLocales the languages the posted body asks for, most preferred first, none for a request
     *                                that names none
     */
    private function page(Request $request, array $uiLocales): ?Response
    {
        if (! $request->isMethod(Request::METHOD_POST) || ! self::isAForm($request) || ! CrossSiteSessionCookie::withheldFrom($request)) {
            return null;
        }
        $fields = self::fields($request->getContent());
        if ($fields === null) {
            return null;
        }
        $action = $request->getRequestUri();
        if (! $request->query->has(self::MARKER)) {
            $action .= (str_contains($action, '?') ? '&' : '?') . self::MARKER . '=1';
        }
        $this->locale->apply($request, $this->locale->choose($request, $uiLocales));

        return $this->pages->render(
            self::TEMPLATE,
            [
                'action' => $action,
                'fields' => $fields,
                'script' => self::SCRIPT,
            ],
            headers: [
                // No "form-action": the second post is answered where the endpoint sends it, a client of OpenID
                // Connect among others, and a browser checks that directive over the whole chain of redirections
                // of a submission (FormTarget), while the one form of this page is written here and posts here.
                'Content-Security-Policy' => sprintf(
                    "default-src 'none'; script-src '%s'; base-uri 'none'; frame-ancestors 'none'",
                    new InlineScript(self::SCRIPT)->cspHashSource(),
                ),
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ],
        );
    }

    /**
     * The pairs of the body, decoded as PHP decodes them, or null when one would not come back from a browser as it
     * went.
     *
     * @return non-empty-list<array{string, string}>|null
     */
    private static function fields(string $body): ?array
    {
        $fields = [];
        foreach (explode('&', $body) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $name = urldecode($name);
            $value = urldecode($value);
            if ($name === '' || $name === self::CHARSET || ! self::returns($name) || ! self::returns($value)) {
                return null;
            }
            $fields[] = [$name, $value];
        }

        return $fields === [] ? null : $fields;
    }

    private static function returns(string $text): bool
    {
        return preg_match('//u', $text) === 1 && preg_match(self::REWRITTEN, $text) === 0;
    }
}
