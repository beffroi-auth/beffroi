<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_slice;
use function explode;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use LogicException;
use function preg_split;
use function strtolower;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use function trim;

/**
 * What a page of the interaction plane adds to the Content-Security-Policy its answer carries: one
 * directive, and the origins that page may reach through it (CSP Level 3 §6.1, §6.3).
 *
 * A page says what it adds and never what the whole policy is, because the whole policy belongs to the
 * deployment: the floor of the plane restricts nothing and comes out as it went in (InteractionPages),
 * and the policy an application writes for its pages is completed once it is written (apps/op
 * config/packages/nelmio_security.yaml). A page that wrote a policy of its own would be a page served
 * without the other directives of that deployment, and nothing would say so: a policy nobody merges is a
 * policy that goes missing in silence.
 *
 * What a page may reach is read from the request it is resuming, so a deployment cannot name it: a
 * redirection URI belongs to a client, the logo of a client is served by a host that client named, and a
 * client may register itself (RFC 7591). The origins are named where the page that will carry them is
 * built and read where the answer leaves, as the name of an exchange is (FapiInteractionId).
 *
 * Which directive, and what that directive falls back to, is the caller's (FormTarget, ImageSource).
 */
final readonly class PolicyCompletion
{
    /**
     * After the policy of the application is written, which is the one to complete. The pages of this
     * plane leave here with the floor of the plane, an application gives way to its own by recognising
     * that floor (apps/op App\Http\DeploymentPolicyPrevails), and a floor completed before that moment is
     * another value it would no longer recognise.
     */
    public const int AFTER_THE_POLICY_IS_WRITTEN = -32;

    /**
     * What a browser refuses to combine with a source: "'none'" is a source list on its own (CSP Level 3
     * §2.2.1), so a directive that refuses everything gives way to the origins the page must reach.
     */
    private const string NO_SOURCE = "'none'";

    /**
     * The two policies an answer may carry, the enforced one and the one that only reports: a report of
     * what the provider does on purpose says nothing to anybody.
     */
    private const array HEADERS = ['Content-Security-Policy', 'Content-Security-Policy-Report-Only'];

    /**
     * @param string $attribute where the origins of a page wait between the controller that names them
     *                          and the answer that carries them
     * @param string $directive the name of the directive, written lowercase here, a directive being
     *                          matched without regard to case (CSP Level 3 §2.2)
     * @param string|null $fallsBackTo the directive this one falls back to, so that a policy naming that
     *                                 one and not this one is completed with this one written out of it
     *                                 (CSP Level 3 §6.1, where "default-src" answers for every fetch
     *                                 directive a policy leaves out); null when it falls back to no
     *                                 other, a policy leaving it out then restricting nothing
     */
    public function __construct(
        private string $attribute,
        private string $directive,
        private ?string $fallsBackTo = null,
    ) {
    }

    /**
     * Named by a page that may reach this origin through this directive, once per origin it may reach. The origin is
     * written into the header as it is named, so a value that is no origin is refused here, where the page names it
     * (SourceOrigin), and not when the answer leaves, where an exception would replace the page by an error page the
     * kernel sends without the listeners left to run.
     *
     * @throws LogicException when the value is not an origin
     */
    public function mayReach(Request $request, string $origin): void
    {
        $origin = SourceOrigin::of($origin);
        $origins = $this->named($request);
        if (in_array($origin, $origins, true)) {
            return;
        }
        $origins[] = $origin;
        $request->attributes->set($this->attribute, $origins);
    }

    /**
     * The policies the answer carries, each one completed with what the page named.
     */
    public function complete(ResponseEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }
        $origins = $this->named($event->getRequest());
        if ($origins === []) {
            return;
        }
        $headers = $event->getResponse()->headers;
        foreach (self::HEADERS as $header) {
            $policies = $headers->all($header);
            if ($policies === []) {
                continue;
            }
            $headers->remove($header);
            foreach ($policies as $policy) {
                $headers->set($header, $this->completed((string) $policy, $origins), false);
            }
        }
    }

    /**
     * The same policy with the origins named in this directive: in the directive the policy wrote, in
     * this directive written out of the one it falls back to when the policy names that one alone, and
     * nowhere when it names neither and the directive restricts nothing.
     *
     * @param non-empty-list<string> $origins
     */
    private function completed(string $policy, array $origins): string
    {
        $directives = [];
        $completed = false;
        $fallback = null;
        foreach (explode(';', $policy) as $directive) {
            $directive = trim($directive);
            if ($directive === '') {
                continue;
            }
            $written = preg_split('/\s+/', $directive);
            if ($written === false) {
                $directives[] = $directive;

                continue;
            }
            $name = strtolower($written[0]);
            if ($name === $this->directive) {
                $directives[] = implode(' ', self::sourcesOf($written[0], array_slice($written, 1), $origins));
                $completed = true;

                continue;
            }
            if ($name === $this->fallsBackTo) {
                $fallback = array_slice($written, 1);
            }
            $directives[] = $directive;
        }
        if ($completed) {
            return implode('; ', $directives);
        }
        if ($fallback === null) {
            return $policy;
        }
        $directives[] = implode(' ', self::sourcesOf($this->directive, $fallback, $origins));

        return implode('; ', $directives);
    }

    /**
     * The directive and its sources, with the origins the page named added to them.
     *
     * @param string $name the name as the policy wrote it, a directive the page did not name being
     *                     written with the name of this one
     * @param list<string> $written the sources the directive carries
     * @param non-empty-list<string> $origins
     *
     * @return non-empty-list<string>
     */
    private static function sourcesOf(string $name, array $written, array $origins): array
    {
        $sources = [$name];
        foreach ($written as $source) {
            if ($source !== self::NO_SOURCE) {
                $sources[] = $source;
            }
        }
        foreach ($origins as $origin) {
            if (! in_array($origin, $sources, true)) {
                $sources[] = $origin;
            }
        }

        return $sources;
    }

    /**
     * @return list<string>
     */
    private function named(Request $request): array
    {
        $origins = $request->attributes->get($this->attribute);
        if (! is_array($origins)) {
            return [];
        }
        $named = [];
        foreach ($origins as $origin) {
            if (is_string($origin)) {
                $named[] = $origin;
            }
        }

        return $named;
    }
}
