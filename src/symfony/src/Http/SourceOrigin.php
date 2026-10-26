<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Encoding\Host;
use LogicException;
use function preg_match;

/**
 * An origin as a page names it in its Content-Security-Policy (CSP Level 3 §2.3.1): a scheme (RFC 3986 §3.1), "://", a
 * host of the core's rule (Host), letters, digits, hyphens and dots or an IPv6 literal between brackets, and an
 * optional port of digits.
 *
 * What a page names is written into the header as it is, so anything else is refused where the page names it rather
 * than pasted into the policy: a ";" in a host would end the directive and start one of its own, "sandbox" freezing
 * the page, a "," would start a policy of its own, and whitespace a source of its own (beffroi/saml S-36). What a page
 * names comes from a rule that refuses such a value first, the reading of the metadata of a service provider (beffroi/saml
 * S-11) and the URIs a client registers (ClientUri), so meeting one is a rule broken upstream: a LogicException, the page not served, rather
 * than the origin left out in silence.
 */
final readonly class SourceOrigin
{
    private const string ORIGIN = '~^[A-Za-z][A-Za-z0-9+.-]*://' . Host::PATTERN . '(?::[0-9]{1,5})?\z~';

    /**
     * @throws LogicException when the value is not an origin
     */
    public static function of(string $origin): string
    {
        if (preg_match(self::ORIGIN, $origin) !== 1) {
            throw new LogicException('A page names an origin in its Content-Security-Policy as a scheme, a host and a port, and nothing else, which would be written into the header as it is (CSP Level 3 §2.3.1, beffroi/saml S-36).');
        }

        return $origin;
    }
}
