<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use function array_any;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use function sprintf;
use Beffroi\Oidc\Port\ProvableMethodsInterface;
use LogicException;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * What the logins of the firewall prove, as the core names it (RFC 8176 §2), in one place: what a given
 * passport proved, for the session the listener opens, and everything a login here may prove, for the
 * discovery and the step-up (decision 0010). Neither is an enumeration: both are read from the logins
 * that are tagged (ProvingLoginInterface), so that what the provider announces is what is wired, and a
 * login added to the firewall is a class tagged and nothing edited.
 */
final readonly class PassportProofs implements ProvableMethodsInterface
{
    /**
     * @param iterable<ProvingLoginInterface> $logins the logins of the firewall, at least one
     */
    public function __construct(
        private iterable $logins,
    ) {
    }

    /**
     * The first login that recognises the passport answers; they are mutually exclusive, a passport
     * carrying the badge of one login only. A firewall that authenticates another way is refused loudly
     * rather than recorded wrongly.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function methods(Passport $passport): array
    {
        foreach ($this->logins as $login) {
            $methods = $login->proofs($passport);
            if ($methods !== null) {
                return $methods;
            }
        }

        throw new LogicException('The firewall authenticated a user of the bundle with a login none of the tagged ones recognises: the passport carries the badge of no login of the bundle.');
    }

    /**
     * When what the passport proved was proven, null when it was proven now: the first login that dates its proofs and
     * recognises the passport answers (DatesItsProofsInterface, beffroi/saml S-57).
     */
    public function provenAt(Passport $passport): ?DateTimeImmutable
    {
        foreach ($this->logins as $login) {
            $provenAt = $login instanceof DatesItsProofsInterface ? $login->provenAt($passport) : null;
            if ($provenAt !== null) {
                return $provenAt;
            }
        }

        return null;
    }

    /**
     * The instant the session the passport opens must end by, null when nothing bounds it: the first login that bounds
     * its session and recognises the passport answers (BoundsItsSessionInterface, beffroi/saml S-57).
     */
    public function sessionNotOnOrAfter(Passport $passport): ?DateTimeImmutable
    {
        foreach ($this->logins as $login) {
            $bound = $login instanceof BoundsItsSessionInterface ? $login->sessionNotOnOrAfter($passport) : null;
            if ($bound !== null) {
                return $bound;
            }
        }

        return null;
    }

    /**
     * Every method the wired logins prove for this tenant, each once, in the order they are tagged: a login
     * whose proofs the floor of the tenant never reads is a login closed there (issue #327), so it is asked
     * login by login and not method by method, a passkey that proves "user" besides its key not being half
     * admitted.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function provableMethods(Tenant $tenant): array
    {
        $methods = [];
        $wired = 0;
        foreach ($this->logins as $login) {
            ++$wired;
            if (! $tenant->loginFloor->admits($login->everyProvableMethod())) {
                continue;
            }
            foreach ($login->everyProvableMethod() as $method) {
                if (! array_any($methods, static fn (AuthenticationMethod $known): bool => $known->equals($method))) {
                    $methods[] = $method;
                }
            }
        }
        if ($methods === [] && $wired === 0) {
            throw new LogicException('The firewall of the interaction pages offers at least one login.');
        }
        if ($methods === []) {
            throw new LogicException(sprintf(
                'No login of the firewall of the interaction pages proves what the tenant "%s" requires of every login, "%s".',
                $tenant->slug,
                $tenant->loginFloor->name(),
            ));
        }

        return $methods;
    }
}
