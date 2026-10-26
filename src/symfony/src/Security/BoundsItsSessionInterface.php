<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use DateTimeImmutable;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * A login whose proofs come with the instant the session they open must end by: an upstream identity provider allows
 * the session it vouches for until its SessionNotOnOrAfter (SAML Core §2.7.2, beffroi/saml S-57), and the session of
 * the core ends no later. A login that bounds nothing implements nothing, and its session lives the lifetime the core
 * gives it.
 */
interface BoundsItsSessionInterface extends ProvingLoginInterface
{
    /**
     * The instant the session must end by, null when the passport is another login's or bounds nothing.
     */
    public function sessionNotOnOrAfter(Passport $passport): ?DateTimeImmutable;
}
