<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use DateTimeImmutable;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * A login whose proofs were given before the request that carries them, and says when: what an upstream identity
 * provider proved is dated by the instant it says the person authenticated, its AuthnInstant, the auth_time of the
 * session (beffroi/saml S-57, OIDC Core §2). A login that proves now implements nothing, and the session it opens or
 * refreshes dates its proofs by the request, as every login of the firewall does.
 */
interface DatesItsProofsInterface extends ProvingLoginInterface
{
    /**
     * When what this passport proved was proven, null when the passport is another login's.
     */
    public function provenAt(Passport $passport): ?DateTimeImmutable;
}
