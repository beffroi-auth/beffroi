<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Session;

/**
 * How a session ended, which its author agrees with (decision 0066); reaching its expiry ends none, so no case names it.
 */
enum SessionEnd: string
{
    /**
     * The person ended it at the provider.
     */
    case User = 'user';

    /**
     * An act of administration ended it: an administrator of the tenant, the console of the host, or a disabling,
     * whoever its author.
     */
    case Administrator = 'administrator';

    /**
     * The person ended it through a relying party.
     */
    case RelyingParty = 'relying_party';

    /**
     * The host ended it by a rule of its own: another person signed in from the browser that held it.
     */
    case Security = 'security';
}
