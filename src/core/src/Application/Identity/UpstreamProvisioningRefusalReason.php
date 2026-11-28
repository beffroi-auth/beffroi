<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Identity;

/**
 * For the audit trail only: whoever is refused reads the same message, whatever the reason.
 */
enum UpstreamProvisioningRefusalReason: string
{
    case OutsideItsDomains = 'outside_its_domains';

    case AddressHeld = 'address_held';

    /**
     * RFC 8265 §3.3: the address names the person, and the profile of a username refuses it.
     */
    case UsernameRefused = 'username_refused';

    case DrawnSubjectTaken = 'drawn_subject_taken';

    case IdentityLinkedMeanwhile = 'identity_linked_meanwhile';

    case MembershipWrittenMeanwhile = 'membership_written_meanwhile';

    case PersonDisabled = 'person_disabled';
}
