<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Port\ProfileClaimsInterface;

/**
 * The claims the profile of a person holds in a deployment under test (spec/saml.md S-45): those the bundle wires by
 * default, the profile of OIDC Core §5.1 and the telephone number, unless a test names others.
 */
final readonly class FixedProfileClaims implements ProfileClaimsInterface
{
    public const array WIRED = [
        'name',
        'given_name',
        'family_name',
        'middle_name',
        'nickname',
        'preferred_username',
        'birthdate',
        'gender',
        'locale',
        'zoneinfo',
        'profile',
        'picture',
        'website',
        'phone_number',
    ];

    /**
     * @param list<string> $names
     */
    public function __construct(
        private array $names = self::WIRED,
    ) {
    }

    public function names(): array
    {
        return $this->names;
    }
}
