<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function array_intersect_key;
use function array_flip;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Saml\Port\ServedClaimsInterface;

/**
 * The claims a provider under test serves (spec/saml.md S-16): the standard claims of OpenID Connect by default, and
 * the values a test gives every user.
 */
final readonly class FixedClaims implements ServedClaimsInterface
{
    public const array STANDARD = [
        'name',
        'given_name',
        'family_name',
        'preferred_username',
        'email',
        'email_verified',
        'address',
        'updated_at',
    ];

    /**
     * @param array<string, mixed> $values by claim name, the same for every user
     * @param list<string> $names
     */
    public function __construct(
        private array $values = [],
        private array $names = self::STANDARD,
    ) {
    }

    public function names(): array
    {
        return $this->names;
    }

    public function of(User $user, array $names): array
    {
        return array_intersect_key($this->values, array_flip($names));
    }
}
