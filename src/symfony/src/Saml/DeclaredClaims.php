<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use function is_array;
use function is_string;

/**
 * The claims the declarations of service providers map, served as they are named (beffroi/saml, spec/saml.md S-16,
 * section 6.2 step 1), or the claims the declarations of upstream identity providers fill, held as they are named
 * (S-45, section 6.10 step 1). What the provider serves, and what the profile holds, comes from the services the
 * container builds, which a compiler pass has not built: ServiceProvidersPass and UpstreamIdentityProvidersPass build
 * the declarations with this when the container is compiled, so that every other rule of a declaration fails the
 * compilation, and MappedClaimsWarmer checks those claims against the real ones right after, in the same build. It
 * reads no user and gives no value.
 */
final readonly class DeclaredClaims implements ServedClaimsInterface, ProfileClaimsInterface
{
    /**
     * @param list<string> $names
     */
    private function __construct(
        private array $names,
    ) {
    }

    /**
     * The claim of every attribute mapping the declarations hold; what is not a mapping is left to the constructors of
     * the declaration, which refuse it.
     *
     * @param array<array-key, mixed> $declarations
     */
    public static function mappedBy(array $declarations): self
    {
        $names = [];
        foreach ($declarations as $declaration) {
            $attributes = is_array($declaration) ? $declaration['attributes'] ?? null : null;
            if (! is_array($attributes)) {
                continue;
            }
            foreach ($attributes as $attribute) {
                $claim = is_array($attribute) ? $attribute['claim'] ?? null : null;
                if (is_string($claim)) {
                    $names[] = $claim;
                }
            }
        }

        return new self($names);
    }

    /**
     * The claim of every attribute of the profile the declarations of upstream identity providers hold; what is not
     * one is left to the constructors of the declaration, which refuse it.
     *
     * @param array<array-key, mixed> $declarations
     */
    public static function filledBy(array $declarations): self
    {
        $names = [];
        foreach ($declarations as $declaration) {
            $profile = is_array($declaration) ? $declaration['profile'] ?? null : null;
            if (! is_array($profile)) {
                continue;
            }
            foreach ($profile as $claim) {
                if (is_string($claim)) {
                    $names[] = $claim;
                }
            }
        }

        return new self($names);
    }

    public function names(): array
    {
        return $this->names;
    }

    public function of(User $user, array $names): array
    {
        return [];
    }
}
