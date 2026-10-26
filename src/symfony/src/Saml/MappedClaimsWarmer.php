<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;

/**
 * The claim of each attribute mapping the declarations of service providers name, checked against the claims the
 * provider serves (beffroi/saml, spec/saml.md S-16, section 6.2 step 1), and the claim of each attribute of the
 * profile the declarations of upstream identity providers name, checked against the claims the profile of a person
 * holds (S-45, section 6.10 step 1), right after the container is compiled, in the same build. Those claims come from
 * the services the container builds, which a compiler pass has not built: ServiceProvidersPass and
 * UpstreamIdentityProvidersPass check every other rule of a declaration and hand this the declarations they built,
 * and Symfony runs a warmer that is not optional as soon as it has compiled a container, in cache:clear and
 * cache:warmup as at the first boot of a process that finds no container compiled. A declaration that holds an
 * environment variable is not among them, being left to its first use.
 *
 * It writes nothing in the cache. A deployment that declares no service provider asks nothing of its claims providers,
 * and one that declares no upstream identity provider nothing of the claims of the profile.
 */
final readonly class MappedClaimsWarmer implements CacheWarmerInterface
{
    /**
     * @param array<array-key, mixed> $declarations by entity ID, those ServiceProvidersPass built
     * @param array<array-key, mixed> $upstreamDeclarations by entity ID, those UpstreamIdentityProvidersPass built
     */
    public function __construct(
        private array $declarations,
        private ServedClaimsInterface $claims,
        private ProfileClaimsInterface $profileClaims,
        private array $upstreamDeclarations = [],
    ) {
    }

    /**
     * Not optional: the warmers a kernel runs right after it compiled its container are those that are not.
     */
    public function isOptional(): bool
    {
        return false;
    }

    /**
     * @throws InvalidConfigurationException when a mapping names a claim the provider does not serve, or an attribute
     *                                       of the profile a claim the profile does not hold
     *
     * @return list<string> nothing to preload
     */
    public function warmUp(string $cacheDir, ?string $buildDir = null): array
    {
        if ($this->declarations !== []) {
            ServiceProvidersPass::build($this->declarations, $this->claims);
        }
        if ($this->upstreamDeclarations !== []) {
            UpstreamIdentityProvidersPass::build($this->upstreamDeclarations, $this->profileClaims);
        }

        return [];
    }
}
