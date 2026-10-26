<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Identity;

use Beffroi\Core\Domain\Identity\Claim\ClaimInterface;
use Beffroi\Core\Domain\Identity\User;
use function array_keys;

/**
 * The claims a person may be able to say of themselves in this deployment (issue #452): what is wired,
 * which is the one source there is. A claim added is a class tagged and a line in the wiring, and nothing
 * here or on a page is edited.
 *
 * What a tenant opens is read against this list and never beside it: a name no wired claim answers is a
 * mistake of the configuration, refused where the configuration is read.
 */
final readonly class WiredClaims
{
    /**
     * @var array<string, ClaimInterface> by the name each claim gives itself
     */
    private array $byName;

    /**
     * @param iterable<ClaimInterface> $claims in the order they are wired, which is the order a page offers them
     */
    public function __construct(iterable $claims)
    {
        $byName = [];
        foreach ($claims as $claim) {
            $byName[$claim->name()] = $claim;
        }
        $this->byName = $byName;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->byName);
    }

    public function named(string $name): ?ClaimInterface
    {
        return $this->byName[$name] ?? null;
    }

    /**
     * What this person may say of themselves, in the order the claims are wired: what their tenant opens
     * and the source that created them does not hold (`User::maySayOfThemselves()`), which says which names,
     * this saying which claims answer them.
     *
     * @return list<ClaimInterface>
     */
    public function openedTo(User $user): array
    {
        $opened = [];
        foreach ($this->byName as $name => $claim) {
            if ($user->maySayOfThemselves($name)) {
                $opened[] = $claim;
            }
        }

        return $opened;
    }
}
