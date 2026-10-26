<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\KeyAlgorithmsInterface;
use function sprintf;

/**
 * The algorithms a deployment of the tests wires, by name: the keys of the upstream identity providers it declares
 * among them (spec/saml.md S-64), as the bundle's registries answer them.
 */
final readonly class WiredAlgorithmsOf implements KeyAlgorithmsInterface
{
    /**
     * @param list<KeyAlgorithmInterface> $algorithms
     */
    public function __construct(
        private array $algorithms,
    ) {
    }

    public function all(): array
    {
        return $this->algorithms;
    }

    public function named(string $name): KeyAlgorithmInterface
    {
        foreach ($this->algorithms as $algorithm) {
            if ($algorithm->name() === $name) {
                return $algorithm;
            }
        }

        throw new UnsupportedAlgorithmException(sprintf('Nothing wired carries the name "%s".', $name));
    }
}
