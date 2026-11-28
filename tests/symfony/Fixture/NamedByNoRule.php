<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Symfony\Component\Messenger\Stamp\StampInterface;

/**
 * A stamp the serializer of the provider has never heard of, as a new version of Messenger or of the provider adds one.
 */
final readonly class NamedByNoRule implements StampInterface
{
    public function __construct(
        public string $carried,
    ) {
    }
}
