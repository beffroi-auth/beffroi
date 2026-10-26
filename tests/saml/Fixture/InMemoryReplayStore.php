<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Replay\RememberedMessage;
use Beffroi\Saml\Port\ReplayStoreInterface;
use DateTimeImmutable;

/**
 * The store of spec/saml.md S-23 in the memory of one process, for the tests only: a message is keyed as the bundle
 * keys it, and never forgotten, the tests reading when it expires instead.
 */
final class InMemoryReplayStore implements ReplayStoreInterface
{
    /**
     * @var array<string, DateTimeImmutable>
     */
    private array $remembered = [];

    public function remember(Tenant $tenant, string $issuer, string $id, DateTimeImmutable $expiresAt): bool
    {
        $key = RememberedMessage::keyOf($tenant, $issuer, $id);
        if (isset($this->remembered[$key])) {
            return false;
        }
        $this->remembered[$key] = $expiresAt;

        return true;
    }

    /**
     * When the message may be forgotten, or null when it was never remembered.
     */
    public function expiresAt(Tenant $tenant, string $issuer, string $id): ?DateTimeImmutable
    {
        return $this->remembered[RememberedMessage::keyOf($tenant, $issuer, $id)] ?? null;
    }

    public function isEmpty(): bool
    {
        return $this->remembered === [];
    }
}
