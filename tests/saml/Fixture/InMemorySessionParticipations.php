<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function array_values;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Each service provider's part in a session (spec/saml.md S-26) in the memory of one process, written once per session
 * and service provider as the bundle writes it.
 */
final class InMemorySessionParticipations implements SessionParticipationRepositoryInterface
{
    /**
     * @var array<string, array<string, SessionParticipation>>
     */
    private array $participations = [];

    public function record(SessionParticipation $participation): void
    {
        $this->participations[$participation->session->id->toRfc4122()][$participation->serviceProvider] ??= $participation;
    }

    public function ofSession(Uuid $sessionId): array
    {
        return array_values($this->participations[$sessionId->toRfc4122()] ?? []);
    }
}
