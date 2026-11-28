<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;
use DateTimeImmutable;

final class RecordingCredentialChangeNotifier implements CredentialChangeNotifierInterface
{
    /**
     * @var list<CredentialChange>
     */
    public private(set) array $told = [];

    /**
     * @var list<DateTimeImmutable|null> when each change was to be told, in the order they were
     */
    public private(set) array $toldAt = [];

    public function tell(CredentialChange $change, ?DateTimeImmutable $at = null): void
    {
        $this->told[] = $change;
        $this->toldAt[] = $at;
    }

    /**
     * @return list<array{string, ?string}> the act and the kind of each change told, in the order they were
     */
    public function acts(): array
    {
        $acts = [];
        foreach ($this->told as $change) {
            $acts[] = [$change->act, $change->kind];
        }

        return $acts;
    }
}
