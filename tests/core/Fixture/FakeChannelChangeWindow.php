<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_key_last;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ChannelChangeWindowInterface;
use function count;
use DateTimeImmutable;

final class FakeChannelChangeWindow implements ChannelChangeWindowInterface
{
    /**
     * @var list<array{string, string}> the person and the claim of each change asked about
     */
    public private(set) array $asked = [];

    /**
     * @param non-empty-list<string|null> $answers when each change in turn is told, as a modifier of its moment, null for
     *                                             never; the last one answers every change after it
     */
    public function __construct(
        private readonly array $answers = ['now'],
    ) {
    }

    public function toldAt(User $user, string $claim, DateTimeImmutable $now): ?DateTimeImmutable
    {
        $this->asked[] = [$user->id->toRfc4122(), $claim];
        $answer = $this->answers[count($this->asked) - 1] ?? $this->answers[array_key_last($this->answers)];

        return $answer === null ? null : $now->modify($answer);
    }
}
