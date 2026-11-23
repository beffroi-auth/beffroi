<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Chain;

use Beffroi\Core\Domain\Event\ChainSignedAnew;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenRows;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedChain;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0060
 */
final class ChainRelinkingTest extends TestCase
{
    private SignedChain $chain;

    protected function setUp(): void
    {
        $this->chain = new SignedChain();
        $this->chain->rows->write();
        $this->chain->rows->write();
        $this->chain->rows->write();
        $this->chain->sign();
        $this->chain->rows->rewrite(2, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));
        $this->chain->rows->insertWithoutALink();
    }

    #[Test]
    public function aChainSignedAnewHoldsTogetherAsTheDatabaseHoldsIt(): void
    {
        // Given
        $this->chain->relinking()->signAnew($this->chain->tenant, $this->chain->chain, Fixtures::context());

        // When
        $verified = $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertSame([0, 4, 4], [$verified->start->position, $verified->end->position, $verified->signed?->head->position]);
    }

    #[Test]
    public function signingAChainAnewIsAnActThatSaysWhichRowsItLinked(): void
    {
        // When
        $this->chain->relinking()->signAnew($this->chain->tenant, $this->chain->chain, Fixtures::context());

        // Then
        $act = $this->chain->events->of(ChainSignedAnew::class)[0] ?? null;
        static::assertSame(['journal', 1, 4], [$act?->chain, $act?->from, $act?->to]);
    }
}
