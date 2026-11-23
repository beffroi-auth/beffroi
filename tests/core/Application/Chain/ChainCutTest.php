<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Chain;

use Beffroi\Core\Application\Chain\ChainCut;
use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenRows;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedChain;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0060
 */
final class ChainCutTest extends TestCase
{
    private SignedChain $chain;

    protected function setUp(): void
    {
        $this->chain = new SignedChain();
    }

    #[Test]
    public function theOldestRowsPastTheWindowAreForgotten(): void
    {
        // Given
        $this->chain->rows->write(SignedChain::past());
        $this->chain->rows->write(SignedChain::past());
        $this->chain->rows->write();

        // When
        $forgotten = $this->chain->forgetPastTheWindow();

        // Then
        static::assertSame(2, $forgotten);
    }

    #[Test]
    public function theCutIsSigned(): void
    {
        // Given
        $this->chain->rows->write(SignedChain::past());
        $cut = $this->chain->rows->write(SignedChain::past());
        $this->chain->rows->write();

        // When
        $this->chain->forgetPastTheWindow();

        // Then
        static::assertTrue($this->chain->checkpoints->last($this->chain->tenant, $this->chain->chain)?->keptAfter->equals($cut));
    }

    #[Test]
    public function aChainTheRetentionCutHoldsTogether(): void
    {
        // Given
        $this->chain->rows->write(SignedChain::past());
        $this->chain->rows->write();
        $this->chain->forgetPastTheWindow();

        // When
        $verified = $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertSame([1, 2], [$verified->start->position, $verified->end->position]);
    }

    #[Test]
    public function aRowPastTheWindowWrittenAfterOneInsideItWaitsForItsTurn(): void
    {
        // Given
        $this->chain->rows->write();
        $this->chain->rows->write(SignedChain::past());

        // When
        $forgotten = $this->chain->forgetPastTheWindow();

        // Then
        static::assertSame(0, $forgotten);
    }

    #[Test]
    public function aCutThatForgetsNothingSignsTheWholeWalkItMade(): void
    {
        // Given
        $this->chain->rows->write();
        $this->chain->sign();
        $this->chain->rows->write();
        $this->chain->clock->modify('+1 day');

        // When
        $this->chain->forgetPastTheWindow();

        // Then
        $signed = $this->chain->checkpoints->last($this->chain->tenant, $this->chain->chain);
        static::assertEquals([2, $this->chain->clock->now()], [$signed?->walked->position, $signed?->walkedAt]);
    }

    #[Test]
    public function aRowWhoseMomentWasMovedBackPastTheWindowIsNotForgotten(): void
    {
        // Given
        $this->chain->rows->write();
        $this->chain->rows->write();
        $this->chain->sign();
        $this->chain->rows->rewrite(1, ChainOfWrittenRows::row(SignedChain::past()));

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The row at position 1 of the chain "journal" is not the one written there.');

        // When
        $this->chain->forgetPastTheWindow();
    }

    #[Test]
    public function aRowMovedBackWithItsLinksComputedAgainUpToTheSignedHeadIsNotForgotten(): void
    {
        // Given
        $this->chain->rows->write();
        $this->chain->rows->write();
        $this->chain->rows->write();
        $this->chain->sign();
        $this->chain->rows->rewriteAndRelink(1, ChainOfWrittenRows::row(SignedChain::past()));

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The rows up to position 3 of the chain "journal" are not the ones signed.');

        // When
        $this->chain->forgetPastTheWindow();
    }

    #[Test]
    public function aChainThatDoesNotFollowKeepsEveryRow(): void
    {
        // Given
        $this->chain->rows->write(SignedChain::past());
        $this->chain->rows->write();
        $this->chain->sign();
        $this->chain->rows->write();
        $this->chain->rows->rewrite(3, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));

        // When
        try {
            $this->chain->forgetPastTheWindow();
        } catch (BrokenChainException) {
        }

        // Then
        static::assertSame(1, $this->chain->rows->linkedAfter($this->chain->tenant, $this->chain->chain, 0, 10)[0]->position);
    }

    #[Test]
    public function aBacklogIsForgottenOverSeveralPasses(): void
    {
        // Given
        for ($written = 0; $written <= ChainCut::FORGOTTEN_AT_ONCE; ++$written) {
            $this->chain->rows->write(SignedChain::past());
        }

        // When
        $forgotten = $this->chain->forgetPastTheWindow();

        // Then
        static::assertSame(ChainCut::FORGOTTEN_AT_ONCE, $forgotten);
    }
}
